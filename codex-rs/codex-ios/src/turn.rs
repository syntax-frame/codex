//! C-ABI shim that drives the REAL Codex turn loop (`run_turn`) end-to-end and
//! streams events back to the caller via a function-pointer callback.
//!
//! Unlike [`crate::codex_run_prompt`], which issues a single Responses API
//! round-trip through `codex-api`, this entry point constructs a minimal
//! `codex-core` `ThreadManager` + `CodexThread`, submits one user turn, and
//! forwards each streamed event (reasoning deltas, assistant text deltas, turn
//! completion, errors) to the supplied callback.
//!
//! The OAuth bearer token + ChatGPT account id are supplied as *runtime*
//! arguments. They are written only to an ephemeral `auth.json` inside a
//! freshly-created temp dir that is deleted when the call returns; nothing is
//! logged or persisted beyond the lifetime of the call.

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_core::test_support::thread_manager_with_models_provider;
use codex_login::AuthCredentialsStoreMode;
use codex_login::AuthDotJson;
use codex_login::AuthKeyringBackendKind;
use codex_login::CodexAuth;
use codex_login::TokenData;
use codex_model_provider_info::ModelProviderInfo;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::config_types::CollaborationMode;
use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::config_types::Settings;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::ThreadSettingsOverrides;
use codex_protocol::user_input::UserInput;

/// Event-kind discriminants passed to the callback.
const KIND_REASONING_DELTA: c_int = 0;
const KIND_TEXT_DELTA: c_int = 1;
const KIND_DONE: c_int = 2;
/// Emitted once just before KIND_DONE: the full updated conversation rollout as
/// a JSON array of Codex `ResponseItem`s (messages + tool calls/outputs +
/// reasoning). The app persists this per node and passes it back next turn.
const KIND_HISTORY: c_int = 4;
/// A tool call the model made, as JSON `{"tool": <name>, "args": <value>}`.
const KIND_TOOL_CALL: c_int = 5;
/// Boundary between two reasoning summary sections — the consumer should start a
/// new "thinking" bubble for subsequent reasoning deltas.
const KIND_REASONING_BREAK: c_int = 6;
const KIND_ERROR: c_int = 3;

/// Callback invoked for each streamed event. `text` is a NUL-terminated UTF-8
/// C string that is ONLY valid for the duration of the call; the callee must
/// copy it if it needs to outlive the invocation. `ctx` is passed through
/// verbatim so Swift can recover its closure/context.
pub type EventCallback =
    extern "C" fn(ctx: *mut c_void, event_kind: c_int, text: *const c_char);

fn c_str_to_string(ptr: *const c_char, field: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{field} pointer was null"));
    }
    // SAFETY: caller guarantees a NUL-terminated C string for non-null pointers.
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str
        .to_str()
        .map(str::to_owned)
        .map_err(|e| format!("{field} was not valid UTF-8: {e}"))
}

/// Invoke the caller's callback with an owned Rust string. The C string is
/// freed as soon as the callback returns.
fn emit(callback: EventCallback, ctx: *mut c_void, kind: c_int, text: &str) {
    // Strip interior NULs so CString never fails.
    let sanitized: String = text.chars().filter(|&c| c != '\0').collect();
    if let Ok(cstr) = CString::new(sanitized) {
        callback(ctx, kind, cstr.as_ptr());
    }
}

/// Build a `CodexAuth` for the ChatGPT/codex backend from a raw OAuth token by
/// writing an ephemeral `auth.json` and loading it through the normal storage
/// path. `codex_home` must be a freshly created (temp) directory.
async fn build_auth(
    codex_home: &std::path::Path,
    access_token: String,
    id_token: String,
    account_id: String,
) -> Result<CodexAuth, String> {
    let id_token_info = codex_login::token_data::parse_chatgpt_jwt_claims(&id_token)
        .map_err(|e| format!("failed to parse id_token: {e}"))?;
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(codex_protocol::auth::AuthMode::Chatgpt),
        openai_api_key: None,
        tokens: Some(TokenData {
            id_token: id_token_info,
            access_token,
            // A refresh token is required by the schema; we never use it
            // because the access token is supplied fresh per call.
            refresh_token: String::new(),
            account_id: Some(account_id),
        }),
        last_refresh: Some(chrono::Utc::now()),
        agent_identity: None,
        personal_access_token: None,
        bedrock_api_key: None,
    };

    let json = serde_json::to_string(&auth_dot_json)
        .map_err(|e| format!("failed to serialize auth.json: {e}"))?;
    tokio::fs::write(codex_home.join("auth.json"), json)
        .await
        .map_err(|e| format!("failed to write ephemeral auth.json: {e}"))?;

    CodexAuth::from_auth_storage(
        codex_home,
        AuthCredentialsStoreMode::File,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        /*auth_route_config*/ None,
    )
    .await
    .map_err(|e| format!("failed to load ephemeral auth: {e}"))?
    .ok_or_else(|| "ephemeral auth.json produced no auth".to_string())
}

async fn run_turn_async(
    access_token: String,
    id_token: String,
    account_id: String,
    model: String,
    prompt: String,
    history_json: String,
    callback: EventCallback,
    ctx: *mut c_void,
) -> Result<(), String> {
    // Ephemeral codex_home: holds auth.json + any thread store artifacts. It is
    // deleted when `_home_guard` drops at the end of this function.
    let home_guard = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
    let codex_home = home_guard.path().to_path_buf();

    let auth = build_auth(&codex_home, access_token, id_token, account_id).await?;

    // The built-in OpenAI provider with ChatGPT auth resolves its base_url to
    // `https://chatgpt.com/backend-api/codex` automatically (see
    // ModelProviderInfo::to_api_provider).
    let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);

    // Minimal ThreadManager: a dummy AuthManager wrapping our CodexAuth plus the
    // codex provider. This is the smallest public construction path; it manages
    // its own ephemeral codex_home (separate from the Config's) for its thread
    // store, which is fine for a one-shot turn.
    let thread_manager = thread_manager_with_models_provider(auth, provider);

    // Minimal Config rooted at the temp home (no on-disk config => defaults).
    let mut config = ConfigBuilder::default()
        .codex_home(codex_home.clone())
        .harness_overrides(ConfigOverrides {
            model: Some(model.clone()),
            ..Default::default()
        })
        .build()
        .await
        .map_err(|e| format!("failed to build config: {e}"))?;

    // Enable reasoning so the model emits reasoning-summary deltas (rendered as
    // "thinking" bubbles in the app). Without these the turn streams only the
    // final answer.
    config.model_reasoning_effort = Some(ReasoningEffort::High);
    config.model_reasoning_summary = Some(ReasoningSummary::Detailed);

    let new_thread = thread_manager
        .start_thread(config)
        .await
        .map_err(|e| format!("failed to start thread: {e}"))?;
    let thread = new_thread.thread;
    let session_model = new_thread.session_configured.model.clone();

    // Seed the node's prior conversation (the full rollout persisted by the app)
    // so the model has memory. This mirrors exactly what Codex keeps across
    // turns: messages, tool calls/outputs, and reasoning items.
    let prior: Vec<ResponseItem> = if history_json.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&history_json)
            .map_err(|e| format!("failed to parse history json: {e}"))?
    };
    if !prior.is_empty() {
        thread
            .inject_response_items(prior)
            .await
            .map_err(|e| format!("failed to seed history: {e}"))?;
    }

    // Submit a single user turn through the real loop, pinning the model.
    thread
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: prompt,
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            responsesapi_client_metadata: None,
            additional_context: Default::default(),
            thread_settings: ThreadSettingsOverrides {
                collaboration_mode: Some(CollaborationMode {
                    mode: ModeKind::Default,
                    settings: Settings {
                        model: if model.is_empty() { session_model } else { model },
                        reasoning_effort: Some(ReasoningEffort::High),
                        developer_instructions: None,
                    },
                }),
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("failed to submit user input: {e}"))?;

    // Drain events until the turn completes (or errors).
    // Track the reasoning summary section so we can signal bubble boundaries:
    // Codex streams reasoning as multiple summary sections (each its own thought),
    // distinguished by `summary_index`.
    let mut last_summary_index: Option<i64> = None;
    loop {
        let event = thread
            .next_event()
            .await
            .map_err(|e| format!("event stream error: {e}"))?;
        match event.msg {
            EventMsg::ReasoningContentDelta(ev) => {
                if last_summary_index.is_some_and(|prev| prev != ev.summary_index) {
                    emit(callback, ctx, KIND_REASONING_BREAK, "");
                }
                last_summary_index = Some(ev.summary_index);
                emit(callback, ctx, KIND_REASONING_DELTA, &ev.delta);
            }
            EventMsg::AgentReasoningSectionBreak(_) => {
                emit(callback, ctx, KIND_REASONING_BREAK, "");
                last_summary_index = None;
            }
            EventMsg::ReasoningRawContentDelta(ev) => {
                emit(callback, ctx, KIND_REASONING_DELTA, &ev.delta);
            }
            // The model called the built-in `update_plan` tool.
            EventMsg::PlanUpdate(args) => {
                let payload = serde_json::json!({ "tool": "update_plan", "args": args });
                if let Ok(json) = serde_json::to_string(&payload) {
                    emit(callback, ctx, KIND_TOOL_CALL, &json);
                }
            }
            // Shell/exec tool call (only fires once exec tools are wired).
            EventMsg::ExecCommandBegin(ev) => {
                let payload = serde_json::json!({ "tool": "shell", "args": ev });
                if let Ok(json) = serde_json::to_string(&payload) {
                    emit(callback, ctx, KIND_TOOL_CALL, &json);
                }
            }
            // MCP tool call (only fires once MCP servers are wired).
            EventMsg::McpToolCallBegin(ev) => {
                let payload = serde_json::json!({ "tool": "mcp", "args": ev });
                if let Ok(json) = serde_json::to_string(&payload) {
                    emit(callback, ctx, KIND_TOOL_CALL, &json);
                }
            }
            EventMsg::AgentMessageContentDelta(ev) => {
                emit(callback, ctx, KIND_TEXT_DELTA, &ev.delta);
            }
            EventMsg::Error(ev) => {
                emit(callback, ctx, KIND_ERROR, &ev.message);
                return Ok(());
            }
            EventMsg::TurnComplete(_) => {
                // Emit the updated rollout (ResponseItems only) so the app can
                // persist it per node and replay it on the next turn.
                match thread.load_history(false).await {
                    Ok(stored) => {
                        let items: Vec<ResponseItem> = stored
                            .items
                            .into_iter()
                            .filter_map(|ri| match ri {
                                RolloutItem::ResponseItem(item) => Some(item),
                                _ => None,
                            })
                            .collect();
                        if let Ok(json) = serde_json::to_string(&items) {
                            emit(callback, ctx, KIND_HISTORY, &json);
                        }
                    }
                    Err(e) => emit(
                        callback,
                        ctx,
                        KIND_ERROR,
                        &format!("load_history failed: {e}"),
                    ),
                }
                emit(callback, ctx, KIND_DONE, "");
                return Ok(());
            }
            _ => {}
        }
    }
}

/// Drive ONE user turn through the real Codex turn loop and stream events to
/// `callback`. Blocks on a tokio runtime built inside the call.
///
/// `event_kind`: 0=reasoning_delta, 1=text_delta, 2=done, 3=error.
///
/// On a setup failure (bad pointers, auth/config/thread construction) the
/// callback is invoked once with `event_kind=3` (error) and a message. A panic
/// anywhere is caught and surfaced as an error event rather than unwinding
/// across the FFI boundary.
///
/// # Safety
/// All string pointers must be either null or valid NUL-terminated C strings.
/// `callback` must be a valid function pointer; `ctx` is passed through opaquely.
#[unsafe(no_mangle)]
pub extern "C" fn codex_run_turn_streaming(
    access_token: *const c_char,
    id_token: *const c_char,
    account_id: *const c_char,
    model: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let result = std::panic::catch_unwind(move || {
        // Parse the C strings on the calling thread (the pointers are only valid
        // for the duration of this call), then move the owned data into a worker.
        let token = c_str_to_string(access_token, "access_token")?;
        let id_tok = c_str_to_string(id_token, "id_token")?;
        let account = c_str_to_string(account_id, "account_id")?;
        let model = c_str_to_string(model, "model")?;
        let prompt = c_str_to_string(prompt, "prompt")?;
        // History is optional: NULL or empty means a fresh conversation.
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };

        // `block_on` drives the main future on the CALLING thread. On iOS the
        // caller is a GCD worker (~512 KiB stack), which Codex's deep async
        // `Session::new` state machine overflows (SIGBUS at the stack guard
        // page). Run the runtime + block_on on a dedicated thread with a large
        // stack instead. (`thread_stack_size` below only covers tokio's own
        // worker threads, not the block_on driver thread.)
        std::thread::Builder::new()
            .name("codex-turn".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || -> Result<(), String> {
                let ctx = ctx_addr as *mut c_void;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_stack_size(16 * 1024 * 1024)
                    .build()
                    .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
                runtime.block_on(run_turn_async(
                    token, id_tok, account, model, prompt, history, callback, ctx,
                ))
            })
            .map_err(|e| format!("failed to spawn worker thread: {e}"))?
            .join()
            .map_err(|_| "worker thread panicked".to_string())?
    });

    match result {
        Ok(Ok(())) => {}
        Ok(Err(message)) => emit(callback, ctx, KIND_ERROR, &message),
        Err(_) => emit(callback, ctx, KIND_ERROR, "panic during turn"),
    }
}
