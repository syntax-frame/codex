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
use codex_protocol::config_types::CollaborationMode;
use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::Settings;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::ThreadSettingsOverrides;
use codex_protocol::user_input::UserInput;

/// Event-kind discriminants passed to the callback.
const KIND_REASONING_DELTA: c_int = 0;
const KIND_TEXT_DELTA: c_int = 1;
const KIND_DONE: c_int = 2;
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
    let config = ConfigBuilder::default()
        .codex_home(codex_home.clone())
        .harness_overrides(ConfigOverrides {
            model: Some(model.clone()),
            ..Default::default()
        })
        .build()
        .await
        .map_err(|e| format!("failed to build config: {e}"))?;

    let new_thread = thread_manager
        .start_thread(config)
        .await
        .map_err(|e| format!("failed to start thread: {e}"))?;
    let thread = new_thread.thread;
    let session_model = new_thread.session_configured.model.clone();

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
                        reasoning_effort: None,
                        developer_instructions: None,
                    },
                }),
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("failed to submit user input: {e}"))?;

    // Drain events until the turn completes (or errors).
    loop {
        let event = thread
            .next_event()
            .await
            .map_err(|e| format!("event stream error: {e}"))?;
        match event.msg {
            EventMsg::ReasoningContentDelta(ev) => {
                emit(callback, ctx, KIND_REASONING_DELTA, &ev.delta);
            }
            EventMsg::ReasoningRawContentDelta(ev) => {
                emit(callback, ctx, KIND_REASONING_DELTA, &ev.delta);
            }
            EventMsg::AgentMessageContentDelta(ev) => {
                emit(callback, ctx, KIND_TEXT_DELTA, &ev.delta);
            }
            EventMsg::Error(ev) => {
                emit(callback, ctx, KIND_ERROR, &ev.message);
                return Ok(());
            }
            EventMsg::TurnComplete(_) => {
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
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let result = std::panic::catch_unwind(move || {
        let ctx = ctx_addr as *mut c_void;
        let token = c_str_to_string(access_token, "access_token")?;
        let id_tok = c_str_to_string(id_token, "id_token")?;
        let account = c_str_to_string(account_id, "account_id")?;
        let model = c_str_to_string(model, "model")?;
        let prompt = c_str_to_string(prompt, "prompt")?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            // Codex's turn loop has deep async state machines; the default 2 MiB
            // worker stack overflows. Match Codex's production worker stack (16 MiB).
            .thread_stack_size(16 * 1024 * 1024)
            .build()
            .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

        runtime.block_on(run_turn_async(token, id_tok, account, model, prompt, callback, ctx))
    });

    match result {
        Ok(Ok(())) => {}
        Ok(Err(message)) => emit(callback, ctx, KIND_ERROR, &message),
        Err(_) => emit(callback, ctx, KIND_ERROR, "panic during turn"),
    }
}
