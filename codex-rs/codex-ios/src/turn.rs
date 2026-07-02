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

use std::collections::HashSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_core::test_support::thread_manager_with_models_provider;
use codex_core::test_support::thread_manager_with_models_provider_and_home;
use codex_exec_server::EnvironmentManager;
use codex_features::Feature;
use codex_login::AuthCredentialsStoreMode;
use codex_login::AuthDotJson;
use codex_login::AuthKeyringBackendKind;
use codex_login::CodexAuth;
use codex_login::TokenData;
use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::WireApi;
use codex_model_provider_info::create_oss_provider_with_base_url;
use codex_protocol::config_types::CollaborationMode;
use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::config_types::SandboxMode;
use codex_protocol::config_types::Settings;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::ReviewDecision;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::ThreadSettingsOverrides;
use codex_protocol::user_input::UserInput;

/// Steers the model toward the on-device tools. This build runs on a phone with
/// no shell and no patch environment, so `apply_patch` and any shell/exec tool
/// cannot work here; without this nudge the model reaches for `apply_patch`
/// first, fails, and only then falls back to `write_file` (a wasted round-trip
/// and a confusing "the patch tool failed" line in the user's chat).
const MOBILE_DEVELOPER_INSTRUCTIONS: &str = "You are running natively on a mobile device. There is no shell and no patch \
environment. For ALL file operations use only the `read_file`, `write_file`, and \
`list_dir` tools. Never use `apply_patch`, `shell`, or `exec_command` — they are \
unavailable here and will fail. To create or modify a file, write its full \
contents with `write_file`.";

/// Server-mode counterpart: the shell/exec tools run on a remote SSH host, so
/// the model SHOULD use them for shell commands. (No anti-shell nudge here.)
const SERVER_MODE_DEVELOPER_INSTRUCTIONS: &str = "You are connected to a remote server. \
Shell/exec tools execute commands ON THAT SERVER over SSH, and file operations act on that \
server's filesystem. When the user asks you to run a shell command, use the shell/exec tool \
and report the command's actual output. To create or edit files on the server, prefer \
`apply_patch` (it edits files directly on the remote host); the shell/exec tools and \
`apply_patch` all operate on the same remote server.";

/// SSH connection parameters for "server mode": when supplied to
/// [`run_turn_async`], the turn's shell/exec tools run on the SSH host instead
/// of being disabled. The C FFI / Swift layer constructs this from caller-
/// provided connection settings (host/port/user/key path/fingerprint).
///
/// The filesystem stays local for this pass (apply_patch / remote files are a
/// later pass); only process execution is redirected over SSH.
#[derive(Clone, Debug)]
pub struct ServerMode {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Path to an OpenSSH private key authorized on the host.
    pub key_path: String,
    /// Expected host-key fingerprint in OpenSSH `SHA256:<base64nopad>` form.
    /// When `Some`, host-key pinning is enforced in `SshProcessBackend`: the
    /// SSH connection is rejected unless the server key fingerprint matches.
    /// When `None`, any host key is accepted (permissive).
    pub host_fingerprint: Option<String>,
}

/// Environment id under which the SSH server-mode environment is registered and
/// selected for the turn.
const SERVER_MODE_ENVIRONMENT_ID: &str = "ssh-server";

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
const IOS_APIKEY_PROVIDER_ID: &str = "ios-apikey";

/// Callback invoked for each streamed event. `text` is a NUL-terminated UTF-8
/// C string that is ONLY valid for the duration of the call; the callee must
/// copy it if it needs to outlive the invocation. `ctx` is passed through
/// verbatim so Swift can recover its closure/context.
pub type EventCallback = extern "C" fn(ctx: *mut c_void, event_kind: c_int, text: *const c_char);

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

/// Pull the first target file path out of an apply_patch grammar body — the
/// `*** Add File: <path>` / `*** Update File: <path>` / `*** Delete File: <path>`
/// line — so the tool bubble can show which file is being edited. Returns "" if
/// none is found.
fn patch_target_file(input: &str) -> String {
    for line in input.lines() {
        let line = line.trim();
        for prefix in ["*** Update File: ", "*** Add File: ", "*** Delete File: "] {
            if let Some(rest) = line.strip_prefix(prefix) {
                return rest.trim().to_string();
            }
        }
    }
    String::new()
}

/// Stable key for tool calls that may be replayed when prior rollout history is
/// injected into a fresh one-shot iOS thread.
fn tool_call_replay_key(item: &ResponseItem) -> Option<String> {
    match item {
        ResponseItem::FunctionCall { call_id, .. } => Some(format!("function:{call_id}")),
        ResponseItem::CustomToolCall { call_id, .. } => Some(format!("custom:{call_id}")),
        _ => None,
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

fn toml_basic_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn write_api_key_provider_config(
    codex_home: &std::path::Path,
    base_url: &str,
) -> Result<(), String> {
    let config = format!(
        r#"model_provider = "{provider_id}"

[model_providers.{provider_id}]
name = "iOS API key"
base_url = {base_url}
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
"#,
        provider_id = IOS_APIKEY_PROVIDER_ID,
        base_url = toml_basic_string(base_url),
    );
    tokio::fs::write(codex_home.join("config.toml"), config)
        .await
        .map_err(|e| format!("failed to write ephemeral config.toml: {e}"))
}

/// How to authenticate + which backend to talk to for a turn.
///
/// This is the ONE place provider selection lives. The ChatGPT-OAuth variant is
/// the original path (unchanged behavior); the ApiKey variant targets any
/// OpenAI-Responses-compatible endpoint (OpenAI proper, a local Ollama/LM Studio
/// server, or any paid compatible provider) with a plain bearer API key.
pub(crate) enum ProviderAuthConfig {
    /// Original path: ChatGPT OAuth tokens; base_url resolves to the codex
    /// backend automatically.
    ChatgptOAuth {
        access_token: String,
        id_token: String,
        account_id: String,
    },
    /// Generic API-key path: `Authorization: Bearer <api_key>` against
    /// `base_url` (must expose the OpenAI Responses API at `<base_url>/responses`).
    ApiKey { base_url: String, api_key: String },
}

pub(crate) async fn run_turn_async(
    provider_config: ProviderAuthConfig,
    model: String,
    prompt: String,
    history_json: String,
    workspace: String,
    server_mode: Option<ServerMode>,
    callback: EventCallback,
    ctx: *mut c_void,
) -> Result<(), String> {
    // Ephemeral codex_home: holds auth.json + any thread store artifacts. It is
    // deleted when `_home_guard` drops at the end of this function.
    let home_guard = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
    let codex_home = home_guard.path().to_path_buf();

    // Build (auth, provider) from the selected config. The OAuth branch is
    // byte-for-byte the original behavior; the ApiKey branch resolves auth via
    // the provider's bearer-token path (see codex-model-provider's
    // `resolve_provider_auth`, which honors a bearer API key BEFORE any OAuth
    // logic), so no ChatGPT machinery is touched.
    let (auth, provider, model_provider_override) = match provider_config {
        ProviderAuthConfig::ChatgptOAuth {
            access_token,
            id_token,
            account_id,
        } => {
            let auth = build_auth(&codex_home, access_token, id_token, account_id).await?;
            // The built-in OpenAI provider with ChatGPT auth resolves its
            // base_url to `https://chatgpt.com/backend-api/codex` automatically
            // (see ModelProviderInfo::to_api_provider).
            let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
            (auth, provider, None)
        }
        ProviderAuthConfig::ApiKey { base_url, api_key } => {
            // `CodexAuth::from_api_key` produces a plain `Authorization: Bearer
            // <key>` header. The provider (name != "OpenAI") targets the given
            // base_url via the Responses wire API. requires_openai_auth is false
            // for the oss provider, so none of the ChatGPT-specific auth applies.
            //
            // The Config built below must also select a provider with this
            // base_url. Otherwise the thread starts with the default `openai`
            // provider and the request falls back to api.openai.com.
            write_api_key_provider_config(&codex_home, &base_url).await?;
            let auth = CodexAuth::from_api_key(&api_key);
            let provider = create_oss_provider_with_base_url(&base_url, WireApi::Responses);
            (auth, provider, Some(IOS_APIKEY_PROVIDER_ID.to_string()))
        }
    };

    // Minimal ThreadManager: a dummy AuthManager wrapping our CodexAuth plus the
    // codex provider. This is the smallest public construction path; it manages
    // its own ephemeral codex_home (separate from the Config's) for its thread
    // store, which is fine for a one-shot turn.
    //
    // In server mode, build a ThreadManager whose EnvironmentManager has the
    // SSH environment registered AND selected as the default, so the turn's
    // shell/exec tools route through the SSH backend (and `has_environment()`
    // is true). Otherwise keep the default (local, shell-disabled) path intact.
    let thread_manager = match &server_mode {
        Some(server) => {
            let environment_manager = std::sync::Arc::new(EnvironmentManager::ssh(
                SERVER_MODE_ENVIRONMENT_ID,
                server.host.clone(),
                server.port,
                server.user.clone(),
                server.key_path.clone(),
                server.host_fingerprint.clone(),
            ));
            thread_manager_with_models_provider_and_home(
                auth,
                provider,
                codex_home.clone(),
                environment_manager,
            )
        }
        None => thread_manager_with_models_provider(auth, provider),
    };

    // Minimal Config rooted at the temp home (no on-disk config => defaults).
    let mut config = ConfigBuilder::default()
        .codex_home(codex_home.clone())
        .harness_overrides(ConfigOverrides {
            model: Some(model.clone()),
            // Root the turn in the node's workspace dir ("zone") so file tools
            // operate inside it.
            cwd: if workspace.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(&workspace))
            },
            // The mobile build has no human in the loop to answer approval
            // prompts and no OS sandbox: never block on an approval (that would
            // hang the turn forever — there is no UI to approve), and treat the
            // node's workspace as writable so any write-capable tool proceeds.
            approval_policy: Some(AskForApproval::Never),
            // In server mode the command runs on a REMOTE machine over SSH, so a
            // *local* OS sandbox is meaningless — and iOS has no seatbelt to set
            // one up, so trying to sandbox would force an escalation that
            // approval=Never auto-denies ("blocked by the execution environment").
            // Use DangerFullAccess so exec dispatches straight to the SSH backend;
            // the real security boundary is the remote host (key-only SSH).
            // Local mode keeps WorkspaceWrite.
            sandbox_mode: Some(if server_mode.is_some() {
                SandboxMode::DangerFullAccess
            } else {
                SandboxMode::WorkspaceWrite
            }),
            model_provider: model_provider_override,
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

    // Shell tool gating:
    // - Local (no server mode): iOS has no shell — there is no `/bin/zsh` to
    //   spawn, so the unified-exec / shell tools can never run here. Worse, when
    //   offered them the model prefers shell (`printf … | tee file`) over our
    //   native `write_file`, which then trips the approval machinery and hangs
    //   the turn. Disable the shell tool so the only file-mutating tools are our
    //   on-device read_file/write_file/list_dir handlers.
    // - Server mode: shell/exec tools run on the SSH host, so re-enable the
    //   shell tool. The SSH environment is registered+selected above, which
    //   makes `has_environment()` true and routes the tools through the SSH
    //   backend.
    if server_mode.is_some() {
        let _ = config.features.enable(Feature::ShellTool);
    } else {
        let _ = config.features.disable(Feature::ShellTool);
    }

    // SPIKE: enable the multi-agent v2 collaboration suite (spawn_agent,
    // send_message, followup_task, wait_agent, interrupt_agent, list_agents).
    // The version is derived from features: MultiAgentV2 => V2. spawn_agent
    // creates another in-process thread via agent_control (no subprocess).
    let _ = config.features.enable(Feature::MultiAgentV2);

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
    let mut replayed_tool_calls: HashSet<String> =
        prior.iter().filter_map(tool_call_replay_key).collect();
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
                        model: if model.is_empty() {
                            session_model
                        } else {
                            model
                        },
                        reasoning_effort: Some(ReasoningEffort::High),
                        developer_instructions: Some(
                            if server_mode.is_some() {
                                SERVER_MODE_DEVELOPER_INSTRUCTIONS
                            } else {
                                MOBILE_DEVELOPER_INSTRUCTIONS
                            }
                            .to_string(),
                        ),
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
            // Safety net: with approval_policy=Never these should not fire, but
            // if any approval-gated tool ever requests a decision there is no UI
            // to answer it — auto-approve so the turn can never deadlock.
            EventMsg::ExecApprovalRequest(ev) => {
                let _ = thread
                    .submit(Op::ExecApproval {
                        id: ev.effective_approval_id(),
                        turn_id: Some(ev.turn_id.clone()),
                        decision: ReviewDecision::Approved,
                    })
                    .await;
            }
            EventMsg::ApplyPatchApprovalRequest(ev) => {
                let _ = thread
                    .submit(Op::PatchApproval {
                        id: ev.call_id.clone(),
                        decision: ReviewDecision::Approved,
                    })
                    .await;
            }
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
            // Any function tool call the model makes (read_file/write_file/
            // list_dir/update_plan/shell/…) surfaces generically here — the raw
            // response item carries the function name + arguments live.
            EventMsg::RawResponseItem(ev) => {
                if let Some(key) = tool_call_replay_key(&ev.item) {
                    if replayed_tool_calls.remove(&key) {
                        continue;
                    }
                }

                match &ev.item {
                    ResponseItem::FunctionCall {
                        name, arguments, ..
                    } => {
                        let args: serde_json::Value =
                            serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);
                        let payload = serde_json::json!({ "tool": name, "args": args });
                        if let Ok(json) = serde_json::to_string(&payload) {
                            emit(callback, ctx, KIND_TOOL_CALL, &json);
                        }
                    }
                    // Freeform / "custom" tools (notably apply_patch) are NOT
                    // FunctionCalls — they carry their raw grammar text in `input`.
                    // Surface them too, and pull the target file out of the patch so
                    // the bubble shows what's being edited.
                    ResponseItem::CustomToolCall { name, input, .. } => {
                        let file = patch_target_file(input);
                        let payload = serde_json::json!({
                            "tool": name,
                            "args": { "path": file },
                        });
                        if let Ok(json) = serde_json::to_string(&payload) {
                            emit(callback, ctx, KIND_TOOL_CALL, &json);
                        }
                    }
                    _ => {}
                }
            }
            // Web search (provider-hosted, not a function call) — surfaced on
            // completion (carries the query + the action/result).
            EventMsg::WebSearchEnd(ev) => {
                let payload = serde_json::json!({ "tool": "web_search", "args": ev });
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
    workspace_path: *const c_char,
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
        // Workspace dir to root the turn at (where file tools operate). Optional.
        let workspace = if workspace_path.is_null() {
            String::new()
        } else {
            c_str_to_string(workspace_path, "workspace_path")?
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
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token: token,
                        id_token: id_tok,
                        account_id: account,
                    },
                    model,
                    prompt,
                    history,
                    workspace,
                    /*server_mode*/ None,
                    callback,
                    ctx,
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

/// Generic API-key counterpart of [`codex_run_turn_streaming`]: drives ONE user
/// turn against ANY OpenAI-Responses-compatible endpoint using a plain bearer
/// API key instead of ChatGPT OAuth. This is the path for OpenAI proper (with an
/// API key), a local Ollama / LM Studio server, or any paid compatible provider.
///
/// `base_url` is the provider's API root that exposes the Responses API at
/// `<base_url>/responses` (e.g. `http://localhost:11434/v1` for a local Ollama,
/// or `https://api.openai.com/v1`). `api_key` is sent as `Authorization: Bearer
/// <api_key>`; for a local server that ignores auth it can be any non-empty
/// placeholder.
///
/// Local mode only (shell/exec disabled, on-device file tools) — mirrors
/// [`codex_run_turn_streaming`]. Event kinds and error handling are identical.
///
/// # Safety
/// All string pointers must be either null or valid NUL-terminated C strings.
/// `callback` must be a valid function pointer; `ctx` is passed through opaquely.
#[unsafe(no_mangle)]
pub extern "C" fn codex_run_turn_streaming_apikey(
    base_url: *const c_char,
    api_key: *const c_char,
    model: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    workspace_path: *const c_char,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let result = std::panic::catch_unwind(move || {
        // Parse the C strings on the calling thread (the pointers are only valid
        // for the duration of this call), then move the owned data into a worker.
        let base_url = c_str_to_string(base_url, "base_url")?;
        let api_key = c_str_to_string(api_key, "api_key")?;
        let model = c_str_to_string(model, "model")?;
        let prompt = c_str_to_string(prompt, "prompt")?;
        // History is optional: NULL or empty means a fresh conversation.
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };
        // Workspace dir to root the turn at (where file tools operate). Optional.
        let workspace = if workspace_path.is_null() {
            String::new()
        } else {
            c_str_to_string(workspace_path, "workspace_path")?
        };

        // Same big-stack worker + multi-thread runtime dance as the OAuth FFI.
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
                    ProviderAuthConfig::ApiKey { base_url, api_key },
                    model,
                    prompt,
                    history,
                    workspace,
                    /*server_mode*/ None,
                    callback,
                    ctx,
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

/// Server-mode counterpart of [`codex_run_turn_streaming`]: drives ONE user
/// turn whose shell/exec tools run on a remote SSH host instead of being
/// disabled. Takes the same params as [`codex_run_turn_streaming`] PLUS the SSH
/// connection settings.
///
/// `workspace_path` here is the cwd ON THE SERVER (it must exist on the remote
/// host); the turn is rooted there.
///
/// `ssh_key_pem` is the OpenSSH PRIVATE KEY CONTENTS (PEM text), NOT a path. It
/// is written to a chmod-600 file inside an ephemeral temp dir for the duration
/// of the call (and deleted afterward); nothing is persisted.
///
/// `ssh_fingerprint` is the expected server host-key fingerprint in OpenSSH
/// `SHA256:...` form. When null or empty, host-key pinning is disabled
/// (permissive). When set, the SSH connection is rejected unless the server's
/// host key matches.
///
/// # Safety
/// All string pointers must be either null or valid NUL-terminated C strings.
/// `callback` must be a valid function pointer; `ctx` is passed through opaquely.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn codex_run_turn_streaming_server(
    access_token: *const c_char,
    id_token: *const c_char,
    account_id: *const c_char,
    model: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    workspace_path: *const c_char,
    ssh_host: *const c_char,
    ssh_port: u16,
    ssh_user: *const c_char,
    ssh_key_pem: *const c_char,
    ssh_fingerprint: *const c_char,
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
        // Workspace dir to root the turn at (on the SERVER). Optional.
        let workspace = if workspace_path.is_null() {
            String::new()
        } else {
            c_str_to_string(workspace_path, "workspace_path")?
        };

        // SSH connection settings.
        let host = c_str_to_string(ssh_host, "ssh_host")?;
        let user = c_str_to_string(ssh_user, "ssh_user")?;
        let key_pem = c_str_to_string(ssh_key_pem, "ssh_key_pem")?;
        // Fingerprint is optional: null/empty => no host-key pinning.
        let fingerprint = if ssh_fingerprint.is_null() {
            None
        } else {
            let s = c_str_to_string(ssh_fingerprint, "ssh_fingerprint")?;
            if s.trim().is_empty() { None } else { Some(s) }
        };

        // Persist the private key PEM to a chmod-600 file in an ephemeral temp
        // dir. The dir (and key) live for the duration of the worker thread and
        // are removed when `key_dir` drops after the turn completes.
        let key_dir =
            tempfile::tempdir().map_err(|e| format!("failed to create ssh key tempdir: {e}"))?;
        let key_path = key_dir.path().join("id_ssh");
        std::fs::write(&key_path, key_pem.as_bytes())
            .map_err(|e| format!("failed to write ssh key file: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("failed to chmod ssh key file: {e}"))?;
        }
        let key_path_str = key_path.to_string_lossy().into_owned();

        let server_mode = ServerMode {
            host,
            port: ssh_port,
            user,
            key_path: key_path_str,
            host_fingerprint: fingerprint,
        };

        // Same big-stack worker + multi-thread runtime dance as the local FFI.
        std::thread::Builder::new()
            .name("codex-turn".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || -> Result<(), String> {
                // Hold the key dir alive until the turn finishes.
                let _key_dir = key_dir;
                let ctx = ctx_addr as *mut c_void;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_stack_size(16 * 1024 * 1024)
                    .build()
                    .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
                runtime.block_on(run_turn_async(
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token: token,
                        id_token: id_tok,
                        account_id: account,
                    },
                    model,
                    prompt,
                    history,
                    workspace,
                    /*server_mode*/ Some(server_mode),
                    callback,
                    ctx,
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

/// Rust-friendly entry point that drives ONE turn (optionally in server mode)
/// on a dedicated big-stack thread + multi-thread tokio runtime, mirroring the
/// safety dance in [`codex_run_turn_streaming`]. Owned `String`s in, so callers
/// (the host test today; the C FFI + Swift wiring next) need not juggle C
/// pointer lifetimes here.
///
/// Pass `server_mode = Some(..)` to run the turn's shell/exec tools on the SSH
/// host; `None` keeps the local, shell-disabled behavior.
///
/// # Safety
/// `callback` must be a valid function pointer; `ctx` is passed through
/// opaquely and must outlive the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn run_turn_streaming(
    access_token: String,
    id_token: String,
    account_id: String,
    model: String,
    prompt: String,
    history_json: String,
    workspace: String,
    server_mode: Option<ServerMode>,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let result = std::panic::catch_unwind(move || {
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
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token,
                        id_token,
                        account_id,
                    },
                    model,
                    prompt,
                    history_json,
                    workspace,
                    server_mode,
                    callback,
                    ctx,
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
