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

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_core::test_support::thread_manager_with_models_provider;
use codex_core::test_support::thread_manager_with_models_provider_and_home;
use codex_exec_server::EnvironmentManager;
use codex_exec_server::SshAuthentication;
use codex_exec_server::SshEnvironmentConfig;
use codex_exec_server::SshTmuxMode;
use codex_features::Feature;
use codex_login::AuthCredentialsStoreMode;
use codex_login::AuthDotJson;
use codex_login::AuthKeyringBackendKind;
use codex_login::CodexAuth;
use codex_login::TokenData;
use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::WireApi;
use codex_model_provider_info::create_oss_provider_with_base_url;
use codex_models_manager::manager::RefreshStrategy;
use codex_protocol::config_types::CollaborationMode;
use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::config_types::SandboxMode;
use codex_protocol::config_types::Settings;
use codex_protocol::dynamic_tools::DynamicToolCallOutputContentItem;
use codex_protocol::dynamic_tools::DynamicToolResponse;
use codex_protocol::dynamic_tools::DynamicToolSpec;
use codex_protocol::models::ImageDetail;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::ReviewDecision;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::ThreadSettingsOverrides;
use codex_protocol::user_input::UserInput;
use tokio::time::timeout;

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
    /// Stable saved-profile key used to pool physical SSH transports.
    pub connection_key: String,
    /// Stable per-agent key used for the node's independent tmux session.
    pub session_key: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub authentication: SshAuthentication,
    /// Expected host-key fingerprint in OpenSSH `SHA256:<base64nopad>` form.
    /// When `Some`, host-key pinning is enforced in `SshProcessBackend`: the
    /// SSH connection is rejected unless the server key fingerprint matches.
    /// When `None`, any host key is accepted (permissive).
    pub host_fingerprint: Option<String>,
    pub tmux_mode: SshTmuxMode,
}

#[derive(Clone, Debug)]
pub struct ServerFileUpload {
    pub local_path: String,
    pub relative_path: String,
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
/// A dynamic-tool call the model made that PAUSES the turn until the client
/// replies via `codex_respond_dynamic_tool`. Payload is JSON
/// `{"turn_handle": <u64>, "call_id": <str>, "tool": <str>,
///   "namespace": <str|null>, "arguments": <value>}`. The turn resumes once the
/// matching response is submitted.
const KIND_DYNAMIC_TOOL_CALL: c_int = 7;
const KIND_ERROR: c_int = 3;
const IOS_APIKEY_PROVIDER_ID: &str = "ios-apikey";
const POST_DYNAMIC_IMAGE_EVENT_TIMEOUT: Duration = Duration::from_secs(90);
const DYNAMIC_IMAGE_RESPONSE_SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT_IMAGE_SUBMIT_TIMEOUT: Duration = Duration::from_secs(45);
const PROMPT_IMAGE_FIRST_EVENT_TIMEOUT: Duration = Duration::from_secs(120);

fn turn_runtime() -> &'static tokio::runtime::Runtime {
    static TURN_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    TURN_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_stack_size(16 * 1024 * 1024)
            .build()
            .expect("failed to build shared codex turn runtime")
    })
}

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

fn parse_server_file_uploads(uploads_json: &str) -> Result<Vec<ServerFileUpload>, String> {
    let trimmed = uploads_json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("uploads_json was not valid JSON: {e}"))?;
    let Some(items) = value.as_array() else {
        return Err("uploads_json must be a JSON array".to_string());
    };

    let mut uploads = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let local_path = item
            .get("local_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("uploads_json[{index}].local_path must be a string"))?;
        let relative_path = item
            .get("relative_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("uploads_json[{index}].relative_path must be a string"))?;

        if local_path.trim().is_empty() {
            return Err(format!("uploads_json[{index}].local_path was empty"));
        }
        validate_upload_relative_path(relative_path)
            .map_err(|e| format!("uploads_json[{index}].relative_path {e}"))?;

        uploads.push(ServerFileUpload {
            local_path: local_path.to_string(),
            relative_path: relative_path.to_string(),
        });
    }

    Ok(uploads)
}

fn validate_upload_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("was empty".to_string());
    }
    if path.starts_with('/') {
        return Err("must be relative".to_string());
    }
    if path.split('/').any(|part| part == "..") {
        return Err("must not contain '..' segments".to_string());
    }
    Ok(())
}

fn join_remote_workspace_path(workspace: &str, relative_path: &str) -> String {
    let workspace = workspace.trim_end_matches('/');
    if workspace.is_empty() {
        relative_path.to_string()
    } else {
        format!("{workspace}/{relative_path}")
    }
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

fn emit_debug_stage(callback: EventCallback, ctx: *mut c_void, stage: &str) {
    let _ = (callback, ctx, stage);
}

/// Monotonic per-turn handle allocated for each turn that may pause on a dynamic
/// tool call. Included in the KIND_DYNAMIC_TOOL_CALL payload and passed back by
/// the client through `codex_respond_dynamic_tool` to route the response to the
/// correct in-flight turn.
static NEXT_TURN_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Sender half used to deliver a client-provided dynamic tool response into the
/// event loop of the turn identified by a turn handle.
type ResponseSender = tokio::sync::mpsc::UnboundedSender<(String, DynamicToolResponse)>;

/// Global registry mapping a turn handle to the channel its event loop is
/// awaiting a dynamic tool response on. Populated for the duration of each turn
/// and removed when the turn ends (via a drop guard on every return path).
fn dynamic_tool_registry() -> &'static Mutex<HashMap<u64, ResponseSender>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, ResponseSender>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Removes a turn's registry entry when the turn's async body returns, on ANY
/// path (TurnComplete, Error, or a `?` early-return), so a handle can never
/// outlive its turn.
struct RegistryGuard(u64);

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = dynamic_tool_registry().lock() {
            map.remove(&self.0);
        }
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

/// Fetch the picker-ready model catalog for the supplied ChatGPT account using
/// the same authenticated Codex ModelsManager that configures normal turns.
pub(crate) async fn list_oauth_models_json(
    access_token: String,
    id_token: String,
    account_id: String,
) -> Result<String, String> {
    let home_guard = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
    let auth = build_auth(home_guard.path(), access_token, id_token, account_id).await?;
    let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
    let thread_manager = thread_manager_with_models_provider(auth, provider);
    let models = thread_manager.list_models(RefreshStrategy::Online).await;
    serde_json::to_string(&models).map_err(|e| format!("failed to serialize model catalog: {e}"))
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

fn parse_wire_api(value: &str) -> Result<WireApi, String> {
    match value.trim() {
        "" | "responses" => Ok(WireApi::Responses),
        "chat_completions" => Ok(WireApi::ChatCompletions),
        other => Err(format!(
            "unsupported wire_api {other:?}; expected \"responses\" or \"chat_completions\""
        )),
    }
}

fn parse_ssh_authentication(
    method: &str,
    secret: String,
) -> Result<(SshAuthentication, Option<tempfile::TempDir>), String> {
    match method.trim().to_ascii_lowercase().as_str() {
        "password" => Ok((SshAuthentication::Password(secret), None)),
        "private_key" | "privatekey" | "key" => {
            let key_dir = tempfile::tempdir()
                .map_err(|e| format!("failed to create ssh key tempdir: {e}"))?;
            let key_path = key_dir.path().join("id_ssh");
            std::fs::write(&key_path, secret.as_bytes())
                .map_err(|e| format!("failed to write ssh key file: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("failed to chmod ssh key file: {e}"))?;
            }
            Ok((
                SshAuthentication::PrivateKeyPath(key_path.to_string_lossy().into_owned()),
                Some(key_dir),
            ))
        }
        other => Err(format!(
            "unsupported ssh authentication method `{other}`; expected private_key or password"
        )),
    }
}

fn parse_tmux_mode(value: &str) -> Result<SshTmuxMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "required" | "" => Ok(SshTmuxMode::Required),
        "preferred" => Ok(SshTmuxMode::Preferred),
        "disabled" | "off" => Ok(SshTmuxMode::Disabled),
        other => Err(format!(
            "unsupported ssh tmux mode `{other}`; expected required, preferred, or disabled"
        )),
    }
}

fn parse_reasoning_effort(value: &str) -> Result<Option<ReasoningEffort>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<ReasoningEffort>()
        .map(Some)
        .map_err(|e| format!("invalid reasoning effort `{value}`: {e}"))
}

async fn write_api_key_provider_config(
    codex_home: &std::path::Path,
    base_url: &str,
    wire_api: WireApi,
) -> Result<(), String> {
    let config = format!(
        r#"model_provider = "{provider_id}"

[model_providers.{provider_id}]
name = "iOS API key"
base_url = {base_url}
wire_api = "{wire_api}"
requires_openai_auth = false
supports_websockets = false
"#,
        provider_id = IOS_APIKEY_PROVIDER_ID,
        base_url = toml_basic_string(base_url),
        // Emit the exact string codex's config deserializer expects — the WireApi
        // Display renders "chatcompletions" (no underscore), which config parsing rejects.
        wire_api = match wire_api {
            WireApi::Responses => "responses",
            WireApi::ChatCompletions => "chat_completions",
        },
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
    /// `base_url` using the selected wire protocol.
    ApiKey {
        base_url: String,
        api_key: String,
        wire_api: WireApi,
    },
}

pub(crate) async fn run_turn_async(
    provider_config: ProviderAuthConfig,
    model: String,
    reasoning_effort: String,
    prompt: String,
    history_json: String,
    workspace: String,
    dynamic_tools_json: String,
    uploads: Vec<ServerFileUpload>,
    server_mode: Option<ServerMode>,
    callback: EventCallback,
    ctx: *mut c_void,
) -> Result<(), String> {
    emit_debug_stage(callback, ctx, "run_turn_async_entered");
    let reasoning_effort = parse_reasoning_effort(&reasoning_effort)?;
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
        ProviderAuthConfig::ApiKey {
            base_url,
            api_key,
            wire_api,
        } => {
            // `CodexAuth::from_api_key` produces a plain `Authorization: Bearer
            // <key>` header. The provider (name != "OpenAI") targets the given
            // base_url via the Responses wire API. requires_openai_auth is false
            // for the oss provider, so none of the ChatGPT-specific auth applies.
            //
            // The Config built below must also select a provider with this
            // base_url. Otherwise the thread starts with the default `openai`
            // provider and the request falls back to api.openai.com.
            write_api_key_provider_config(&codex_home, &base_url, wire_api).await?;
            let auth = CodexAuth::from_api_key(&api_key);
            let provider = create_oss_provider_with_base_url(&base_url, wire_api);
            (auth, provider, Some(IOS_APIKEY_PROVIDER_ID.to_string()))
        }
    };
    emit_debug_stage(callback, ctx, "auth_ready");

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
            let environment_manager = std::sync::Arc::new(EnvironmentManager::ssh_with_config(
                SERVER_MODE_ENVIRONMENT_ID,
                SshEnvironmentConfig {
                    connection_key: server.connection_key.clone(),
                    agent_key: server.session_key.clone(),
                    host: server.host.clone(),
                    port: server.port,
                    user: server.user.clone(),
                    authentication: server.authentication.clone(),
                    host_fingerprint: server.host_fingerprint.clone(),
                    tmux_mode: server.tmux_mode,
                },
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
            // An empty model means "use the account's current catalog default".
            // This keeps the iOS Provider Default option live as models evolve.
            model: (!model.trim().is_empty()).then_some(model.clone()),
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
    emit_debug_stage(callback, ctx, "config_ready");

    // An explicit effort comes from the node picker. None means the model
    // manager applies the selected model's live default.
    config.model_reasoning_effort = reasoning_effort.clone();
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

    // Disable Codex's built-in multi-agent suites (spawn_agent / wait_agent /
    // close_agent / send_message / …). Their tool names clash with OUR
    // orchestration dynamic tools (executed in Swift as persistent, visible graph
    // nodes), and the built-ins run in-process — invisible to the graph and
    // capped at ~6 concurrent threads. BOTH versions must be off:
    //   - MultiAgentV2 (feature `multi_agent_v2`) → the V2 suite
    //   - Collab       (feature `multi_agent`)    → the V1 (`multi_agent_v1__…`)
    // Missing the Collab one let the model fall back to the V1 built-ins, which
    // spawned invisible, capped sub-agents instead of our graph nodes.
    let _ = config.features.disable(Feature::MultiAgentV2);
    let _ = config.features.disable(Feature::Collab);

    // Orchestration tools are supplied by the client (Swift) as dynamic tool
    // specs and executed on-device. Parse the JSON array into DynamicToolSpecs;
    // empty/absent => a plain turn with no dynamic tools.
    let dynamic_tools: Vec<DynamicToolSpec> = if dynamic_tools_json.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&dynamic_tools_json)
            .map_err(|e| format!("failed to parse dynamic_tools_json: {e}"))?
    };

    let new_thread = thread_manager
        .start_thread_with_tools(config, dynamic_tools)
        .await
        .map_err(|e| format!("failed to start thread: {e}"))?;
    emit_debug_stage(callback, ctx, "thread_started");
    let thread = new_thread.thread;
    let session_model = new_thread.session_configured.model.clone();

    // Allocate a turn handle and register the channel the event loop will await
    // a dynamic tool response on. The drop guard removes the entry on every
    // return path so the handle never outlives the turn.
    let turn_handle = NEXT_TURN_HANDLE.fetch_add(1, Ordering::Relaxed);
    let (resp_tx, mut resp_rx) =
        tokio::sync::mpsc::unbounded_channel::<(String, DynamicToolResponse)>();
    dynamic_tool_registry()
        .lock()
        .map_err(|_| "dynamic tool registry poisoned".to_string())?
        .insert(turn_handle, resp_tx);
    let _registry_guard = RegistryGuard(turn_handle);

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
        emit_debug_stage(callback, ctx, "history_inject_begin");
        thread
            .inject_response_items(prior)
            .await
            .map_err(|e| format!("failed to seed history: {e}"))?;
        emit_debug_stage(callback, ctx, "history_inject_end");
    }

    // Submit a single user turn through the real loop, pinning the model.
    // Image uploads go in as normal prompt images instead of dynamic-tool output:
    // this uses Codex's upstream multimodal path and avoids wedging after a
    // tool-returned input_image.
    let image_uploads = uploads
        .iter()
        .filter(|upload| is_supported_image_upload(&upload.relative_path))
        .take(4)
        .collect::<Vec<_>>();
    let prompt_contains_images = !image_uploads.is_empty();
    let mut user_items = vec![UserInput::Text {
        text: prompt,
        text_elements: Vec::new(),
    }];
    user_items.extend(
        image_uploads
            .into_iter()
            .map(|upload| UserInput::LocalImage {
                path: std::path::PathBuf::from(upload.local_path.clone()),
                detail: Some(ImageDetail::Auto),
            }),
    );
    let user_input_op = Op::UserInput {
        items: user_items,
        final_output_json_schema: None,
        responsesapi_client_metadata: None,
        additional_context: Default::default(),
        thread_settings: ThreadSettingsOverrides {
            collaboration_mode: Some(CollaborationMode {
                mode: ModeKind::Default,
                settings: Settings {
                    model: if model.trim().is_empty() {
                        session_model
                    } else {
                        model
                    },
                    reasoning_effort,
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
    };
    if prompt_contains_images {
        emit_debug_stage(callback, ctx, "prompt_image_submit_begin");
        match timeout(PROMPT_IMAGE_SUBMIT_TIMEOUT, thread.submit(user_input_op)).await {
            Ok(result) => {
                let _ = result.map_err(|e| format!("failed to submit user input: {e}"))?;
                emit_debug_stage(callback, ctx, "prompt_image_submit_end");
            }
            Err(_) => {
                emit(
                    callback,
                    ctx,
                    KIND_ERROR,
                    "timed out submitting prompt image input to the model",
                );
                return Ok(());
            }
        }
    } else {
        emit_debug_stage(callback, ctx, "prompt_submit_begin");
        thread
            .submit(user_input_op)
            .await
            .map_err(|e| format!("failed to submit user input: {e}"))?;
        emit_debug_stage(callback, ctx, "prompt_submit_end");
    }

    // Drain events until the turn completes (or errors).
    // Track the reasoning summary section so we can signal bubble boundaries:
    // Codex streams reasoning as multiple summary sections (each its own thought),
    // distinguished by `summary_index`.
    let mut last_summary_index: Option<i64> = None;
    // Whether the current assistant message streamed any content deltas.
    // Providers on the Chat Completions wire API deliver the reply as a single
    // final `AgentMessage` with no `AgentMessageContentDelta`s; when that
    // happens we surface the final text as one text-delta so the app renders +
    // persists it. Responses streams deltas, so this stays true → no double-emit.
    let mut saw_message_delta = false;
    // A dynamic tool may return images back into the model. If the provider
    // wedges after accepting that output, the app otherwise waits forever with
    // no additional stream event. Keep the timeout scoped to image outputs so
    // long-running normal tools are not interrupted.
    let mut awaiting_event_after_dynamic_image = false;
    let mut awaiting_first_event_after_prompt_image = prompt_contains_images;
    loop {
        let event = if awaiting_first_event_after_prompt_image {
            emit_debug_stage(callback, ctx, "prompt_image_first_event_wait");
            match timeout(PROMPT_IMAGE_FIRST_EVENT_TIMEOUT, thread.next_event()).await {
                Ok(result) => result.map_err(|e| format!("event stream error: {e}"))?,
                Err(_) => {
                    emit(
                        callback,
                        ctx,
                        KIND_ERROR,
                        "model did not produce an event after receiving prompt image input",
                    );
                    return Ok(());
                }
            }
        } else if awaiting_event_after_dynamic_image {
            match timeout(POST_DYNAMIC_IMAGE_EVENT_TIMEOUT, thread.next_event()).await {
                Ok(result) => result.map_err(|e| format!("event stream error: {e}"))?,
                Err(_) => {
                    emit(
                        callback,
                        ctx,
                        KIND_ERROR,
                        "model did not continue after receiving image tool output",
                    );
                    return Ok(());
                }
            }
        } else {
            thread
                .next_event()
                .await
                .map_err(|e| format!("event stream error: {e}"))?
        };
        awaiting_first_event_after_prompt_image = false;
        awaiting_event_after_dynamic_image = false;
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
                if let Some(key) = tool_call_replay_key(&ev.item)
                    && replayed_tool_calls.remove(&key)
                {
                    continue;
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
                saw_message_delta = true;
                emit(callback, ctx, KIND_TEXT_DELTA, &ev.delta);
            }
            // The finalized assistant message. If it already streamed as deltas
            // (Responses), those carried the text — do nothing. If it did NOT
            // (Chat Completions), emit the full text once so the reply isn't
            // lost from the transcript / live view. Reset for the next message.
            EventMsg::AgentMessage(ev) => {
                if !saw_message_delta && !ev.message.is_empty() {
                    emit(callback, ctx, KIND_TEXT_DELTA, &ev.message);
                }
                saw_message_delta = false;
            }
            // A dynamic tool call: the turn is now PAUSED. Surface it to the
            // client with the turn handle + call id, then block THIS loop
            // awaiting the client's response (mirrors the codex-core test's
            // request -> submit(DynamicToolResponse) flow — no other events fire
            // while paused). The client executes the tool and calls
            // `codex_respond_dynamic_tool`, which delivers `(call_id, response)`
            // here; we submit it and resume draining events.
            EventMsg::DynamicToolCallRequest(req) => {
                let payload = serde_json::json!({
                    "turn_handle": turn_handle,
                    "call_id": req.call_id,
                    "tool": req.tool,
                    "namespace": req.namespace,
                    "arguments": req.arguments,
                });
                if let Ok(json) = serde_json::to_string(&payload) {
                    emit(callback, ctx, KIND_DYNAMIC_TOOL_CALL, &json);
                }
                match resp_rx.recv().await {
                    Some((call_id, response)) => {
                        let response_contains_image = response.content_items.iter().any(|item| {
                            matches!(item, DynamicToolCallOutputContentItem::InputImage { .. })
                        });
                        let op = Op::DynamicToolResponse {
                            id: call_id,
                            response,
                        };
                        if response_contains_image {
                            emit(
                                callback,
                                ctx,
                                KIND_TOOL_CALL,
                                r#"{"tool":"dynamic_image_response_submit","args":{"phase":"begin"}}"#,
                            );
                            match timeout(DYNAMIC_IMAGE_RESPONSE_SUBMIT_TIMEOUT, thread.submit(op))
                                .await
                            {
                                Ok(result) => {
                                    result.map_err(|e| {
                                        format!("failed to submit dynamic image tool response: {e}")
                                    })?;
                                    emit(
                                        callback,
                                        ctx,
                                        KIND_TOOL_CALL,
                                        r#"{"tool":"dynamic_image_response_submit","args":{"phase":"end"}}"#,
                                    );
                                }
                                Err(_) => {
                                    emit(
                                        callback,
                                        ctx,
                                        KIND_ERROR,
                                        "timed out submitting image tool output to the model",
                                    );
                                    return Ok(());
                                }
                            }
                        } else {
                            thread.submit(op).await.map_err(|e| {
                                format!("failed to submit dynamic tool response: {e}")
                            })?;
                        }
                        awaiting_event_after_dynamic_image = response_contains_image;
                    }
                    None => {
                        emit(
                            callback,
                            ctx,
                            KIND_ERROR,
                            "dynamic tool response channel closed",
                        );
                        return Ok(());
                    }
                }
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

fn is_supported_image_upload(relative_path: &str) -> bool {
    let Some(ext) = std::path::Path::new(relative_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return false;
    };
    matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp")
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
    reasoning_effort: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    workspace_path: *const c_char,
    dynamic_tools_json: *const c_char,
    uploads_json: *const c_char,
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
        let reasoning_effort = if reasoning_effort.is_null() {
            String::new()
        } else {
            c_str_to_string(reasoning_effort, "reasoning_effort")?
        };
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
        // Client-supplied dynamic tool specs (JSON array). Optional.
        let dynamic_tools = if dynamic_tools_json.is_null() {
            String::new()
        } else {
            c_str_to_string(dynamic_tools_json, "dynamic_tools_json")?
        };
        let uploads = if uploads_json.is_null() {
            Vec::new()
        } else {
            parse_server_file_uploads(&c_str_to_string(uploads_json, "uploads_json")?)?
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
                turn_runtime().block_on(run_turn_async(
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token: token,
                        id_token: id_tok,
                        account_id: account,
                    },
                    model,
                    reasoning_effort,
                    prompt,
                    history,
                    workspace,
                    dynamic_tools,
                    uploads,
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
    wire_api: *const c_char,
    model: *const c_char,
    reasoning_effort: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    workspace_path: *const c_char,
    dynamic_tools_json: *const c_char,
    uploads_json: *const c_char,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let result = std::panic::catch_unwind(move || {
        // Parse the C strings on the calling thread (the pointers are only valid
        // for the duration of this call), then move the owned data into a worker.
        let base_url = c_str_to_string(base_url, "base_url")?;
        let api_key = c_str_to_string(api_key, "api_key")?;
        let wire_api = if wire_api.is_null() {
            WireApi::Responses
        } else {
            parse_wire_api(&c_str_to_string(wire_api, "wire_api")?)?
        };
        let model = c_str_to_string(model, "model")?;
        let reasoning_effort = if reasoning_effort.is_null() {
            String::new()
        } else {
            c_str_to_string(reasoning_effort, "reasoning_effort")?
        };
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
        // Client-supplied dynamic tool specs (JSON array). Optional.
        let dynamic_tools = if dynamic_tools_json.is_null() {
            String::new()
        } else {
            c_str_to_string(dynamic_tools_json, "dynamic_tools_json")?
        };
        let uploads = if uploads_json.is_null() {
            Vec::new()
        } else {
            parse_server_file_uploads(&c_str_to_string(uploads_json, "uploads_json")?)?
        };

        // Same big-stack worker + multi-thread runtime dance as the OAuth FFI.
        std::thread::Builder::new()
            .name("codex-turn".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || -> Result<(), String> {
                let ctx = ctx_addr as *mut c_void;
                turn_runtime().block_on(run_turn_async(
                    ProviderAuthConfig::ApiKey {
                        base_url,
                        api_key,
                        wire_api,
                    },
                    model,
                    reasoning_effort,
                    prompt,
                    history,
                    workspace,
                    dynamic_tools,
                    uploads,
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

/// Generic API-key + server-mode counterpart: provider selection and SSH tool
/// routing are independent. This drives ONE turn against an API-key provider
/// while shell/exec tools run on the configured SSH host.
///
/// # Safety
/// All string pointers must be either null or valid NUL-terminated C strings.
/// `callback` must be a valid function pointer; `ctx` is passed through opaquely.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn codex_run_turn_streaming_apikey_server(
    base_url: *const c_char,
    api_key: *const c_char,
    wire_api: *const c_char,
    model: *const c_char,
    reasoning_effort: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    workspace_path: *const c_char,
    dynamic_tools_json: *const c_char,
    ssh_connection_key: *const c_char,
    ssh_session_key: *const c_char,
    ssh_host: *const c_char,
    ssh_port: u16,
    ssh_user: *const c_char,
    ssh_auth_method: *const c_char,
    ssh_secret: *const c_char,
    ssh_fingerprint: *const c_char,
    ssh_tmux_mode: *const c_char,
    uploads_json: *const c_char,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let result = std::panic::catch_unwind(move || {
        let base_url = c_str_to_string(base_url, "base_url")?;
        let api_key = c_str_to_string(api_key, "api_key")?;
        let wire_api = if wire_api.is_null() {
            WireApi::Responses
        } else {
            parse_wire_api(&c_str_to_string(wire_api, "wire_api")?)?
        };
        let model = c_str_to_string(model, "model")?;
        let reasoning_effort = if reasoning_effort.is_null() {
            String::new()
        } else {
            c_str_to_string(reasoning_effort, "reasoning_effort")?
        };
        let prompt = c_str_to_string(prompt, "prompt")?;
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };
        let workspace = if workspace_path.is_null() {
            String::new()
        } else {
            c_str_to_string(workspace_path, "workspace_path")?
        };
        let dynamic_tools = if dynamic_tools_json.is_null() {
            String::new()
        } else {
            c_str_to_string(dynamic_tools_json, "dynamic_tools_json")?
        };
        let uploads = if uploads_json.is_null() {
            Vec::new()
        } else {
            parse_server_file_uploads(&c_str_to_string(uploads_json, "uploads_json")?)?
        };

        let host = c_str_to_string(ssh_host, "ssh_host")?;
        let user = c_str_to_string(ssh_user, "ssh_user")?;
        let auth_method = c_str_to_string(ssh_auth_method, "ssh_auth_method")?;
        let secret = c_str_to_string(ssh_secret, "ssh_secret")?;
        let connection_key = if ssh_connection_key.is_null() {
            format!("{user}@{host}:{ssh_port}")
        } else {
            let value = c_str_to_string(ssh_connection_key, "ssh_connection_key")?;
            if value.trim().is_empty() {
                format!("{user}@{host}:{ssh_port}")
            } else {
                value
            }
        };
        let session_key = if ssh_session_key.is_null() {
            format!("{user}@{host}:{ssh_port}:{workspace}")
        } else {
            let s = c_str_to_string(ssh_session_key, "ssh_session_key")?;
            if s.trim().is_empty() {
                format!("{user}@{host}:{ssh_port}:{workspace}")
            } else {
                s
            }
        };
        let fingerprint = if ssh_fingerprint.is_null() {
            None
        } else {
            let s = c_str_to_string(ssh_fingerprint, "ssh_fingerprint")?;
            if s.trim().is_empty() { None } else { Some(s) }
        };
        let tmux_mode = if ssh_tmux_mode.is_null() {
            SshTmuxMode::Required
        } else {
            parse_tmux_mode(&c_str_to_string(ssh_tmux_mode, "ssh_tmux_mode")?)?
        };
        let (authentication, secret_guard) = parse_ssh_authentication(&auth_method, secret)?;

        let server_mode = ServerMode {
            connection_key,
            session_key,
            host,
            port: ssh_port,
            user,
            authentication,
            host_fingerprint: fingerprint,
            tmux_mode,
        };

        std::thread::Builder::new()
            .name("codex-turn".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || -> Result<(), String> {
                let _secret_guard = secret_guard;
                let ctx = ctx_addr as *mut c_void;
                turn_runtime().block_on(async move {
                    for upload in &uploads {
                        let remote_path =
                            join_remote_workspace_path(&workspace, &upload.relative_path);
                        crate::ssh::ssh_upload_file(
                            &server_mode.host,
                            server_mode.port,
                            &server_mode.user,
                            &server_mode.authentication,
                            server_mode.host_fingerprint.clone(),
                            &upload.local_path,
                            &remote_path,
                        )
                        .await
                        .map_err(|e| {
                            format!(
                                "failed to upload {} to SSH workspace: {e}",
                                upload.relative_path
                            )
                        })?;
                    }

                    run_turn_async(
                        ProviderAuthConfig::ApiKey {
                            base_url,
                            api_key,
                            wire_api,
                        },
                        model,
                        reasoning_effort,
                        prompt,
                        history,
                        workspace,
                        dynamic_tools,
                        uploads,
                        Some(server_mode),
                        callback,
                        ctx,
                    )
                    .await
                })
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
    reasoning_effort: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    workspace_path: *const c_char,
    dynamic_tools_json: *const c_char,
    ssh_connection_key: *const c_char,
    ssh_session_key: *const c_char,
    ssh_host: *const c_char,
    ssh_port: u16,
    ssh_user: *const c_char,
    ssh_auth_method: *const c_char,
    ssh_secret: *const c_char,
    ssh_fingerprint: *const c_char,
    ssh_tmux_mode: *const c_char,
    uploads_json: *const c_char,
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
        let reasoning_effort = if reasoning_effort.is_null() {
            String::new()
        } else {
            c_str_to_string(reasoning_effort, "reasoning_effort")?
        };
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
        // Client-supplied dynamic tool specs (JSON array). Optional.
        let dynamic_tools = if dynamic_tools_json.is_null() {
            String::new()
        } else {
            c_str_to_string(dynamic_tools_json, "dynamic_tools_json")?
        };
        let uploads = if uploads_json.is_null() {
            Vec::new()
        } else {
            parse_server_file_uploads(&c_str_to_string(uploads_json, "uploads_json")?)?
        };

        // SSH connection settings.
        let host = c_str_to_string(ssh_host, "ssh_host")?;
        let user = c_str_to_string(ssh_user, "ssh_user")?;
        let auth_method = c_str_to_string(ssh_auth_method, "ssh_auth_method")?;
        let secret = c_str_to_string(ssh_secret, "ssh_secret")?;
        let connection_key = if ssh_connection_key.is_null() {
            format!("{user}@{host}:{ssh_port}")
        } else {
            let value = c_str_to_string(ssh_connection_key, "ssh_connection_key")?;
            if value.trim().is_empty() {
                format!("{user}@{host}:{ssh_port}")
            } else {
                value
            }
        };
        let session_key = if ssh_session_key.is_null() {
            format!("{user}@{host}:{ssh_port}:{workspace}")
        } else {
            let s = c_str_to_string(ssh_session_key, "ssh_session_key")?;
            if s.trim().is_empty() {
                format!("{user}@{host}:{ssh_port}:{workspace}")
            } else {
                s
            }
        };
        // Fingerprint is optional: null/empty => no host-key pinning.
        let fingerprint = if ssh_fingerprint.is_null() {
            None
        } else {
            let s = c_str_to_string(ssh_fingerprint, "ssh_fingerprint")?;
            if s.trim().is_empty() { None } else { Some(s) }
        };
        let tmux_mode = if ssh_tmux_mode.is_null() {
            SshTmuxMode::Required
        } else {
            parse_tmux_mode(&c_str_to_string(ssh_tmux_mode, "ssh_tmux_mode")?)?
        };
        let (authentication, secret_guard) = parse_ssh_authentication(&auth_method, secret)?;

        let server_mode = ServerMode {
            connection_key,
            session_key,
            host,
            port: ssh_port,
            user,
            authentication,
            host_fingerprint: fingerprint,
            tmux_mode,
        };

        // Same big-stack worker + multi-thread runtime dance as the local FFI.
        std::thread::Builder::new()
            .name("codex-turn".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || -> Result<(), String> {
                // Hold a temporary key file alive when private-key auth is used.
                let _secret_guard = secret_guard;
                let ctx = ctx_addr as *mut c_void;
                turn_runtime().block_on(async move {
                    for upload in &uploads {
                        let remote_path =
                            join_remote_workspace_path(&workspace, &upload.relative_path);
                        crate::ssh::ssh_upload_file(
                            &server_mode.host,
                            server_mode.port,
                            &server_mode.user,
                            &server_mode.authentication,
                            server_mode.host_fingerprint.clone(),
                            &upload.local_path,
                            &remote_path,
                        )
                        .await
                        .map_err(|e| {
                            format!(
                                "failed to upload {} to SSH workspace: {e}",
                                upload.relative_path
                            )
                        })?;
                    }

                    run_turn_async(
                        ProviderAuthConfig::ChatgptOAuth {
                            access_token: token,
                            id_token: id_tok,
                            account_id: account,
                        },
                        model,
                        reasoning_effort,
                        prompt,
                        history,
                        workspace,
                        dynamic_tools,
                        uploads,
                        /*server_mode*/ Some(server_mode),
                        callback,
                        ctx,
                    )
                    .await
                })
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
    reasoning_effort: String,
    prompt: String,
    history_json: String,
    workspace: String,
    dynamic_tools_json: String,
    uploads: Vec<ServerFileUpload>,
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
                turn_runtime().block_on(run_turn_async(
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token,
                        id_token,
                        account_id,
                    },
                    model,
                    reasoning_effort,
                    prompt,
                    history_json,
                    workspace,
                    dynamic_tools_json,
                    uploads,
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

/// Resolve an in-flight dynamic tool call: deliver the client's result back to
/// the paused turn identified by `turn_handle` so it can resume. Call this once
/// per KIND_DYNAMIC_TOOL_CALL event, echoing back the `call_id` from that
/// event's payload.
///
/// `response_json` is a NUL-terminated UTF-8 JSON object. Text-only clients may
/// pass `{"text": <string>, "success": <bool>}`. Multimodal clients may pass
/// `{"content_items": [{"type": "input_text", "text": "..."}, {"type":
/// "input_image", "image_url": "data:...", "detail": "high"}], "success":
/// <bool>}`. `text` defaults to "", `success` to true.
///
/// Returns 0 on success. Non-zero codes: 1 = bad call_id pointer, 2 = bad
/// response_json pointer, 3 = response_json failed to parse, 4 = registry lock
/// poisoned, 5 = the turn already ended (receiver dropped), 6 = unknown
/// turn_handle (no such in-flight turn).
///
/// # Safety
/// `call_id` and `response_json` must be valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub extern "C" fn codex_respond_dynamic_tool(
    turn_handle: u64,
    call_id: *const c_char,
    response_json: *const c_char,
) -> c_int {
    let call_id = match c_str_to_string(call_id, "call_id") {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let response_json = match c_str_to_string(response_json, "response_json") {
        Ok(s) => s,
        Err(_) => return 2,
    };
    // Parsed via serde_json::Value to keep the C ABI stable while allowing newer
    // multimodal clients to send structured dynamic-tool content items.
    let value: serde_json::Value = match serde_json::from_str(&response_json) {
        Ok(v) => v,
        Err(_) => return 3,
    };
    let success = value
        .get("success")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let content_items = match parse_dynamic_tool_content_items(&value) {
        Ok(Some(items)) => items,
        Ok(None) => {
            let text = value
                .get("text")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            vec![DynamicToolCallOutputContentItem::InputText { text }]
        }
        Err(_) => return 3,
    };
    let response = DynamicToolResponse {
        content_items,
        success,
    };

    let sender = {
        let map = match dynamic_tool_registry().lock() {
            Ok(m) => m,
            Err(_) => return 4,
        };
        map.get(&turn_handle).cloned()
    };
    match sender {
        Some(tx) => match tx.send((call_id, response)) {
            Ok(()) => 0,
            Err(_) => 5,
        },
        None => 6,
    }
}

fn parse_dynamic_tool_content_items(
    value: &serde_json::Value,
) -> Result<Option<Vec<DynamicToolCallOutputContentItem>>, ()> {
    let Some(raw_items) = value
        .get("content_items")
        .or_else(|| value.get("contentItems"))
    else {
        return Ok(None);
    };
    let items = raw_items.as_array().ok_or(())?;
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        let item_type = item
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or(())?;
        match item_type {
            "input_text" | "inputText" => {
                let text = item
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(())?
                    .to_string();
                parsed.push(DynamicToolCallOutputContentItem::InputText { text });
            }
            "input_image" | "inputImage" => {
                let image_url = item
                    .get("image_url")
                    .or_else(|| item.get("imageUrl"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or(())?
                    .to_string();
                let detail = match item.get("detail").and_then(serde_json::Value::as_str) {
                    None => None,
                    Some("auto") => Some(ImageDetail::Auto),
                    Some("low") => Some(ImageDetail::Low),
                    Some("high") => Some(ImageDetail::High),
                    Some("original") => Some(ImageDetail::Original),
                    Some(_) => return Err(()),
                };
                parsed.push(DynamicToolCallOutputContentItem::InputImage { image_url, detail });
            }
            _ => return Err(()),
        }
    }
    Ok(Some(parsed))
}

#[cfg(test)]
#[path = "turn_tests.rs"]
mod tests;
