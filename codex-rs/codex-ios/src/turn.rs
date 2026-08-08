//! C-ABI shim that drives the REAL Codex turn loop (`run_turn`) end-to-end and
//! streams events back to the caller via a function-pointer callback.
//!
//! Unlike [`crate::codex_run_prompt`], which issues a single Responses API
//! round-trip through `codex-api`, this entry point constructs a minimal
//! `codex-core` `ThreadManager` + `CodexThread`, submits one user turn, and
//! forwards each streamed event (reasoning deltas, assistant text deltas, turn
//! completion, errors) to the supplied callback.
//!
//! OAuth credentials are supplied as runtime arguments and remain in memory.
//! Model context is persisted separately in a caller-provided, per-node Codex
//! home so Codex can resume and compact its own rollout across app launches.

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use codex_core::CodexThread;
use codex_core::config::Config;
use codex_core::config::ConfigBuilder;
use codex_core::config::ConfigOverrides;
use codex_core::test_support::default_http_client_factory;
use codex_core::test_support::thread_manager_with_models_provider;
use codex_core::test_support::thread_manager_with_models_provider_and_home;
use codex_exec_server::EnvironmentManager;
use codex_exec_server::SshAuthentication;
use codex_exec_server::SshEnvironmentConfig;
use codex_exec_server::SshTmuxMode;
use codex_features::Feature;
use codex_login::CodexAuth;
use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::WireApi;
use codex_model_provider_info::create_oss_provider_with_base_url;
use codex_models_manager::ModelsManagerConfig;
use codex_models_manager::manager::RefreshStrategy;
use codex_protocol::config_types::CollaborationMode;
use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::config_types::SandboxMode;
use codex_protocol::config_types::Settings;
use codex_protocol::dynamic_tools::DynamicToolArgumentHandling;
use codex_protocol::dynamic_tools::DynamicToolArgumentIdentity;
use codex_protocol::dynamic_tools::DynamicToolArgumentPolicySpec;
use codex_protocol::dynamic_tools::DynamicToolCallOutputContentItem;
use codex_protocol::dynamic_tools::DynamicToolNamespaceTool;
use codex_protocol::dynamic_tools::DynamicToolResponse;
use codex_protocol::dynamic_tools::DynamicToolSpec;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ImageDetail;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ModelPreset;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::openai_models::ReasoningEffortPreset;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ItemStartedEvent;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::ReviewDecision;
use codex_protocol::protocol::ThreadSettingsOverrides;
use codex_protocol::user_input::UserInput;
use serde::Serialize;
use tokio::time::timeout;

const CONTEXT_LOCK_FILE: &str = ".agentapp-context.lock";
const CONTEXT_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const CONTEXT_LOCK_RETRY_DELAY: Duration = Duration::from_millis(50);

struct ContextFileLock(File);

impl Drop for ContextFileLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

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

const AGENTAPP_BROWSER_TOOL_NAMES: [&str; 7] = [
    "agentapp_browser_create",
    "agentapp_browser_open",
    "agentapp_browser_list",
    "agentapp_browser_snapshot",
    "agentapp_browser_act",
    "agentapp_browser_screenshot",
    "agentapp_browser_close",
];

fn trusted_agentapp_browser_argument_policy() -> Result<DynamicToolSpec, String> {
    let canonical = AGENTAPP_BROWSER_TOOL_NAMES.iter().map(|name| {
        DynamicToolArgumentIdentity {
            namespace: None,
            name: (*name).to_string(),
            // The AgentApp-owned flat names are reserved across namespaces.
            // A stale or hostile response must not regain persistence merely
            // by adding a namespace to the same function name.
            match_any_namespace: true,
            match_case_insensitive: true,
        }
    });
    let legacy_root = AGENTAPP_BROWSER_TOOL_NAMES
        .iter()
        .map(|name| DynamicToolArgumentIdentity {
            namespace: None,
            name: format!(
                "browser.{}",
                name.strip_prefix("agentapp_browser_").unwrap_or(name)
            ),
            match_any_namespace: true,
            match_case_insensitive: true,
        });
    let legacy_namespace =
        AGENTAPP_BROWSER_TOOL_NAMES
            .iter()
            .map(|name| DynamicToolArgumentIdentity {
                namespace: Some("browser".to_string()),
                name: name
                    .strip_prefix("agentapp_browser_")
                    .unwrap_or(name)
                    .to_string(),
                match_any_namespace: false,
                match_case_insensitive: true,
            });
    DynamicToolArgumentPolicySpec::trusted_transient(
        canonical
            .chain(legacy_root)
            .chain(legacy_namespace)
            .collect(),
    )
    .map(DynamicToolSpec::ArgumentPolicy)
    .map_err(str::to_string)
}

fn parse_agentapp_dynamic_tools_json(
    dynamic_tools_json: &str,
) -> Result<Vec<DynamicToolSpec>, String> {
    let mut dynamic_tools: Vec<DynamicToolSpec> = if dynamic_tools_json.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(dynamic_tools_json)
            .map_err(|error| format!("failed to parse dynamic_tools_json: {error}"))?
    };

    for spec in &mut dynamic_tools {
        match spec {
            DynamicToolSpec::Function(function) => {
                if function.argument_handling.redacts_arguments() {
                    return Err(
                        "dynamic_tools_json cannot set transient argument handling".to_string()
                    );
                }
                if AGENTAPP_BROWSER_TOOL_NAMES
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&function.name))
                {
                    function.argument_handling = DynamicToolArgumentHandling::Transient;
                }
            }
            DynamicToolSpec::Namespace(namespace) => {
                for tool in &mut namespace.tools {
                    let DynamicToolNamespaceTool::Function(function) = tool;
                    if function.argument_handling.redacts_arguments() {
                        return Err(
                            "dynamic_tools_json cannot set transient argument handling".to_string()
                        );
                    }
                    if AGENTAPP_BROWSER_TOOL_NAMES
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(&function.name))
                    {
                        return Err(format!(
                            "AgentApp browser tool name {} is reserved for the root namespace",
                            function.name
                        ));
                    }
                }
            }
            DynamicToolSpec::ArgumentPolicy(_) => {
                return Err(
                    "dynamic_tools_json cannot supply argument privacy policies".to_string()
                );
            }
        }
    }
    dynamic_tools.push(trusted_agentapp_browser_argument_policy()?);
    Ok(dynamic_tools)
}

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
/// Compatibility projection containing only the latest completed assistant
/// message. Codex's actual model context stays in its persistent rollout.
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
/// Announces the numeric handle for a live, steerable regular turn. The client
/// can pass it to `codex_steer_turn` while this turn remains active.
const KIND_TURN_READY: c_int = 8;
/// Codex compacted the persistent model context.
const KIND_CONTEXT_COMPACTED: c_int = 9;
/// Accumulated token/context-window information for the current thread.
const KIND_TOKEN_COUNT: c_int = 10;
/// Exact token usage reported by one upstream response completion.
const KIND_RAW_RESPONSE_COMPLETED: c_int = 11;
/// Canonical Codex turn-item lifecycle events.
const KIND_ITEM_STARTED: c_int = 12;
const KIND_ITEM_COMPLETED: c_int = 13;
/// Codex started compacting the persistent model context.
const KIND_CONTEXT_COMPACTION_STARTED: c_int = 14;
/// Content-free lifecycle telemetry for Core-internal deferred tool discovery.
/// Search queries, matching schemas, call IDs, and tool arguments deliberately
/// never cross this boundary.
const KIND_TOOL_DISCOVERY: c_int = 15;
/// The native Codex turn was aborted. This is terminal and is never followed
/// by KIND_DONE for the same handle.
const KIND_TURN_ABORTED: c_int = 16;
const TOOL_DISCOVERY_CONTRACT_VERSION: u32 = 1;
const KIND_ERROR: c_int = 3;
const IOS_APIKEY_PROVIDER_ID: &str = "ios-apikey";
const CONTEXT_POINTER_FILE: &str = "agentapp-thread.json";
const ERROR_TERMINAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const POST_DYNAMIC_IMAGE_EVENT_TIMEOUT: Duration = Duration::from_secs(90);
const DYNAMIC_IMAGE_RESPONSE_SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT_IMAGE_SUBMIT_TIMEOUT: Duration = Duration::from_secs(45);
const PROMPT_IMAGE_FIRST_EVENT_TIMEOUT: Duration = Duration::from_secs(120);
/// Matches AgentApp's ordered photo-picker limit. Overflow is rejected instead
/// of silently claiming images are attached after their bytes were dropped.
const MAX_PROMPT_IMAGE_UPLOADS: usize = 10;
const TURN_RUNTIME_MAX_BLOCKING_THREADS: usize = 16;
const TURN_RUNTIME_BLOCKING_THREAD_KEEP_ALIVE: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TurnFailure {
    Public(String),
    ProtectedAlreadyReported,
}

impl From<String> for TurnFailure {
    fn from(message: String) -> Self {
        Self::Public(message)
    }
}

/// Highest content-free discovery-event payload contract this library emits.
/// Additive ABI query: older libraries simply lack the symbol and never emit
/// event kind 15.
#[unsafe(no_mangle)]
pub extern "C" fn codex_ios_tool_discovery_contract_version() -> u32 {
    TOOL_DISCOVERY_CONTRACT_VERSION
}

fn turn_runtime() -> &'static tokio::runtime::Runtime {
    static TURN_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    TURN_RUNTIME.get_or_init(build_turn_runtime)
}

fn build_turn_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(TURN_RUNTIME_MAX_BLOCKING_THREADS)
        .thread_keep_alive(TURN_RUNTIME_BLOCKING_THREAD_KEEP_ALIVE)
        .enable_all()
        .thread_stack_size(16 * 1024 * 1024)
        .build()
        .expect("failed to build shared codex turn runtime")
}

fn tool_discovery_event_json(event: &str) -> String {
    serde_json::json!({
        "contract_version": TOOL_DISCOVERY_CONTRACT_VERSION,
        "event": event,
    })
    .to_string()
}

fn model_context_resume_error_class(error: &codex_protocol::error::CodexErr) -> &'static str {
    let codex_protocol::error::CodexErr::Io(error) = error else {
        return "invalid_or_unavailable";
    };
    let Some(error) = codex_rollout::rollout_read_error(error) else {
        return "invalid_or_unavailable";
    };
    match error {
        codex_rollout::RolloutReadError::ResourceExhausted { .. } => "resource_exhausted",
        codex_rollout::RolloutReadError::RecordTooLarge { .. } => "record_size_limit",
        codex_rollout::RolloutReadError::DecodedBytesTooLarge { .. } => "decoded_bytes_limit",
        codex_rollout::RolloutReadError::TooManyRecords { .. } => "record_count_limit",
        codex_rollout::RolloutReadError::TruncatedRecord { .. } => "truncated_record",
        codex_rollout::RolloutReadError::InvalidUtf8 { .. } => "invalid_utf8",
        codex_rollout::RolloutReadError::MalformedJson { .. } => "malformed_json",
        codex_rollout::RolloutReadError::CompressedData { .. } => "compressed_data",
        codex_rollout::RolloutReadError::EmptySession
        | codex_rollout::RolloutReadError::WorkerFailed => "invalid_or_unavailable",
    }
}

fn persistent_model_context_storage_error(
    operation: &'static str,
    error: &impl std::fmt::Display,
) -> String {
    tracing::warn!(
        operation,
        error = %error,
        "persistent model-context storage operation failed"
    );
    format!("failed to {operation} persistent model context")
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedThreadPointer {
    version: u32,
    thread_id: String,
    rollout_path: String,
}

fn context_turn_locks() -> &'static Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn context_turn_lock(codex_home: &Path) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
    let mut locks = context_turn_locks()
        .lock()
        .map_err(|_| "model-context lock registry poisoned".to_string())?;
    Ok(Arc::clone(
        locks
            .entry(codex_home.to_path_buf())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
    ))
}

async fn acquire_context_file_lock(codex_home: &Path) -> Result<ContextFileLock, String> {
    let lock_path = codex_home.join(CONTEXT_LOCK_FILE);
    tokio::task::spawn_blocking(move || {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| format!("failed to open model-context lock: {error}"))?;
        let deadline = Instant::now() + CONTEXT_LOCK_TIMEOUT;
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(ContextFileLock(file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(format!("failed to acquire model-context lock: {error}"));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out acquiring model-context lock at {}",
                    lock_path.display()
                ));
            }
            std::thread::sleep(CONTEXT_LOCK_RETRY_DELAY);
        }
    })
    .await
    .map_err(|error| format!("model-context lock task failed: {error}"))?
}

fn validate_relative_rollout_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err("rollout pointer must be a non-empty relative path".to_string());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("rollout pointer contains an unsafe path component".to_string());
    }
    Ok(())
}

fn event_matches_turn(event: &Event, expected_turn_id: &str) -> bool {
    if event.id != expected_turn_id {
        return false;
    }

    match &event.msg {
        EventMsg::TurnComplete(turn_complete) => turn_complete.turn_id == expected_turn_id,
        EventMsg::TurnAborted(turn_aborted) => {
            turn_aborted.turn_id.as_deref() == Some(expected_turn_id)
        }
        _ => true,
    }
}

async fn read_thread_pointer(codex_home: &Path) -> Result<Option<PathBuf>, String> {
    let pointer_path = codex_home.join(CONTEXT_POINTER_FILE);
    let bytes = match tokio::fs::read(&pointer_path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read model-context pointer {}: {error}",
                pointer_path.display()
            ));
        }
    };
    let pointer: PersistedThreadPointer = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid model-context pointer: {error}"))?;
    let relative_path = PathBuf::from(pointer.rollout_path);
    validate_relative_rollout_path(&relative_path)?;
    Ok(Some(codex_home.join(relative_path)))
}

async fn write_thread_pointer(
    codex_home: &Path,
    thread_id: codex_protocol::ThreadId,
    rollout_path: &Path,
) -> Result<(), String> {
    let relative_path = rollout_path.strip_prefix(codex_home).map_err(|_| {
        format!(
            "rollout path {} is outside model-context home {}",
            rollout_path.display(),
            codex_home.display()
        )
    })?;
    validate_relative_rollout_path(relative_path)?;
    let pointer = PersistedThreadPointer {
        version: 1,
        thread_id: thread_id.to_string(),
        rollout_path: relative_path.to_string_lossy().into_owned(),
    };
    let bytes = serde_json::to_vec(&pointer)
        .map_err(|error| format!("failed to encode model-context pointer: {error}"))?;
    let pointer_path = codex_home.join(CONTEXT_POINTER_FILE);
    let temporary_path = codex_home.join(format!("{CONTEXT_POINTER_FILE}.tmp"));
    tokio::fs::write(&temporary_path, bytes)
        .await
        .map_err(|error| format!("failed to write model-context pointer: {error}"))?;
    tokio::fs::rename(&temporary_path, &pointer_path)
        .await
        .map_err(|error| format!("failed to commit model-context pointer: {error}"))
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

fn finish_turn_with_cleanup(
    protected_error_emitted: bool,
    turn_result: Result<(), String>,
    cleanup_result: Result<(), String>,
) -> Result<(), TurnFailure> {
    let result = match (turn_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(format!("{error}; additionally: {cleanup_error}")),
    };
    if !protected_error_emitted {
        return result.map_err(TurnFailure::Public);
    }
    result.map_err(|error| {
        tracing::warn!(
            error = %error,
            "turn failed after a protected terminal error was reported"
        );
        TurnFailure::ProtectedAlreadyReported
    })
}

fn emit_turn_result(
    callback: EventCallback,
    ctx: *mut c_void,
    result: std::thread::Result<Result<(), TurnFailure>>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(TurnFailure::ProtectedAlreadyReported)) => {}
        Ok(Err(TurnFailure::Public(message))) => emit(callback, ctx, KIND_ERROR, &message),
        Err(_) => emit(callback, ctx, KIND_ERROR, "panic during turn"),
    }
}

fn emit_item_started_events(callback: EventCallback, ctx: *mut c_void, event: &ItemStartedEvent) {
    if let Ok(json) = serde_json::to_string(event) {
        emit(callback, ctx, KIND_ITEM_STARTED, &json);
        if matches!(&event.item, TurnItem::ContextCompaction(_)) {
            emit(callback, ctx, KIND_CONTEXT_COMPACTION_STARTED, &json);
        }
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

type ResponseSender = tokio::sync::mpsc::UnboundedSender<(String, DynamicToolResponse)>;

/// Atomic lifecycle for a registered streaming call. A handle is visible before
/// setup starts, so an interrupt cannot be lost in auth or thread construction.
enum TurnBridge {
    Starting {
        interrupt_requested: bool,
        cleanup_claimed: bool,
    },
    Active {
        dynamic_response_sender: ResponseSender,
        thread: Arc<CodexThread>,
        interrupt_requested: bool,
        cleanup_claimed: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TurnExitDisposition {
    HostDetach,
    UserInterrupt,
}

/// Global registry mapping a short-lived numeric handle to a streaming call.
/// Entries exist from the entry-point callback through worker completion.
fn active_turn_registry() -> &'static Mutex<HashMap<u64, TurnBridge>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, TurnBridge>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_starting_turn(
    callback: EventCallback,
    ctx: *mut c_void,
) -> Result<(u64, RegistryGuard), String> {
    let turn_handle = NEXT_TURN_HANDLE.fetch_add(1, Ordering::Relaxed);
    active_turn_registry()
        .lock()
        .map_err(|_| "active turn registry poisoned".to_string())?
        .insert(
            turn_handle,
            TurnBridge::Starting {
                interrupt_requested: false,
                cleanup_claimed: false,
            },
        );
    emit(callback, ctx, KIND_TURN_READY, &turn_handle.to_string());
    Ok((turn_handle, RegistryGuard(turn_handle)))
}

fn activate_turn(
    turn_handle: u64,
    thread: Arc<CodexThread>,
) -> Result<
    (
        tokio::sync::mpsc::UnboundedReceiver<(String, DynamicToolResponse)>,
        bool,
    ),
    String,
> {
    let (response_sender, response_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = active_turn_registry()
        .lock()
        .map_err(|_| "active turn registry poisoned".to_string())?;
    let entry = registry
        .get_mut(&turn_handle)
        .ok_or_else(|| "turn handle was removed during startup".to_string())?;
    let TurnBridge::Starting {
        interrupt_requested,
        cleanup_claimed,
    } = entry
    else {
        return Err("turn handle was already activated".to_string());
    };
    let interrupt_requested = *interrupt_requested;
    let cleanup_claimed = *cleanup_claimed;
    *entry = TurnBridge::Active {
        dynamic_response_sender: response_sender,
        thread,
        interrupt_requested,
        cleanup_claimed,
    };
    Ok((response_receiver, interrupt_requested))
}

fn startup_interrupt_requested(turn_handle: u64) -> Result<bool, String> {
    let registry = active_turn_registry()
        .lock()
        .map_err(|_| "active turn registry poisoned".to_string())?;
    match registry.get(&turn_handle) {
        Some(TurnBridge::Starting {
            interrupt_requested,
            ..
        }) => Ok(*interrupt_requested),
        Some(TurnBridge::Active { .. }) => Err("turn handle was already activated".to_string()),
        None => Err("unknown or finished turn handle".to_string()),
    }
}

fn claim_turn_exit_disposition(turn_handle: u64) -> Result<TurnExitDisposition, String> {
    let mut registry = active_turn_registry()
        .lock()
        .map_err(|_| "active turn registry poisoned".to_string())?;
    let (interrupt_requested, cleanup_claimed) = match registry.get_mut(&turn_handle) {
        Some(TurnBridge::Starting {
            interrupt_requested,
            cleanup_claimed,
        })
        | Some(TurnBridge::Active {
            interrupt_requested,
            cleanup_claimed,
            ..
        }) => (interrupt_requested, cleanup_claimed),
        None => return Err("unknown or finished turn handle".to_string()),
    };
    if *cleanup_claimed {
        return Err("turn cleanup was already claimed".to_string());
    }
    *cleanup_claimed = true;
    Ok(if *interrupt_requested {
        TurnExitDisposition::UserInterrupt
    } else {
        TurnExitDisposition::HostDetach
    })
}

async fn request_interrupt(turn_handle: u64) -> Result<(), String> {
    let thread = {
        let mut registry = active_turn_registry()
            .lock()
            .map_err(|_| "active turn registry poisoned".to_string())?;
        match registry.get_mut(&turn_handle) {
            Some(TurnBridge::Starting {
                interrupt_requested,
                cleanup_claimed,
            }) => {
                if *interrupt_requested {
                    return Ok(());
                }
                if *cleanup_claimed {
                    return Err("turn cleanup has already started".to_string());
                }
                *interrupt_requested = true;
                None
            }
            Some(TurnBridge::Active {
                thread,
                interrupt_requested,
                cleanup_claimed,
                ..
            }) => {
                if *interrupt_requested {
                    return Ok(());
                }
                if *cleanup_claimed {
                    return Err("turn cleanup has already started".to_string());
                }
                *interrupt_requested = true;
                Some(Arc::clone(thread))
            }
            None => return Err("unknown or finished turn handle".to_string()),
        }
    };
    if let Some(thread) = thread {
        thread
            .submit(Op::Interrupt)
            .await
            .map_err(|error| format!("failed to interrupt turn: {error}"))?;
    }
    Ok(())
}

/// Removes a turn's registry entry when the turn's async body returns, on ANY
/// path (TurnComplete, Error, or a `?` early-return), so a handle can never
/// outlive its turn.
struct RegistryGuard(u64);

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = active_turn_registry().lock() {
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

/// Build in-memory ChatGPT auth from caller-managed OAuth credentials.
///
/// AgentApp refreshes the access token outside Rust and supplies a current
/// token for each call. Using Codex's external-token representation prevents a
/// persistent model-context home from ever containing credentials or an empty
/// refresh token that Codex might later try to refresh itself.
async fn build_auth(
    access_token: String,
    _id_token: String,
    account_id: String,
) -> Result<CodexAuth, String> {
    CodexAuth::from_external_chatgpt_tokens(&access_token, &account_id, /*plan_type*/ None)
        .map_err(|error| format!("failed to construct external ChatGPT auth: {error}"))
}

/// Fetch the picker-ready model catalog for the supplied ChatGPT account using
/// the same authenticated Codex ModelsManager that configures normal turns.
pub(crate) async fn list_oauth_models_json(
    access_token: String,
    id_token: String,
    account_id: String,
) -> Result<String, String> {
    let auth = build_auth(access_token, id_token, account_id).await?;
    let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
    let thread_manager = thread_manager_with_models_provider(auth, provider);
    let models = thread_manager
        .list_models(RefreshStrategy::Online, default_http_client_factory())
        .await;
    serde_json::to_string(&models).map_err(|e| format!("failed to serialize model catalog: {e}"))
}

/// No-turn resolution payload for a ChatGPT account's dynamic OAuth defaults.
/// The selected model is always one produced by the same ModelsManager picker
/// pipeline used at turn start; unavailable is explicit rather than a guessed
/// first catalog row.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OAuthDefaultsResolution {
    Available {
        account_id: String,
        fetched_at_unix_ms: u128,
        model_slug: String,
        display_name: String,
        default_reasoning_effort: String,
    },
    Unavailable {
        account_id: String,
        fetched_at_unix_ms: u128,
        reason: String,
    },
}

/// Select a picker-visible preset using the same authentication availability
/// policy as normal model selection. ChatGPT/OAuth accounts may use a model
/// that is not API-key eligible; API-key callers remain limited to
/// `supported_in_api` presets.
fn resolve_oauth_preset(
    picker: &[ModelPreset],
    chatgpt_mode: bool,
) -> Result<ModelPreset, String> {
    let authenticated_models = ModelPreset::filter_by_auth(picker.to_vec(), chatgpt_mode);
    authenticated_models
        .iter()
        .filter(|model| model.show_in_picker)
        .find(|model| model.is_default)
        .or_else(|| {
            authenticated_models
                .iter()
                .find(|model| model.show_in_picker)
        })
        .cloned()
        .ok_or_else(|| "OAuth model picker produced no usable model".to_string())
}

fn resolve_oauth_effort(
    supported: &[ReasoningEffortPreset],
    declared_default: Option<ReasoningEffort>,
) -> Result<ReasoningEffort, String> {
    supported
        .iter()
        .find(|effort| effort.effort.to_string() == "medium")
        .map(|effort| effort.effort.clone())
        .or_else(|| declared_default.filter(|default| {
            supported.iter().any(|effort| effort.effort == *default)
        }))
        .or_else(|| supported.get(supported.len() / 2).map(|effort| effort.effort.clone()))
        .ok_or_else(|| "OAuth default model has no usable reasoning effort".to_string())
}

/// Resolve the concrete OAuth defaults without creating a turn. This follows
/// the normal root-turn ModelsManager flow: online refresh, picker filtering
/// and priority ordering, then `get_default_model` and model-info metadata.
pub(crate) async fn resolve_oauth_defaults_json(
    access_token: String,
    id_token: String,
    account_id: String,
) -> Result<String, String> {
    let auth = build_auth(access_token, id_token, account_id.clone()).await?;
    let provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
    let thread_manager = thread_manager_with_models_provider(auth, provider);
    let models_manager = thread_manager.get_models_manager();
    let http_client_factory = default_http_client_factory();
    let picker_models = models_manager
        .list_models(RefreshStrategy::Online, http_client_factory)
        .await;
    let fetched_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_millis();
    // `list_models` has already applied authenticated visibility and Core's
    // priority/recommendation ordering. An explicit account default wins; if
    // none exists, the first picker item is Core's strongest eligible model.
    let preset = match resolve_oauth_preset(&picker_models, /* chatgpt_mode */ true) {
        Ok(preset) => preset,
        Err(reason) => {
            return serde_json::to_string(&OAuthDefaultsResolution::Unavailable {
                account_id,
                fetched_at_unix_ms,
                reason,
            })
            .map_err(|error| format!("failed to serialize OAuth defaults: {error}"));
        }
    };
    let model_slug = preset.model.clone();
    let model_info = models_manager
        .get_model_info(&model_slug, &ModelsManagerConfig::default())
        .await;
    let default_reasoning_effort = match resolve_oauth_effort(
        &model_info.supported_reasoning_levels,
        model_info.default_reasoning_level,
    ) {
        Ok(effort) => effort,
        Err(reason) => {
            return serde_json::to_string(&OAuthDefaultsResolution::Unavailable {
                account_id,
                fetched_at_unix_ms,
                reason: format!("OAuth default model `{model_slug}` {reason}"),
            })
            .map_err(|error| format!("failed to serialize OAuth defaults: {error}"));
        }
    };
    serde_json::to_string(&OAuthDefaultsResolution::Available {
        account_id,
        fetched_at_unix_ms,
        model_slug,
        display_name: preset.display_name.clone(),
        default_reasoning_effort: default_reasoning_effort.to_string(),
    })
    .map_err(|error| format!("failed to serialize OAuth defaults: {error}"))
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

/// Copy one file from a configured SSH workspace to an app-provided local
/// destination. Returns an allocated empty string on success or `ERROR: ...`;
/// release it with `codex_free_string`.
///
/// # Safety
/// Every pointer must address a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn codex_download_ssh_workspace_file(
    ssh_host: *const c_char,
    ssh_port: u16,
    ssh_user: *const c_char,
    ssh_auth_method: *const c_char,
    ssh_secret: *const c_char,
    ssh_fingerprint: *const c_char,
    workspace_path: *const c_char,
    remote_path: *const c_char,
    local_path: *const c_char,
    max_bytes: u64,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<(), String> {
        let host = c_str_to_string(ssh_host, "ssh_host")?;
        let user = c_str_to_string(ssh_user, "ssh_user")?;
        let auth_method = c_str_to_string(ssh_auth_method, "ssh_auth_method")?;
        let secret = c_str_to_string(ssh_secret, "ssh_secret")?;
        let fingerprint = if ssh_fingerprint.is_null() {
            None
        } else {
            let value = c_str_to_string(ssh_fingerprint, "ssh_fingerprint")?;
            if value.trim().is_empty() {
                None
            } else {
                Some(value)
            }
        };
        let workspace = c_str_to_string(workspace_path, "workspace_path")?;
        let remote = c_str_to_string(remote_path, "remote_path")?;
        let local = c_str_to_string(local_path, "local_path")?;
        let (authentication, secret_guard) = parse_ssh_authentication(&auth_method, secret)?;

        let result = turn_runtime().block_on(crate::ssh::ssh_download_workspace_file(
            &host,
            ssh_port,
            &user,
            &authentication,
            fingerprint,
            &workspace,
            &remote,
            &local,
            max_bytes,
        ));
        drop(secret_guard);
        result.map(|_| ())
    });

    let message = match result {
        Ok(Ok(())) => String::new(),
        Ok(Err(error)) => format!("ERROR: {error}"),
        Err(_) => "ERROR: panic while downloading SSH workspace file".to_string(),
    };
    CString::new(message)
        .unwrap_or_else(|_| {
            CString::new("ERROR: invalid download result").expect("literal CString")
        })
        .into_raw()
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
    turn_handle: u64,
    provider_config: ProviderAuthConfig,
    model: String,
    reasoning_effort: String,
    service_tier: String,
    prompt: String,
    history_json: String,
    context_home: String,
    workspace: String,
    dynamic_tools_json: String,
    uploads: Vec<ServerFileUpload>,
    server_mode: Option<ServerMode>,
    callback: EventCallback,
    ctx: *mut c_void,
) -> Result<(), TurnFailure> {
    emit_debug_stage(callback, ctx, "run_turn_async_entered");
    let reasoning_effort = parse_reasoning_effort(&reasoning_effort)?;
    let service_tier = match service_tier.trim() {
        "" => None,
        "fast" => Some("priority".to_string()),
        value => Some(value.to_string()),
    };
    let temporary_home = if context_home.trim().is_empty() {
        Some(tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?)
    } else {
        None
    };
    let codex_home = temporary_home
        .as_ref()
        .map(|home| home.path().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(&context_home));
    tokio::fs::create_dir_all(&codex_home)
        .await
        .map_err(|error| format!("failed to create model-context home: {error}"))?;
    let turn_lock = context_turn_lock(&codex_home)?;
    let _turn_guard = turn_lock.lock().await;
    let _context_file_lock = acquire_context_file_lock(&codex_home).await?;

    // Build auth and provider independently from the persistent context home.
    // Credentials remain in memory and are never written beside the rollout.
    let (auth, provider, model_provider_override) = match provider_config {
        ProviderAuthConfig::ChatgptOAuth {
            access_token,
            id_token,
            account_id,
        } => {
            let auth = build_auth(access_token, id_token, account_id).await?;
            let _ = tokio::fs::remove_file(codex_home.join("config.toml")).await;
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
        None => thread_manager_with_models_provider_and_home(
            auth,
            provider,
            codex_home.clone(),
            Arc::new(EnvironmentManager::default_for_tests()),
        ),
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
            service_tier: service_tier.map(Some),
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
    // AgentApp has its own durable plan surface and no bridge for the upstream
    // blocking question request yet. Do not advertise tools this host cannot
    // service correctly.
    config.update_plan_enabled = false;
    config.experimental_request_user_input_enabled = false;

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
        // Keep the mobile bridge's public contract explicit: server mode offers
        // exec_command + write_stdin even if an upstream default changes.
        let _ = config.features.enable(Feature::UnifiedExec);
    } else {
        let _ = config.features.disable(Feature::ShellTool);
        let _ = config.features.disable(Feature::UnifiedExec);
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
    disable_upstream_multi_agent(&mut config);

    // Orchestration tools are supplied by the client (Swift) as dynamic tool
    // specs and executed on-device. The bridge, rather than client JSON, owns
    // the fixed browser argument-privacy policy. It is appended even when the
    // Browser Tool setting is Off so stale calls and resumed histories remain
    // protected without restoring any model-visible browser schema.
    let dynamic_tools = parse_agentapp_dynamic_tools_json(&dynamic_tools_json)?;

    let resume_path = read_thread_pointer(&codex_home).await?;
    let mut resumed = false;
    let new_thread = if let Some(rollout_path) = resume_path {
        let reconciliation_request = thread_manager
            .execution_reconciliation_request_from_rollout(rollout_path.clone())
            .await
            .map_err(|error| {
                format!(
                    "failed to resume persistent model context [{}]",
                    model_context_resume_error_class(&error)
                )
            })?;
        let pending_writes = reconciliation_request.pending_writes.clone();
        let recovered_executions = thread_manager
            .environment_manager()
            .reconcile_default_environment(reconciliation_request)
            .await
            .map_err(|error| format!("failed to reconcile exact remote executions: {error}"))?;
        emit_debug_stage(callback, ctx, "exact_execution_reconciled");
        let thread = thread_manager
            .resume_thread_from_rollout_with_tools_and_recovered_executions(
                config.clone(),
                rollout_path.clone(),
                thread_manager.auth_manager(),
                /*parent_trace*/ None,
                /*supports_openai_form_elicitation*/ false,
                dynamic_tools.clone(),
                recovered_executions,
                pending_writes,
            )
            .await
            .map_err(|error| {
                format!(
                    "failed to resume persistent model context [{}]",
                    model_context_resume_error_class(&error)
                )
            })?;
        resumed = true;
        emit_debug_stage(callback, ctx, "thread_resumed");
        thread
    } else {
        thread_manager
            .start_thread_with_tools(config, dynamic_tools)
            .await
            .map_err(|e| format!("failed to start thread: {e}"))?
    };
    emit_debug_stage(callback, ctx, "thread_ready");
    let thread = new_thread.thread;
    let session_model = new_thread.session_configured.model.clone();
    let mut protected_error_emitted = false;
    let turn_result: Result<(), String> = async {

    // `history_json` is retained for legacy bridge callers that still need to
    // bootstrap a genuinely new context. AgentApp passes it empty: resumed
    // threads load Codex's own native rollout and are never reconstructed from
    // the visible transcript.
    let prior: Vec<ResponseItem> = if resumed || history_json.trim().is_empty() {
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
    if !context_home.trim().is_empty() {
        if !resumed {
            // `rollout_path()` is reserved before the recorder has written its
            // initial SessionMeta. Materialize that record before publishing
            // the pointer so an early provider failure or startup interrupt
            // can never leave AgentApp pointing at a nonexistent rollout.
            thread
                .try_ensure_rollout_materialized()
                .await
                .map_err(|error| persistent_model_context_storage_error("materialize", &error))?;
        }
        let rollout_path = thread.rollout_path().ok_or_else(|| {
            "persistent model-context thread did not provide a rollout path".to_string()
        })?;
        let rollout_meta = codex_core::read_session_meta_line(&rollout_path)
            .await
            .map_err(|error| persistent_model_context_storage_error("validate", &error))?;
        if rollout_meta.meta.id != new_thread.thread_id {
            return Err("persistent model-context rollout belongs to another thread".to_string());
        }
        write_thread_pointer(&codex_home, new_thread.thread_id, &rollout_path).await?;
    }

    // Submit a single user turn through the real loop, pinning the model.
    // Image uploads go in as normal prompt images instead of dynamic-tool output:
    // this uses Codex's upstream multimodal path and avoids wedging after a
    // tool-returned input_image.
    let image_uploads = prompt_image_uploads(&uploads)?;
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
    // Keep the registry in Starting until the user operation has been submitted.
    // An interrupt observed before this check skips input entirely. An interrupt
    // racing after the check is preserved by activate_turn below, after input is
    // already ordered, and is then submitted and drained.
    if startup_interrupt_requested(turn_handle)? {
        emit(callback, ctx, KIND_TURN_ABORTED, "");
        return Ok(());
    }
    let mut submit_timed_out = false;
    let expected_turn_id = if prompt_contains_images {
        emit_debug_stage(callback, ctx, "prompt_image_submit_begin");
        match timeout(PROMPT_IMAGE_SUBMIT_TIMEOUT, thread.submit(user_input_op)).await {
            Ok(result) => {
                let turn_id =
                    result.map_err(|e| format!("failed to submit user input: {e}"))?;
                emit_debug_stage(callback, ctx, "prompt_image_submit_end");
                Some(turn_id)
            }
            Err(_) => {
                emit(
                    callback,
                    ctx,
                    KIND_ERROR,
                    "timed out submitting prompt image input to the model",
                );
                submit_timed_out = true;
                None
            }
        }
    } else {
        emit_debug_stage(callback, ctx, "prompt_submit_begin");
        let turn_id = thread
            .submit(user_input_op)
            .await
            .map_err(|e| format!("failed to submit user input: {e}"))?;
        emit_debug_stage(callback, ctx, "prompt_submit_end");
        Some(turn_id)
    };
    let (mut resp_rx, interrupted_during_submit) = activate_turn(turn_handle, Arc::clone(&thread))?;
    let mut interrupting_after_submit = submit_timed_out || interrupted_during_submit;
    if interrupting_after_submit {
        // The input operation is already ordered (or its submit future timed
        // out and may still have taken effect), so cancellation cannot be
        // overtaken by a later UserInput submission.
        thread
            .submit(Op::Interrupt)
            .await
            .map_err(|error| format!("failed to interrupt submitted turn: {error}"))?;
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
    let mut latest_agent_message: Option<String> = None;
    // A dynamic tool may return images back into the model. If the provider
    // wedges after accepting that output, the app otherwise waits forever with
    // no additional stream event. Keep the timeout scoped to image outputs so
    // long-running normal tools are not interrupted.
    let mut awaiting_event_after_dynamic_image = false;
    let mut awaiting_first_event_after_prompt_image = prompt_contains_images;
    let mut terminal_error_deadline: Option<tokio::time::Instant> = None;
    'event_loop: loop {
        let event = if let Some(deadline) = terminal_error_deadline {
            match tokio::time::timeout_at(deadline, thread.next_event()).await {
                Ok(result) => result.map_err(|e| format!("event stream error: {e}"))?,
                Err(_) => return Ok(()),
            }
        } else if interrupting_after_submit {
            thread
                .next_event()
                .await
                .map_err(|e| format!("event stream error while interrupting: {e}"))?
        } else if awaiting_first_event_after_prompt_image {
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
                    request_interrupt(turn_handle).await?;
                    interrupting_after_submit = true;
                    continue;
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
                    request_interrupt(turn_handle).await?;
                    interrupting_after_submit = true;
                    continue;
                }
            }
        } else {
            thread
                .next_event()
                .await
                .map_err(|e| format!("event stream error: {e}"))?
        };
        if expected_turn_id
            .as_deref()
            .is_some_and(|turn_id| !event_matches_turn(&event, turn_id))
        {
            continue;
        }
        awaiting_first_event_after_prompt_image = false;
        awaiting_event_after_dynamic_image = false;
        match event.msg {
            EventMsg::ItemStarted(ev) => {
                emit_item_started_events(callback, ctx, &ev);
            }
            EventMsg::ItemCompleted(ev) => {
                if let Ok(json) = serde_json::to_string(&ev) {
                    emit(callback, ctx, KIND_ITEM_COMPLETED, &json);
                }
            }
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
                    ResponseItem::ToolSearchCall { .. } => {
                        let payload = tool_discovery_event_json("search_requested");
                        emit(callback, ctx, KIND_TOOL_DISCOVERY, &payload);
                    }
                    ResponseItem::ToolSearchOutput { .. } => {
                        let payload = tool_discovery_event_json("search_loaded");
                        emit(callback, ctx, KIND_TOOL_DISCOVERY, &payload);
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
                latest_agent_message = Some(ev.message.clone());
                if !saw_message_delta && !ev.message.is_empty() {
                    emit(callback, ctx, KIND_TEXT_DELTA, &ev.message);
                }
                saw_message_delta = false;
            }
            EventMsg::ContextCompacted(_) => {
                emit(callback, ctx, KIND_CONTEXT_COMPACTED, "{}");
            }
            EventMsg::TokenCount(ev) => {
                if let Ok(json) = serde_json::to_string(&ev) {
                    emit(callback, ctx, KIND_TOKEN_COUNT, &json);
                }
            }
            EventMsg::RawResponseCompleted(ev) => {
                if let Ok(json) = serde_json::to_string(&ev) {
                    emit(callback, ctx, KIND_RAW_RESPONSE_COMPLETED, &json);
                }
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
                let response = loop {
                    tokio::select! {
                        biased;
                        event = thread.next_event() => {
                            let event = event.map_err(|error| {
                                format!("event stream error while awaiting tool: {error}")
                            })?;
                            if expected_turn_id
                                .as_deref()
                                .is_some_and(|turn_id| !event_matches_turn(&event, turn_id))
                            {
                                continue;
                            }
                            match event.msg {
                                EventMsg::TurnAborted(_) => {
                                    emit(callback, ctx, KIND_TURN_ABORTED, "");
                                    return Ok(());
                                }
                                EventMsg::Error(error) => {
                                    if !protected_error_emitted {
                                        emit(callback, ctx, KIND_ERROR, &error.message);
                                        protected_error_emitted = true;
                                        terminal_error_deadline = Some(
                                            tokio::time::Instant::now()
                                                + ERROR_TERMINAL_DRAIN_TIMEOUT,
                                        );
                                    }
                                    continue 'event_loop;
                                }
                                _ => continue,
                            }
                        },
                        response = resp_rx.recv() => break response,
                    }
                };
                match response {
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
                                    request_interrupt(turn_handle).await?;
                                    interrupting_after_submit = true;
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
                if !protected_error_emitted {
                    emit(callback, ctx, KIND_ERROR, &ev.message);
                    protected_error_emitted = true;
                    terminal_error_deadline = Some(
                        tokio::time::Instant::now() + ERROR_TERMINAL_DRAIN_TIMEOUT,
                    );
                }
            }
            EventMsg::TurnAborted(_) => {
                emit(callback, ctx, KIND_TURN_ABORTED, "");
                return Ok(());
            }
            EventMsg::TurnComplete(ev) => {
                if ev.error.is_some() && !protected_error_emitted {
                    // Every iOS turn installs the trusted transient browser
                    // argument policy. Preserve its privacy projection even if
                    // Core supplies the failure only on the terminal event.
                    emit(callback, ctx, KIND_ERROR, "A protected turn failed.");
                    protected_error_emitted = true;
                }
                if interrupting_after_submit || protected_error_emitted {
                    return Ok(());
                }
                // Keep the legacy history event small. The durable model context
                // is Codex's rollout; this projection exists only for consumers
                // that recover a non-streamed final assistant message.
                if let Some(message) = latest_agent_message.as_deref() {
                    let projection = serde_json::json!([{
                        "type": "message",
                        "role": "assistant",
                        "content": [{
                            "type": "output_text",
                            "text": message,
                        }],
                    }]);
                    if let Ok(json) = serde_json::to_string(&projection) {
                        emit(callback, ctx, KIND_HISTORY, &json);
                    }
                }
                emit(callback, ctx, KIND_DONE, "");
                return Ok(());
            }
            _ => {}
        }
    }
    }
    .await;
    let cleanup_result = match claim_turn_exit_disposition(turn_handle) {
        Ok(exit_disposition) => match exit_disposition {
            TurnExitDisposition::HostDetach => {
                let detach_result = thread.prepare_for_host_detach().await.map_err(|error| {
                    format!("failed to flush model context before host detach: {error}")
                });
                let shutdown_result = thread.shutdown_and_wait().await.map_err(|error| {
                    format!("failed to finish model-context host detach: {error}")
                });
                match (detach_result, shutdown_result) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                    (Err(error), Err(shutdown_error)) => {
                        Err(format!("{error}; additionally: {shutdown_error}"))
                    }
                }
            }
            TurnExitDisposition::UserInterrupt => thread
                .shutdown_and_wait()
                .await
                .map_err(|error| format!("failed to terminate interrupted model turn: {error}")),
        },
        Err(error) => Err(error),
    };
    finish_turn_with_cleanup(protected_error_emitted, turn_result, cleanup_result)
}

fn disable_upstream_multi_agent(config: &mut Config) {
    // AgentApp owns the visible, durable graph and supplies its orchestration
    // tools dynamically from Swift. `agents_enabled = false` is required in
    // addition to disabling both feature flags: without the explicit override,
    // a model's advertised MultiAgentV2 default can still select V2 and inject
    // upstream `/root` identity guidance into every independently hosted node.
    config.agents_enabled = false;
    let _ = config.features.disable(Feature::MultiAgentV2);
    let _ = config.features.disable(Feature::Collab);
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

fn prompt_image_uploads(uploads: &[ServerFileUpload]) -> Result<Vec<&ServerFileUpload>, String> {
    let images = uploads
        .iter()
        .filter(|upload| is_supported_image_upload(&upload.relative_path))
        .collect::<Vec<_>>();
    if images.len() > MAX_PROMPT_IMAGE_UPLOADS {
        return Err(format!(
            "too many prompt images: received {}, maximum is {MAX_PROMPT_IMAGE_UPLOADS}",
            images.len()
        ));
    }
    Ok(images)
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
    service_tier: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    context_home_path: *const c_char,
    workspace_path: *const c_char,
    dynamic_tools_json: *const c_char,
    uploads_json: *const c_char,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let (turn_handle, _registry_guard) = match register_starting_turn(callback, ctx) {
        Ok(registered) => registered,
        Err(message) => {
            emit(callback, ctx, KIND_ERROR, &message);
            return;
        }
    };
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
        let service_tier = if service_tier.is_null() {
            String::new()
        } else {
            c_str_to_string(service_tier, "service_tier")?
        };
        let prompt = c_str_to_string(prompt, "prompt")?;
        // History is optional: NULL or empty means a fresh conversation.
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };
        let context_home = c_str_to_string(context_home_path, "context_home_path")?;
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
            .spawn(move || -> Result<(), TurnFailure> {
                let ctx = ctx_addr as *mut c_void;
                turn_runtime().block_on(run_turn_async(
                    turn_handle,
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token: token,
                        id_token: id_tok,
                        account_id: account,
                    },
                    model,
                    reasoning_effort,
                    service_tier,
                    prompt,
                    history,
                    context_home,
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

    emit_turn_result(callback, ctx, result);
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
    service_tier: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    context_home_path: *const c_char,
    workspace_path: *const c_char,
    dynamic_tools_json: *const c_char,
    uploads_json: *const c_char,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let (turn_handle, _registry_guard) = match register_starting_turn(callback, ctx) {
        Ok(registered) => registered,
        Err(message) => {
            emit(callback, ctx, KIND_ERROR, &message);
            return;
        }
    };
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
        let service_tier = if service_tier.is_null() {
            String::new()
        } else {
            c_str_to_string(service_tier, "service_tier")?
        };
        let prompt = c_str_to_string(prompt, "prompt")?;
        // History is optional: NULL or empty means a fresh conversation.
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };
        let context_home = c_str_to_string(context_home_path, "context_home_path")?;
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
            .spawn(move || -> Result<(), TurnFailure> {
                let ctx = ctx_addr as *mut c_void;
                turn_runtime().block_on(run_turn_async(
                    turn_handle,
                    ProviderAuthConfig::ApiKey {
                        base_url,
                        api_key,
                        wire_api,
                    },
                    model,
                    reasoning_effort,
                    service_tier,
                    prompt,
                    history,
                    context_home,
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

    emit_turn_result(callback, ctx, result);
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
    service_tier: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    context_home_path: *const c_char,
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
    let (turn_handle, _registry_guard) = match register_starting_turn(callback, ctx) {
        Ok(registered) => registered,
        Err(message) => {
            emit(callback, ctx, KIND_ERROR, &message);
            return;
        }
    };
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
        let service_tier = if service_tier.is_null() {
            String::new()
        } else {
            c_str_to_string(service_tier, "service_tier")?
        };
        let prompt = c_str_to_string(prompt, "prompt")?;
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };
        let context_home = c_str_to_string(context_home_path, "context_home_path")?;
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
            .spawn(move || -> Result<(), TurnFailure> {
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
                        turn_handle,
                        ProviderAuthConfig::ApiKey {
                            base_url,
                            api_key,
                            wire_api,
                        },
                        model,
                        reasoning_effort,
                        service_tier,
                        prompt,
                        history,
                        context_home,
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

    emit_turn_result(callback, ctx, result);
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
    service_tier: *const c_char,
    prompt: *const c_char,
    history_json: *const c_char,
    context_home_path: *const c_char,
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
    let (turn_handle, _registry_guard) = match register_starting_turn(callback, ctx) {
        Ok(registered) => registered,
        Err(message) => {
            emit(callback, ctx, KIND_ERROR, &message);
            return;
        }
    };
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
        let service_tier = if service_tier.is_null() {
            String::new()
        } else {
            c_str_to_string(service_tier, "service_tier")?
        };
        let prompt = c_str_to_string(prompt, "prompt")?;
        // History is optional: NULL or empty means a fresh conversation.
        let history = if history_json.is_null() {
            String::new()
        } else {
            c_str_to_string(history_json, "history_json")?
        };
        let context_home = c_str_to_string(context_home_path, "context_home_path")?;
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
            .spawn(move || -> Result<(), TurnFailure> {
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
                        turn_handle,
                        ProviderAuthConfig::ChatgptOAuth {
                            access_token: token,
                            id_token: id_tok,
                            account_id: account,
                        },
                        model,
                        reasoning_effort,
                        service_tier,
                        prompt,
                        history,
                        context_home,
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

    emit_turn_result(callback, ctx, result);
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
    service_tier: String,
    prompt: String,
    history_json: String,
    context_home: String,
    workspace: String,
    dynamic_tools_json: String,
    uploads: Vec<ServerFileUpload>,
    server_mode: Option<ServerMode>,
    ctx: *mut c_void,
    callback: EventCallback,
) {
    let ctx_addr = ctx as usize;
    let (turn_handle, _registry_guard) = match register_starting_turn(callback, ctx) {
        Ok(registered) => registered,
        Err(message) => {
            emit(callback, ctx, KIND_ERROR, &message);
            return;
        }
    };
    let result = std::panic::catch_unwind(move || {
        std::thread::Builder::new()
            .name("codex-turn".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || -> Result<(), TurnFailure> {
                let ctx = ctx_addr as *mut c_void;
                turn_runtime().block_on(run_turn_async(
                    turn_handle,
                    ProviderAuthConfig::ChatgptOAuth {
                        access_token,
                        id_token,
                        account_id,
                    },
                    model,
                    reasoning_effort,
                    service_tier,
                    prompt,
                    history_json,
                    context_home,
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

    emit_turn_result(callback, ctx, result);
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
        let map = match active_turn_registry().lock() {
            Ok(m) => m,
            Err(_) => return 4,
        };
        match map.get(&turn_handle) {
            Some(TurnBridge::Active {
                dynamic_response_sender,
                interrupt_requested: false,
                ..
            }) => Some(dynamic_response_sender.clone()),
            Some(TurnBridge::Starting { .. })
            | Some(TurnBridge::Active {
                interrupt_requested: true,
                ..
            })
            | None => None,
        }
    };
    match sender {
        Some(tx) => match tx.send((call_id, response)) {
            Ok(()) => 0,
            Err(_) => 5,
        },
        None => 6,
    }
}

/// Inject a user-authored text message into an active regular turn.
///
/// Returns 0 when Codex accepted the steering input. Non-zero codes:
/// 1 = bad text pointer, 2 = empty text, 4 = registry lock poisoned,
/// 6 = unknown/finished turn handle, 7 = the active turn rejected steering.
///
/// # Safety
/// `text` must be a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub extern "C" fn codex_steer_turn(turn_handle: u64, text: *const c_char) -> c_int {
    let text = match c_str_to_string(text, "text") {
        Ok(text) => text,
        Err(_) => return 1,
    };
    if text.trim().is_empty() {
        return 2;
    }

    let thread = {
        let map = match active_turn_registry().lock() {
            Ok(map) => map,
            Err(_) => return 4,
        };
        match map.get(&turn_handle) {
            Some(TurnBridge::Active {
                thread,
                interrupt_requested: false,
                ..
            }) => Some(Arc::clone(thread)),
            Some(TurnBridge::Starting { .. })
            | Some(TurnBridge::Active {
                interrupt_requested: true,
                ..
            })
            | None => None,
        }
    };
    let Some(thread) = thread else {
        return 6;
    };

    let input = vec![UserInput::Text {
        text,
        text_elements: Vec::new(),
    }];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        turn_runtime().block_on(thread.steer_input(
            input,
            Default::default(),
            /*expected_turn_id*/ None,
            /*client_user_message_id*/ None,
            /*responsesapi_client_metadata*/ None,
        ))
    }));
    match result {
        Ok(Ok(_)) => 0,
        Ok(Err(_)) | Err(_) => 7,
    }
}

/// Interrupt a registered streaming turn, including one still in setup.
///
/// Returns 0 when the request is recorded (also for repeats), 4 when the
/// registry lock is poisoned, 6 for an unknown/finished handle, and 7 when an
/// active thread rejected the interrupt submission.
#[unsafe(no_mangle)]
pub extern "C" fn codex_interrupt_turn(turn_handle: u64) -> c_int {
    let thread = {
        let mut registry = match active_turn_registry().lock() {
            Ok(registry) => registry,
            Err(_) => return 4,
        };
        match registry.get_mut(&turn_handle) {
            Some(TurnBridge::Starting {
                interrupt_requested,
                cleanup_claimed,
            }) => {
                if *interrupt_requested {
                    return 0;
                }
                if *cleanup_claimed {
                    return 6;
                }
                *interrupt_requested = true;
                None
            }
            Some(TurnBridge::Active {
                thread,
                interrupt_requested,
                cleanup_claimed,
                ..
            }) => {
                if *interrupt_requested {
                    return 0;
                }
                if *cleanup_claimed {
                    return 6;
                }
                *interrupt_requested = true;
                Some(Arc::clone(thread))
            }
            None => return 6,
        }
    };
    let Some(thread) = thread else {
        return 0;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        turn_runtime().block_on(thread.submit(Op::Interrupt))
    }));
    match result {
        Ok(Ok(_)) => 0,
        Ok(Err(_)) | Err(_) => 7,
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
