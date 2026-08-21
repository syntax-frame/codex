use std::ffi::CStr;
use std::ffi::CString;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use codex_exec_server::SshAuthentication;
use codex_exec_server::SshTmuxMode;
use codex_features::Feature;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::TurnItem;
use codex_protocol::items::UserMessageItem;
use codex_protocol::openai_models::ModelPreset;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::openai_models::ReasoningEffortPreset;
use codex_protocol::protocol::CodexErrorInfo;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::ItemStartedEvent;
use codex_protocol::protocol::RateLimitReachedType;
use codex_protocol::protocol::RateLimitSnapshot;

use super::AGENTAPP_BROWSER_TOOL_NAMES;
use super::CONTEXT_LOCK_FILE;
use super::CONTEXT_POINTER_FILE;
use super::KIND_CONTEXT_COMPACTION_STARTED;
use super::KIND_DONE;
use super::KIND_ERROR;
use super::KIND_ITEM_STARTED;
use super::KIND_STARTUP_STAGE;
use super::KIND_STRUCTURED_ERROR;
use super::KIND_TURN_READY;
use super::KIND_TURN_STARTING;
use super::PersistedThreadPointer;
use super::ProviderAuthConfig;
use super::ServerFileUpload;
use super::TURN_RUNTIME_MAX_BLOCKING_THREADS;
use super::TurnBridge;
use super::TurnExitDisposition;
use super::TurnFailure;
use super::acquire_context_file_lock;
use super::active_turn_registry;
use super::build_turn_runtime;
use super::claim_turn_exit_disposition;
use super::codex_interrupt_turn;
use super::codex_ios_tool_discovery_contract_version;
use super::codex_run_turn_streaming_apikey;
use super::codex_steer_turn;
use super::codex_steer_turn_with_uploads;
use super::disable_upstream_multi_agent;
use super::emit;
use super::emit_debug_stage;
use super::emit_item_started_events;
use super::emit_turn_result;
use super::finish_host_detach_cleanup;
use super::finish_turn_after_cleanup;
use super::finish_turn_with_cleanup;
use super::interrupted_model_turn_cleanup_error;
use super::ios_error_payload;
use super::model_context_resume_error_class;
use super::model_context_resume_error_reason;
use super::parse_agentapp_dynamic_tools_json;
use super::parse_reasoning_effort;
use super::parse_server_file_uploads;
use super::parse_ssh_authentication;
use super::parse_tmux_mode;
use super::persistent_model_context_resume_error;
use super::persistent_model_context_storage_error;
use super::prompt_image_uploads;
use super::read_thread_pointer;
use super::register_starting_turn;
use super::resolve_oauth_effort;
use super::resolve_oauth_preset;
use super::startup_interrupt_requested;
use super::steering_user_input;
use super::tool_discovery_event_json;
use super::validate_relative_rollout_path;
use super::warm_thread_fingerprint;
use super::write_thread_pointer;

fn oauth_preset(model: &str, is_default: bool) -> ModelPreset {
    ModelPreset {
        id: model.to_string(),
        model: model.to_string(),
        display_name: model.to_string(),
        description: String::new(),
        default_reasoning_effort: ReasoningEffort::Medium,
        supported_reasoning_efforts: vec![],
        supports_personality: false,
        additional_speed_tiers: vec![],
        service_tiers: vec![],
        default_service_tier: None,
        is_default,
        upgrade: None,
        show_in_picker: true,
        multi_agent_version: None,
        availability_nux: None,
        supported_in_api: true,
        input_modalities: vec![],
    }
}

fn effort(effort: ReasoningEffort) -> ReasoningEffortPreset {
    ReasoningEffortPreset {
        effort,
        description: String::new(),
    }
}

#[test]
fn structured_error_payload_preserves_usage_limit_classification() {
    let error = ErrorEvent {
        message: "Usage limit reached".to_string(),
        codex_error_info: Some(CodexErrorInfo::UsageLimitExceeded),
    };
    let rate_limits = RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: Some("Codex".to_string()),
        primary: None,
        secondary: None,
        credits: None,
        individual_limit: None,
        spend_control_reached: Some(false),
        plan_type: None,
        rate_limit_reached_type: Some(RateLimitReachedType::WorkspaceMemberCreditsDepleted),
    };

    let payload = ios_error_payload(&error, Some(&rate_limits)).expect("serialize error envelope");
    let payload: serde_json::Value = serde_json::from_str(&payload).expect("parse error envelope");

    assert_eq!(
        payload,
        serde_json::json!({
            "contract_version": 1,
            "code": "usage_limit_exceeded",
            "message": "Usage limit reached",
            "rate_limits": {
                "limit_id": "codex",
                "limit_name": "Codex",
                "primary": null,
                "secondary": null,
                "credits": null,
                "individual_limit": null,
                "spend_control_reached": false,
                "plan_type": null,
                "rate_limit_reached_type": "workspace_member_credits_depleted"
            }
        })
    );
    assert_eq!(KIND_STRUCTURED_ERROR, 18);
}

#[test]
fn structured_unauthorized_error_does_not_attach_unrelated_rate_limits() {
    let error = ErrorEvent {
        message: "Sign in again".to_string(),
        codex_error_info: Some(CodexErrorInfo::Unauthorized),
    };
    let rate_limits = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: None,
        individual_limit: None,
        spend_control_reached: None,
        plan_type: None,
        rate_limit_reached_type: Some(RateLimitReachedType::RateLimitReached),
    };

    let payload = ios_error_payload(&error, Some(&rate_limits)).expect("serialize error envelope");
    let payload: serde_json::Value = serde_json::from_str(&payload).expect("parse error envelope");

    assert_eq!(
        payload,
        serde_json::json!({
            "contract_version": 1,
            "code": "unauthorized",
            "message": "Sign in again"
        })
    );
}

#[test]
fn oauth_default_policy_prefers_flag_then_ranked_picker_and_concrete_effort() {
    let ranked = vec![
        oauth_preset("strongest", false),
        oauth_preset("default", true),
        oauth_preset("other-default", true),
    ];
    assert_eq!(
        resolve_oauth_preset(&ranked, true).unwrap().model,
        "default"
    );
    let no_default = vec![
        oauth_preset("strongest", false),
        oauth_preset("weaker", false),
    ];
    assert_eq!(
        resolve_oauth_preset(&no_default, true).unwrap().model,
        "strongest"
    );
    let mut hidden = oauth_preset("hidden", true);
    hidden.show_in_picker = false;
    assert_eq!(
        resolve_oauth_preset(&[hidden, oauth_preset("visible", false)], true)
            .unwrap()
            .model,
        "visible"
    );
    assert_eq!(
        resolve_oauth_effort(
            &[
                effort(ReasoningEffort::Low),
                effort(ReasoningEffort::Medium)
            ],
            Some(ReasoningEffort::Low),
        )
        .unwrap(),
        ReasoningEffort::Medium
    );
}

#[test]
fn oauth_default_policy_uses_production_auth_filter_for_ffi_resolution() {
    let mut chatgpt_default = oauth_preset("chatgpt-default", true);
    chatgpt_default.supported_in_api = false;
    let api_picker_model = oauth_preset("api-picker-model", false);

    // The no-turn FFI resolves ChatGPT/OAuth accounts. It must retain a
    // picker-visible account default even when it is not available to an
    // API-key caller.
    assert_eq!(
        resolve_oauth_preset(
            &[chatgpt_default.clone(), api_picker_model.clone()],
            /* chatgpt_mode */ true,
        )
        .unwrap()
        .model,
        "chatgpt-default"
    );

    // The same production availability helper preserves API-key filtering.
    assert_eq!(
        resolve_oauth_preset(
            &[chatgpt_default, api_picker_model],
            /* chatgpt_mode */ false,
        )
        .unwrap()
        .model,
        "api-picker-model"
    );
}

#[test]
fn oauth_default_policy_falls_back_to_supported_default_then_middle_and_errors_empty() {
    assert_eq!(
        resolve_oauth_effort(
            &[effort(ReasoningEffort::Low), effort(ReasoningEffort::High)],
            Some(ReasoningEffort::High),
        )
        .unwrap(),
        ReasoningEffort::High
    );
    assert_eq!(
        resolve_oauth_effort(
            &[effort(ReasoningEffort::Low), effort(ReasoningEffort::High)],
            Some(ReasoningEffort::Medium),
        )
        .unwrap(),
        ReasoningEffort::High
    );
    assert!(resolve_oauth_preset(&[], true).is_err());
    assert!(resolve_oauth_effort(&[], None).is_err());
}

#[tokio::test]
async fn context_file_lock_excludes_other_os_lock_holders_and_releases_on_drop() {
    let home = tempfile::tempdir().expect("context home");
    let first = acquire_context_file_lock(home.path())
        .await
        .expect("first lock");
    let second = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.path().join(CONTEXT_LOCK_FILE))
        .expect("second descriptor");

    assert_ne!(
        unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    drop(first);
    assert_eq!(
        unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    unsafe {
        libc::flock(second.as_raw_fd(), libc::LOCK_UN);
    }
}

extern "C" fn capture_event(ctx: *mut c_void, kind: c_int, text: *const c_char) {
    // SAFETY: tests pass a live Vec pointer as `ctx`, and the synchronous bridge
    // joins its worker before returning. `emit` supplies a valid C string.
    let events = unsafe { &mut *ctx.cast::<Vec<(c_int, String)>>() };
    // SAFETY: `emit` guarantees `text` is a non-null, NUL-terminated C string
    // for the duration of this callback.
    let text = unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned();
    events.push((kind, text));
}

fn non_diagnostic_events(events: &[(c_int, String)]) -> Vec<&(c_int, String)> {
    events
        .iter()
        .filter(|(kind, _)| *kind != KIND_STARTUP_STAGE)
        .collect()
}

#[test]
fn startup_stage_uses_a_dedicated_event_kind() {
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();

    emit_debug_stage(capture_event, ctx, "thread_reused");

    assert_eq!(
        events,
        vec![(KIND_STARTUP_STAGE, "thread_reused".to_string())]
    );
}

#[test]
fn warm_thread_fingerprint_tracks_turn_configuration() {
    let provider = ProviderAuthConfig::ChatgptOAuth {
        access_token: "access-a".to_string(),
        id_token: "id-a".to_string(),
        account_id: "account-a".to_string(),
    };
    let same = warm_thread_fingerprint(
        &provider,
        "gpt-test",
        "medium",
        "default",
        "/workspace",
        "[]",
        None,
    );
    assert_eq!(
        same,
        warm_thread_fingerprint(
            &provider,
            "gpt-test",
            "medium",
            "default",
            "/workspace",
            "[]",
            None,
        )
    );

    let refreshed_provider = ProviderAuthConfig::ChatgptOAuth {
        access_token: "access-b".to_string(),
        id_token: "id-a".to_string(),
        account_id: "account-a".to_string(),
    };
    assert_ne!(
        same,
        warm_thread_fingerprint(
            &refreshed_provider,
            "gpt-test",
            "medium",
            "default",
            "/workspace",
            "[]",
            None,
        )
    );
    assert_ne!(
        same,
        warm_thread_fingerprint(
            &provider,
            "gpt-test",
            "medium",
            "default",
            "/workspace",
            r#"[{"name":"new_tool"}]"#,
            None,
        )
    );
}

#[test]
fn pre_submit_interrupt_gate_is_idempotent_and_registry_guard_cleans_up() {
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();
    let (handle, guard) = register_starting_turn(capture_event, ctx).expect("register turn");

    assert_eq!(events, vec![(KIND_TURN_STARTING, handle.to_string())]);
    assert!(!startup_interrupt_requested(handle).expect("startup state"));
    assert_eq!(codex_interrupt_turn(handle), 0);
    assert!(startup_interrupt_requested(handle).expect("interrupted startup state"));
    assert_eq!(
        claim_turn_exit_disposition(handle).expect("interrupt disposition"),
        TurnExitDisposition::UserInterrupt
    );
    assert_eq!(codex_interrupt_turn(handle), 0);
    {
        let registry = active_turn_registry().lock().expect("registry lock");
        assert!(matches!(
            registry.get(&handle),
            Some(TurnBridge::Starting {
                interrupt_requested: true,
                cleanup_claimed: true,
            })
        ));
    }

    drop(guard);
    assert_eq!(codex_interrupt_turn(handle), 6);
}

#[test]
fn host_detach_claim_rejects_a_late_stop_instead_of_reporting_false_success() {
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();
    let (handle, guard) = register_starting_turn(capture_event, ctx).expect("register turn");

    assert_eq!(
        claim_turn_exit_disposition(handle).expect("host detach claim"),
        TurnExitDisposition::HostDetach
    );
    assert_eq!(codex_interrupt_turn(handle), 6);
    assert!(!startup_interrupt_requested(handle).expect("not interrupted"));

    drop(guard);
}

#[test]
fn prompt_image_limit_matches_agentapp_picker_without_silent_truncation() {
    let uploads = (0..10)
        .map(|index| ServerFileUpload {
            local_path: format!("/tmp/image-{index}.png"),
            relative_path: format!("uploads/image-{index}.png"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        prompt_image_uploads(&uploads)
            .expect("picker-sized image batch")
            .len(),
        10
    );

    let mut overflow = uploads;
    overflow.push(ServerFileUpload {
        local_path: "/tmp/image-10.png".to_string(),
        relative_path: "uploads/image-10.png".to_string(),
    });
    assert_eq!(
        prompt_image_uploads(&overflow).expect_err("overflow must be explicit"),
        "too many prompt images: received 11, maximum is 10"
    );
}

#[test]
fn steering_upload_manifest_requires_bounded_unique_regular_files() {
    let directory = tempfile::tempdir().expect("upload directory");
    let first = directory.path().join("first.png");
    let second = directory.path().join("second.pdf");
    std::fs::write(&first, b"image").expect("first upload");
    std::fs::write(&second, b"document").expect("second upload");
    let valid = serde_json::json!([
        {
            "local_path": first,
            "relative_path": "uploads/first.png"
        },
        {
            "local_path": second,
            "relative_path": "uploads/second.pdf"
        }
    ]);
    assert_eq!(
        parse_server_file_uploads(&valid.to_string())
            .expect("valid manifest")
            .len(),
        2
    );

    let relative_local = serde_json::json!([{
        "local_path": "relative.png",
        "relative_path": "uploads/relative.png"
    }]);
    assert!(
        parse_server_file_uploads(&relative_local.to_string())
            .expect_err("local path must be absolute")
            .contains("must be absolute")
    );

    let duplicate = serde_json::json!([
        {
            "local_path": directory.path().join("first.png"),
            "relative_path": "uploads/duplicate.png"
        },
        {
            "local_path": directory.path().join("second.pdf"),
            "relative_path": "uploads/duplicate.png"
        }
    ]);
    assert!(
        parse_server_file_uploads(&duplicate.to_string())
            .expect_err("remote destination must be unique")
            .contains("was duplicated")
    );

    let malformed = serde_json::json!([{
        "local_path": directory.path().join("first.png"),
        "relative_path": "uploads//first.png"
    }]);
    assert!(
        parse_server_file_uploads(&malformed.to_string())
            .expect_err("remote path must be normalized")
            .contains("normalized relative path")
    );

    let too_many = (0..33)
        .map(|index| {
            serde_json::json!({
                "local_path": directory.path().join("first.png"),
                "relative_path": format!("uploads/{index}.png")
            })
        })
        .collect::<Vec<_>>();
    assert!(
        parse_server_file_uploads(&serde_json::Value::Array(too_many).to_string())
            .expect_err("manifest count must be bounded")
            .contains("maximum is 32")
    );
}

#[cfg(unix)]
#[test]
fn steering_upload_manifest_rejects_local_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("upload directory");
    let target = directory.path().join("target.png");
    let link = directory.path().join("link.png");
    std::fs::write(&target, b"image").expect("target upload");
    symlink(&target, &link).expect("upload symlink");
    let manifest = serde_json::json!([{
        "local_path": link,
        "relative_path": "uploads/link.png"
    }]);

    assert!(
        parse_server_file_uploads(&manifest.to_string())
            .expect_err("symlink must be rejected")
            .contains("regular non-symlink file")
    );
}

fn run_apikey_turn(context_home: &Path) -> Vec<(c_int, String)> {
    run_apikey_turn_against(context_home, "http://127.0.0.1:1/v1")
}

fn run_apikey_turn_against(context_home: &Path, base_url: &str) -> Vec<(c_int, String)> {
    let base_url = CString::new(base_url).expect("base URL");
    let api_key = CString::new("test-key").expect("API key");
    let wire_api = CString::new("responses").expect("wire API");
    let model = CString::new("gpt-5.4").expect("model");
    let prompt = CString::new("test prompt").expect("prompt");
    let context_home =
        CString::new(context_home.to_string_lossy().as_bytes()).expect("context home");
    let dynamic_tools = CString::new("[]").expect("dynamic tools");
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();

    codex_run_turn_streaming_apikey(
        base_url.as_ptr(),
        api_key.as_ptr(),
        wire_api.as_ptr(),
        model.as_ptr(),
        /*reasoning_effort*/ std::ptr::null(),
        /*service_tier*/ std::ptr::null(),
        prompt.as_ptr(),
        /*history_json*/ std::ptr::null(),
        context_home.as_ptr(),
        /*workspace_path*/ std::ptr::null(),
        dynamic_tools.as_ptr(),
        /*uploads_json*/ std::ptr::null(),
        ctx,
        capture_event,
    );

    events
}

struct RejectingResponsesServer {
    base_url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl RejectingResponsesServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rejecting server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking rejecting server");
        let address = listener.local_addr().expect("rejecting server address");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let body = r#"{"error":{"message":"forced failure","type":"invalid_request_error","code":"invalid_request"}}"#;
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut request = [0_u8; 8192];
                        let _ = stream.read(&mut request);
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{address}/v1"),
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for RejectingResponsesServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("rejecting server worker");
        }
    }
}

struct PersistenceSabotagingResponsesServer {
    base_url: String,
    sabotage_result: mpsc::Receiver<Result<(), String>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl PersistenceSabotagingResponsesServer {
    fn start(context_home: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind success server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking success server");
        let address = listener.local_addr().expect("success server address");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (sabotage_tx, sabotage_result) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let body = concat!(
                "event: response.created\n",
                "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-durability\"}}\n\n",
                "event: response.completed\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-durability\",\"usage\":{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}\n\n"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut request = [0_u8; 8192];
                        let _ = stream.read(&mut request);
                        let result = sabotage_rollout_path(context_home.as_path());
                        let _ = sabotage_tx.send(result);
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{address}/v1"),
            sabotage_result,
            stop,
            worker: Some(worker),
        }
    }

    fn sabotage_result(&self) -> Result<(), String> {
        self.sabotage_result
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| format!("missing sabotage result: {error}"))?
    }
}

impl Drop for PersistenceSabotagingResponsesServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("success server worker");
        }
    }
}

fn sabotage_rollout_path(context_home: &Path) -> Result<(), String> {
    let pointer_bytes = std::fs::read(context_home.join(CONTEXT_POINTER_FILE))
        .map_err(|error| format!("read context pointer: {error}"))?;
    let pointer: PersistedThreadPointer = serde_json::from_slice(&pointer_bytes)
        .map_err(|error| format!("decode context pointer: {error}"))?;
    let rollout_path = context_home.join(pointer.rollout_path);
    let preserved_path = rollout_path.with_extension("jsonl.preserved");
    std::fs::rename(&rollout_path, &preserved_path)
        .map_err(|error| format!("preserve rollout: {error}"))?;
    std::fs::create_dir(&rollout_path)
        .map_err(|error| format!("replace rollout with directory: {error}"))
}

#[test]
fn failed_protected_first_turn_leaves_a_resumable_rollout() {
    let home = tempfile::tempdir().expect("context home");
    let server = RejectingResponsesServer::start();

    let first = run_apikey_turn_against(home.path(), &server.base_url);
    let first_kinds = first.iter().map(|(kind, _)| *kind).collect::<Vec<_>>();
    let starting_index = first_kinds
        .iter()
        .position(|kind| *kind == KIND_TURN_STARTING)
        .expect("starting event");
    let ready_index = first_kinds
        .iter()
        .position(|kind| *kind == KIND_TURN_READY)
        .expect("ready event");
    let error_index = first_kinds
        .iter()
        .position(|kind| *kind == KIND_STRUCTURED_ERROR)
        .expect("protected error");
    assert!(starting_index < ready_index);
    assert!(ready_index < error_index);
    assert_eq!(
        first
            .iter()
            .filter(|(kind, _)| *kind == KIND_STRUCTURED_ERROR)
            .map(|(_, payload)| {
                serde_json::from_str::<serde_json::Value>(payload)
                    .expect("structured error payload")["message"]
                    .as_str()
                    .expect("structured error message")
                    .to_string()
            })
            .collect::<Vec<_>>(),
        vec!["A protected turn failed.".to_string()]
    );
    assert!(!first.iter().any(|(kind, _)| *kind == KIND_DONE));

    let pointer_path = home.path().join(CONTEXT_POINTER_FILE);
    let pointer_bytes = std::fs::read(&pointer_path).expect("durable pointer");
    let pointer: PersistedThreadPointer =
        serde_json::from_slice(&pointer_bytes).expect("pointer JSON");
    let rollout_path = home.path().join(pointer.rollout_path);
    assert!(rollout_path.is_file(), "pointer target must exist");
    assert!(
        std::fs::metadata(&rollout_path)
            .expect("rollout metadata")
            .len()
            > 0,
        "rollout must contain at least SessionMeta"
    );

    let second = run_apikey_turn_against(home.path(), &server.base_url);
    assert!(second.iter().any(|(kind, payload)| {
        *kind == KIND_STRUCTURED_ERROR
            && serde_json::from_str::<serde_json::Value>(payload)
                .ok()
                .and_then(|value| value["message"].as_str().map(str::to_string))
                .as_deref()
                == Some("A protected turn failed.")
    }));
    assert!(
        !second
            .iter()
            .any(|(_, message)| { message.contains("failed to resume persistent model context") })
    );
    assert_eq!(
        std::fs::read(pointer_path).expect("stable pointer"),
        pointer_bytes
    );
}

#[test]
fn bridge_never_emits_done_when_rollout_flush_and_shutdown_fail() {
    let home = tempfile::tempdir().expect("context home");
    let server = PersistenceSabotagingResponsesServer::start(home.path().to_path_buf());

    let events = run_apikey_turn_against(home.path(), &server.base_url);
    server
        .sabotage_result()
        .expect("replace the live rollout path");

    assert!(
        !events.iter().any(|(kind, _)| *kind == KIND_DONE),
        "terminal success must wait for durable persistence cleanup"
    );
    let errors = events
        .iter()
        .filter(|(kind, _)| *kind == KIND_ERROR)
        .map(|(_, message)| message.as_str())
        .collect::<Vec<_>>();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("failed to flush persistent model context"));
    assert!(errors[0].contains("failed to shutdown persistent model context"));
    assert!(!errors[0].contains(home.path().to_string_lossy().as_ref()));
    assert!(!errors[0].contains("rollout.jsonl"));
}

#[test]
fn turn_runtime_enforces_blocking_pool_ceiling() {
    let runtime = build_turn_runtime();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (started_tx, started_rx) = mpsc::channel();
    let mut tasks = Vec::new();
    for _ in 0..(TURN_RUNTIME_MAX_BLOCKING_THREADS * 4) {
        let gate = Arc::clone(&gate);
        let started_tx = started_tx.clone();
        tasks.push(runtime.spawn_blocking(move || {
            started_tx.send(()).expect("started receiver");
            let (released, wake) = &*gate;
            let mut released = released.lock().expect("gate lock");
            while !*released {
                released = wake.wait(released).expect("gate wait");
            }
        }));
    }
    drop(started_tx);

    let mut started_before_release = 0usize;
    let mut start_observation_error = None;
    for _ in 0..TURN_RUNTIME_MAX_BLOCKING_THREADS {
        match started_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => started_before_release += 1,
            Err(error) => {
                start_observation_error = Some(error);
                break;
            }
        }
    }
    let seventeenth_started = matches!(started_rx.recv_timeout(Duration::from_millis(250)), Ok(()));

    {
        let (released, wake) = &*gate;
        *released.lock().expect("gate lock") = true;
        wake.notify_all();
    }
    runtime.block_on(async {
        for task in tasks {
            task.await.expect("blocking task should finish");
        }
    });
    assert!(
        start_observation_error.is_none(),
        "not all configured blocking workers started: {start_observation_error:?}"
    );
    assert_eq!(
        started_before_release, TURN_RUNTIME_MAX_BLOCKING_THREADS,
        "unexpected configured blocking-worker count"
    );
    assert!(
        !seventeenth_started,
        "a seventeenth blocking worker started before capacity was released"
    );
    eprintln!(
        "turn_runtime_blocking_ceiling_evidence started_before_release={started_before_release}"
    );
}

#[tokio::test]
async fn agentapp_policy_cannot_be_reenabled_by_model_multi_agent_defaults() {
    let home = tempfile::tempdir().expect("config home");
    let mut config = codex_core::config::ConfigBuilder::default()
        .codex_home(home.path().to_path_buf())
        .build()
        .await
        .expect("default config");
    let _ = config.features.enable(Feature::MultiAgentV2);
    let _ = config.features.enable(Feature::Collab);
    disable_upstream_multi_agent(&mut config);

    assert!(!config.agents_enabled);
    assert!(!config.features.enabled(Feature::MultiAgentV2));
    assert!(!config.features.enabled(Feature::Collab));
}

#[test]
fn model_context_resume_errors_are_content_free_stable_classes() {
    use codex_protocol::error::CodexErr;
    use codex_rollout::RolloutReadError;
    use codex_rollout::RolloutReadResource;

    for (error, expected) in [
        (
            RolloutReadError::ResourceExhausted {
                resource: RolloutReadResource::ItemList,
                record: 7,
            },
            "resource_exhausted",
        ),
        (
            RolloutReadError::DecodedBytesTooLarge { limit: 268_435_456 },
            "decoded_bytes_limit",
        ),
        (
            RolloutReadError::RecordTooLarge {
                record: 9,
                limit: 100_663_296,
            },
            "record_size_limit",
        ),
        (
            RolloutReadError::TooManyRecords { limit: 100_000 },
            "record_count_limit",
        ),
        (
            RolloutReadError::TruncatedRecord { record: 11 },
            "truncated_record",
        ),
        (RolloutReadError::InvalidUtf8 { record: 5 }, "invalid_utf8"),
        (
            RolloutReadError::MalformedJson { record: 4 },
            "malformed_json",
        ),
        (
            RolloutReadError::CompressedData { record: 8 },
            "compressed_data",
        ),
    ] {
        let error = CodexErr::Io(std::io::Error::other(error));
        assert_eq!(model_context_resume_error_class(&error), expected);
    }
    assert_eq!(
        model_context_resume_error_class(&CodexErr::Fatal("private structural detail".to_string())),
        "invalid_or_unavailable"
    );
    let receipt_gap = CodexErr::Fatal(
        "background session private has completed nonempty write_stdin call private \
         without a durable stdout cursor receipt"
            .to_string(),
    );
    assert_eq!(
        model_context_resume_error_reason(&receipt_gap),
        "remote_write_receipt_gap"
    );
    let restoration = CodexErr::Fatal(
        "committed background session private did not resolve to one exact descriptor".to_string(),
    );
    assert_eq!(
        model_context_resume_error_reason(&restoration),
        "remote_session_restoration"
    );
    let restoration_message = persistent_model_context_resume_error("thread_resume", &restoration);
    assert_eq!(
        restoration_message,
        "failed to resume persistent model context \
         [invalid_or_unavailable;stage=thread_resume;reason=remote_session_restoration]"
    );
    assert!(!restoration_message.contains("background session private"));
    let public_message = persistent_model_context_resume_error("thread_resume", &receipt_gap);
    assert_eq!(
        public_message,
        "failed to resume persistent model context \
         [invalid_or_unavailable;stage=thread_resume;reason=remote_write_receipt_gap]"
    );
    assert!(!public_message.contains("background session private"));
    assert!(!public_message.contains("write_stdin call private"));
}

#[test]
fn persistent_model_context_storage_errors_hide_internal_details() {
    let private_detail = "/private/context/sessions/rollout.jsonl: malformed secret record";

    for operation in ["materialize", "validate"] {
        let public_message = persistent_model_context_storage_error(operation, &private_detail);
        assert_eq!(
            public_message,
            format!("failed to {operation} persistent model context")
        );
        assert!(!public_message.contains(private_detail));
        assert!(!public_message.contains("/private/context"));
    }

    let public_message = interrupted_model_turn_cleanup_error(&private_detail);
    assert_eq!(public_message, "failed to terminate interrupted model turn");
    assert!(!public_message.contains(private_detail));
    assert!(!public_message.contains("/private/context"));
}

#[test]
fn protected_turn_post_error_failures_never_cross_ffi() {
    let private_event_error =
        "event stream error: /private/context/rollout.jsonl contains secret arguments";
    let private_cleanup_error =
        "failed to finish model-context host detach: secret transport detail";
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();
    emit(capture_event, ctx, KIND_ERROR, "A protected turn failed.");

    for (turn_result, cleanup_result) in [
        (Err(private_event_error.to_string()), Ok(())),
        (Ok(()), Err(private_cleanup_error.to_string())),
    ] {
        let result = finish_turn_with_cleanup(
            /*protected_error_emitted*/ true,
            turn_result,
            cleanup_result,
        );
        assert!(
            matches!(&result, Err(TurnFailure::ProtectedAlreadyReported)),
            "post-error failure must retain failure semantics"
        );
        emit_turn_result(capture_event, ctx, Ok(result));
    }

    assert_eq!(
        events,
        vec![(KIND_ERROR, "A protected turn failed.".to_string())]
    );
    assert!(events.iter().all(|(_, message)| {
        !message.contains(private_event_error)
            && !message.contains(private_cleanup_error)
            && !message.contains("/private/context")
            && !message.contains("secret transport detail")
    }));
}

#[test]
fn done_is_emitted_only_after_successful_persistence_cleanup() {
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();

    let success = finish_turn_after_cleanup(
        capture_event,
        ctx,
        /*completed_turn*/ true,
        /*protected_error_emitted*/ false,
        Ok(()),
        Ok(()),
    );
    emit_turn_result(capture_event, ctx, Ok(success));
    assert_eq!(events, vec![(KIND_DONE, String::new())]);

    events.clear();
    let private_detail = "/private/context/rollout.jsonl: secret record";
    let cleanup_error = persistent_model_context_storage_error("shutdown", &private_detail);
    let failure = finish_turn_after_cleanup(
        capture_event,
        ctx,
        /*completed_turn*/ true,
        /*protected_error_emitted*/ false,
        Ok(()),
        Err(cleanup_error),
    );
    emit_turn_result(capture_event, ctx, Ok(failure));
    assert_eq!(
        events,
        vec![(
            KIND_ERROR,
            "failed to shutdown persistent model context".to_string(),
        )]
    );
    assert!(
        events
            .iter()
            .all(|(_, message)| !message.contains(private_detail))
    );
}

#[test]
fn completed_turn_survives_post_detach_shutdown_failure() {
    let private_detail = "/private/context/rollout.jsonl: secret SessionEnd failure";
    let shutdown_error = persistent_model_context_storage_error("shutdown", &private_detail);
    let cleanup_result =
        finish_host_detach_cleanup(/*completed_turn*/ true, Ok(()), Err(shutdown_error));
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();

    let result = finish_turn_after_cleanup(
        capture_event,
        ctx,
        /*completed_turn*/ true,
        /*protected_error_emitted*/ false,
        Ok(()),
        cleanup_result,
    );
    emit_turn_result(capture_event, ctx, Ok(result));

    assert_eq!(events, vec![(KIND_DONE, String::new())]);
    assert!(events.iter().all(|(_, message)| {
        !message.contains(private_detail) && !message.contains("/private/context")
    }));
}

#[test]
fn completed_turn_still_fails_when_host_detach_durability_barrier_fails() {
    let detach_error = persistent_model_context_storage_error(
        "flush",
        &"/private/context/rollout.jsonl: secret flush failure",
    );
    let cleanup_result =
        finish_host_detach_cleanup(/*completed_turn*/ true, Err(detach_error), Ok(()));
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();

    let result = finish_turn_after_cleanup(
        capture_event,
        ctx,
        /*completed_turn*/ true,
        /*protected_error_emitted*/ false,
        Ok(()),
        cleanup_result,
    );
    emit_turn_result(capture_event, ctx, Ok(result));

    assert_eq!(
        events,
        vec![(
            KIND_ERROR,
            "failed to flush persistent model context".to_string(),
        )]
    );
}

#[test]
fn password_authentication_preserves_secret_without_temp_file() {
    let secret = " password with spaces ".to_string();
    let (authentication, guard) =
        parse_ssh_authentication("password", secret.clone()).expect("password auth");

    match authentication {
        SshAuthentication::Password(password) => assert_eq!(password, secret),
        SshAuthentication::PrivateKeyPath(_) => panic!("expected password authentication"),
    }
    assert!(guard.is_none());
}

#[test]
fn private_key_authentication_materializes_a_scoped_mode_600_file() {
    let secret = "test-private-key".to_string();
    let (authentication, guard) =
        parse_ssh_authentication("private_key", secret.clone()).expect("private key auth");
    let path = match authentication {
        SshAuthentication::PrivateKeyPath(path) => path,
        SshAuthentication::Password(_) => panic!("expected private key authentication"),
    };
    let guard = guard.expect("private key tempdir");

    assert_eq!(
        std::fs::read_to_string(&path).expect("temporary key"),
        secret
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("temporary key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    drop(guard);
    assert!(!Path::new(&path).exists());
}

#[test]
fn tmux_modes_parse_to_their_execution_policies() {
    assert_eq!(
        parse_tmux_mode("").expect("default mode"),
        SshTmuxMode::Required
    );
    assert_eq!(
        parse_tmux_mode("preferred").expect("preferred mode"),
        SshTmuxMode::Preferred
    );
    assert_eq!(
        parse_tmux_mode("off").expect("disabled alias"),
        SshTmuxMode::Disabled
    );
    assert!(parse_tmux_mode("sometimes").is_err());
}

#[test]
fn reasoning_effort_supports_automatic_known_and_future_values() {
    assert_eq!(parse_reasoning_effort("").unwrap(), None);
    assert_eq!(
        parse_reasoning_effort("xhigh").unwrap(),
        Some(ReasoningEffort::XHigh)
    );
    assert_eq!(
        parse_reasoning_effort("future-tier").unwrap(),
        Some(ReasoningEffort::Custom("future-tier".to_string()))
    );
}

#[test]
fn browser_argument_policy_is_bridge_owned_and_present_when_catalog_is_off() {
    let tools = parse_agentapp_dynamic_tools_json("[]").expect("Off catalog");
    assert_eq!(tools.len(), 1);
    let codex_protocol::dynamic_tools::DynamicToolSpec::ArgumentPolicy(policy) = &tools[0] else {
        panic!("privacy-only policy");
    };
    assert!(policy.is_trusted());
    assert_eq!(policy.tools.len(), AGENTAPP_BROWSER_TOOL_NAMES.len() * 3);
    let runtime_policy =
        codex_protocol::dynamic_tools::DynamicToolArgumentPolicy::from_dynamic_tools(&tools);
    for name in AGENTAPP_BROWSER_TOOL_NAMES {
        let identity = policy
            .tools
            .iter()
            .find(|identity| identity.name == name)
            .expect("canonical identity");
        assert!(
            identity.match_any_namespace,
            "canonical browser names stay protected across namespace shifts"
        );
        assert!(
            runtime_policy
                .handling_for(Some("hostile__namespace"), name)
                .redacts_arguments()
        );

        let suffix = name
            .strip_prefix("agentapp_browser_")
            .expect("canonical browser prefix");
        assert!(
            runtime_policy
                .handling_for(None, &format!("browser.{suffix}"))
                .redacts_arguments()
        );
        assert!(
            runtime_policy
                .handling_for(Some("browser"), suffix)
                .redacts_arguments()
        );
    }
}

#[test]
fn bridge_marks_exact_browser_functions_transient_and_leaves_other_tools_persistent() {
    let mut wire_tools = AGENTAPP_BROWSER_TOOL_NAMES
        .iter()
        .map(|name| {
            serde_json::json!({
                "type": "function",
                "name": name,
                "description": "browser",
                "inputSchema": {"type": "object", "properties": {}},
                "deferLoading": false
            })
        })
        .collect::<Vec<_>>();
    wire_tools.push(serde_json::json!({
        "type": "function",
        "name": "ordinary_tool",
        "description": "ordinary",
        "inputSchema": {"type": "object", "properties": {}},
        "deferLoading": false
    }));
    let tools =
        parse_agentapp_dynamic_tools_json(&serde_json::to_string(&wire_tools).expect("wire JSON"))
            .expect("bridge tools");

    let functions = tools
        .iter()
        .filter_map(|spec| match spec {
            codex_protocol::dynamic_tools::DynamicToolSpec::Function(function) => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(functions.len(), AGENTAPP_BROWSER_TOOL_NAMES.len() + 1);
    for function in functions {
        if AGENTAPP_BROWSER_TOOL_NAMES.contains(&function.name.as_str()) {
            assert!(function.argument_handling.redacts_arguments());
        } else {
            assert!(function.argument_handling.is_persistent());
        }
    }
}

#[test]
fn bridge_rejects_client_supplied_privacy_authority() {
    let client_policy = serde_json::json!([{
        "type": "argumentPolicy",
        "argumentHandling": "transient",
        "tools": [{
            "name": "exec_command",
            "matchAnyNamespace": true
        }]
    }]);
    assert!(
        parse_agentapp_dynamic_tools_json(&client_policy.to_string())
            .expect_err("client policy must fail")
            .contains("cannot supply argument privacy policies")
    );

    let client_transient_function = serde_json::json!([{
        "type": "function",
        "name": "exec_command",
        "description": "collision",
        "inputSchema": {"type": "object", "properties": {}},
        "argumentHandling": "transient"
    }]);
    assert!(
        parse_agentapp_dynamic_tools_json(&client_transient_function.to_string())
            .expect_err("client transient function must fail")
            .contains("cannot set transient argument handling")
    );
}

#[test]
fn bridge_reserves_browser_names_across_case_and_namespaces() {
    let case_variant = serde_json::json!([{
        "type": "function",
        "name": "AGENTAPP_BROWSER_ACT",
        "description": "browser",
        "inputSchema": {"type": "object", "properties": {}}
    }]);
    let tools =
        parse_agentapp_dynamic_tools_json(&case_variant.to_string()).expect("case variant tool");
    let function = tools
        .iter()
        .find_map(|spec| match spec {
            codex_protocol::dynamic_tools::DynamicToolSpec::Function(function) => Some(function),
            _ => None,
        })
        .expect("function");
    assert!(function.argument_handling.redacts_arguments());

    for namespace in ["", "mcp_server"] {
        let namespaced_collision = serde_json::json!([{
            "type": "namespace",
            "name": namespace,
            "description": "hostile namespace shift",
            "tools": [{
                "type": "function",
                "name": "agentapp_browser_act",
                "description": "collision",
                "inputSchema": {"type": "object", "properties": {}}
            }]
        }]);
        assert!(
            parse_agentapp_dynamic_tools_json(&namespaced_collision.to_string())
                .expect_err("reserved browser name must not be namespaced")
                .contains("reserved for the root namespace")
        );
    }
}

#[test]
fn steering_rejects_invalid_text_and_expired_handles() {
    assert_eq!(codex_steer_turn(1, std::ptr::null()), 1);

    let empty = CString::new("   ").unwrap();
    assert_eq!(codex_steer_turn(1, empty.as_ptr()), 2);

    let text = CString::new("Please change direction.").unwrap();
    assert_eq!(codex_steer_turn(u64::MAX, text.as_ptr()), 6);

    let malformed = CString::new("{not-json").unwrap();
    assert_eq!(
        codex_steer_turn_with_uploads(u64::MAX, text.as_ptr(), malformed.as_ptr()),
        8
    );
}

#[test]
fn starting_turn_handle_rejects_attachment_steering_until_ready() {
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();
    let (handle, guard) = register_starting_turn(capture_event, ctx).expect("register turn");
    let text = CString::new("Inspect this attachment.").expect("steering text");
    let uploads = CString::new("[]").expect("empty uploads");

    assert_eq!(
        codex_steer_turn_with_uploads(handle, text.as_ptr(), uploads.as_ptr()),
        6
    );
    assert_eq!(events, vec![(KIND_TURN_STARTING, handle.to_string())]);

    drop(guard);
}

#[test]
fn attachment_steering_builds_text_and_local_image_input_without_silent_truncation() {
    let uploads = vec![
        ServerFileUpload {
            local_path: "/tmp/screenshot.png".to_string(),
            relative_path: "uploads/screenshot.png".to_string(),
        },
        ServerFileUpload {
            local_path: "/tmp/report.pdf".to_string(),
            relative_path: "uploads/report.pdf".to_string(),
        },
    ];
    let input = steering_user_input("Please inspect both attachments.".to_string(), &uploads)
        .expect("valid steering input");
    assert_eq!(input.len(), 2);
    assert!(matches!(
        &input[0],
        codex_protocol::user_input::UserInput::Text { text, .. }
            if text == "Please inspect both attachments."
    ));
    assert!(matches!(
        &input[1],
        codex_protocol::user_input::UserInput::LocalImage { path, .. }
            if path == Path::new("/tmp/screenshot.png")
    ));
}

#[test]
fn model_context_pointer_rejects_absolute_and_parent_paths() {
    assert!(validate_relative_rollout_path(Path::new("sessions/thread.jsonl")).is_ok());
    assert!(validate_relative_rollout_path(Path::new("")).is_err());
    assert!(validate_relative_rollout_path(Path::new("/tmp/thread.jsonl")).is_err());
    assert!(validate_relative_rollout_path(Path::new("../thread.jsonl")).is_err());
}

#[tokio::test]
async fn model_context_pointer_round_trips_inside_context_home() {
    let home = tempfile::tempdir().expect("context home");
    let rollout = home.path().join("sessions/2026/thread.jsonl");
    std::fs::create_dir_all(rollout.parent().expect("rollout parent")).expect("sessions");
    std::fs::write(&rollout, b"").expect("rollout");
    let thread_id = codex_protocol::ThreadId::new();

    write_thread_pointer(home.path(), thread_id, &rollout)
        .await
        .expect("write pointer");

    assert_eq!(
        read_thread_pointer(home.path())
            .await
            .expect("read pointer"),
        Some(rollout)
    );
}

#[tokio::test]
async fn model_context_pointer_refuses_rollouts_outside_context_home() {
    let home = tempfile::tempdir().expect("context home");
    let outside = tempfile::NamedTempFile::new().expect("outside rollout");

    let error = write_thread_pointer(home.path(), codex_protocol::ThreadId::new(), outside.path())
        .await
        .expect_err("outside rollout must fail");

    assert!(error.contains("outside model-context home"));
}

#[test]
fn malformed_model_context_pointer_surfaces_error_without_replacement() {
    let home = tempfile::tempdir().expect("context home");
    let pointer_path = home.path().join(CONTEXT_POINTER_FILE);
    let pointer_bytes = b"{not valid json";
    std::fs::write(&pointer_path, pointer_bytes).expect("malformed pointer");

    let events = run_apikey_turn(home.path());
    let visible_events = non_diagnostic_events(&events);

    assert_eq!(
        visible_events
            .iter()
            .map(|event| event.0)
            .collect::<Vec<_>>(),
        vec![KIND_TURN_STARTING, KIND_ERROR]
    );
    assert!(
        visible_events[1]
            .1
            .contains("invalid model-context pointer")
    );
    assert_eq!(
        std::fs::read(pointer_path).expect("preserved pointer"),
        pointer_bytes
    );
}

#[test]
fn failed_model_context_resume_preserves_pointer_and_rollout() {
    let home = tempfile::tempdir().expect("context home");
    let relative_rollout = "sessions/thread.jsonl";
    let rollout_path = home.path().join(relative_rollout);
    std::fs::create_dir_all(rollout_path.parent().expect("rollout parent"))
        .expect("rollout parent");
    let rollout_bytes = b"not a valid rollout\n";
    std::fs::write(&rollout_path, rollout_bytes).expect("invalid rollout");
    let pointer = PersistedThreadPointer {
        version: 1,
        thread_id: codex_protocol::ThreadId::new().to_string(),
        rollout_path: relative_rollout.to_string(),
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("pointer JSON");
    let pointer_path = home.path().join(CONTEXT_POINTER_FILE);
    std::fs::write(&pointer_path, &pointer_bytes).expect("pointer");

    let events = run_apikey_turn(home.path());
    let visible_events = non_diagnostic_events(&events);

    assert_eq!(
        visible_events
            .iter()
            .map(|event| event.0)
            .collect::<Vec<_>>(),
        vec![KIND_TURN_STARTING, KIND_ERROR]
    );
    assert_eq!(
        visible_events[1].1,
        "failed to resume persistent model context \
         [malformed_json;stage=execution_reconciliation;reason=rollout_read]"
    );
    assert!(
        !visible_events[1].1.contains(relative_rollout),
        "public resume errors must not expose the rollout path"
    );
    assert!(
        !visible_events[0].1.contains("not a valid rollout"),
        "public resume errors must not expose record content"
    );
    assert_eq!(
        std::fs::read(pointer_path).expect("preserved pointer"),
        pointer_bytes
    );
    assert_eq!(
        std::fs::read(rollout_path).expect("preserved rollout"),
        rollout_bytes
    );
}

#[test]
fn truncated_model_context_resume_preserves_typed_failure() {
    let home = tempfile::tempdir().expect("context home");
    let relative_rollout = "sessions/thread.jsonl";
    let rollout_path = home.path().join(relative_rollout);
    std::fs::create_dir_all(rollout_path.parent().expect("rollout parent"))
        .expect("rollout parent");
    let rollout_bytes = br#"{"timestamp":"truncated""#;
    std::fs::write(&rollout_path, rollout_bytes).expect("truncated rollout");
    let pointer = PersistedThreadPointer {
        version: 1,
        thread_id: codex_protocol::ThreadId::new().to_string(),
        rollout_path: relative_rollout.to_string(),
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("pointer JSON");
    let pointer_path = home.path().join(CONTEXT_POINTER_FILE);
    std::fs::write(&pointer_path, &pointer_bytes).expect("pointer");

    let events = run_apikey_turn(home.path());
    let visible_events = non_diagnostic_events(&events);

    assert_eq!(
        visible_events
            .iter()
            .map(|event| event.0)
            .collect::<Vec<_>>(),
        vec![KIND_TURN_STARTING, KIND_ERROR]
    );
    assert_eq!(
        visible_events[1].1,
        "failed to resume persistent model context \
         [truncated_record;stage=execution_reconciliation;reason=rollout_read]"
    );
    assert_eq!(
        std::fs::read(pointer_path).expect("preserved pointer"),
        pointer_bytes
    );
    assert_eq!(
        std::fs::read(rollout_path).expect("preserved rollout"),
        rollout_bytes
    );
}

#[test]
fn context_compaction_start_emits_dedicated_and_generic_events() {
    let thread_id = codex_protocol::ThreadId::new();
    let compaction_event = ItemStartedEvent {
        thread_id,
        turn_id: "turn-1".to_string(),
        item: TurnItem::ContextCompaction(ContextCompactionItem::new()),
        started_at_ms: 42,
    };
    let regular_event = ItemStartedEvent {
        thread_id,
        turn_id: "turn-1".to_string(),
        item: TurnItem::UserMessage(UserMessageItem::new(&[])),
        started_at_ms: 43,
    };
    let compaction_json = serde_json::to_string(&compaction_event).expect("compaction event JSON");
    let regular_json = serde_json::to_string(&regular_event).expect("regular event JSON");
    let mut events = Vec::new();
    let ctx = (&mut events as *mut Vec<(c_int, String)>).cast::<c_void>();

    emit_item_started_events(capture_event, ctx, &compaction_event);
    emit_item_started_events(capture_event, ctx, &regular_event);

    assert_eq!(
        events,
        vec![
            (KIND_ITEM_STARTED, compaction_json.clone()),
            (KIND_CONTEXT_COMPACTION_STARTED, compaction_json),
            (KIND_ITEM_STARTED, regular_json),
        ]
    );
}

#[test]
fn tool_discovery_event_is_versioned_and_content_free() {
    assert_eq!(codex_ios_tool_discovery_contract_version(), 1);
    let payload = tool_discovery_event_json("search_loaded");
    let value: serde_json::Value = serde_json::from_str(&payload).expect("discovery JSON");
    let object = value.as_object().expect("discovery object");

    assert_eq!(object.len(), 2);
    assert_eq!(object["contract_version"], 1);
    assert_eq!(object["event"], "search_loaded");
    for forbidden in [
        "prompt",
        "query",
        "arguments",
        "url",
        "credentials",
        "filename",
        "output",
        "conversation",
        "call_id",
        "turn_id",
        "node_id",
    ] {
        assert!(!object.contains_key(forbidden));
    }
}
