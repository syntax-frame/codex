use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::path::Path;

use codex_exec_server::SshAuthentication;
use codex_exec_server::SshTmuxMode;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::TurnItem;
use codex_protocol::items::UserMessageItem;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::ItemStartedEvent;

use super::CONTEXT_POINTER_FILE;
use super::KIND_CONTEXT_COMPACTION_STARTED;
use super::KIND_ERROR;
use super::KIND_ITEM_STARTED;
use super::PersistedThreadPointer;
use super::codex_run_turn_streaming_apikey;
use super::codex_steer_turn;
use super::emit_item_started_events;
use super::parse_reasoning_effort;
use super::parse_ssh_authentication;
use super::parse_tmux_mode;
use super::read_thread_pointer;
use super::tool_discovery_event_json;
use super::validate_relative_rollout_path;
use super::write_thread_pointer;

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

fn run_apikey_turn(context_home: &Path) -> Vec<(c_int, String)> {
    let base_url = CString::new("http://127.0.0.1:1/v1").expect("base URL");
    let api_key = CString::new("test-key").expect("API key");
    let wire_api = CString::new("responses").expect("wire API");
    let model = CString::new("gpt-5.4").expect("model");
    let prompt = CString::new("test prompt").expect("prompt");
    let context_home =
        CString::new(context_home.to_string_lossy().as_bytes()).expect("context home");
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
        /*dynamic_tools_json*/ std::ptr::null(),
        /*uploads_json*/ std::ptr::null(),
        ctx,
        capture_event,
    );

    events
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
fn steering_rejects_invalid_text_and_expired_handles() {
    assert_eq!(codex_steer_turn(1, std::ptr::null()), 1);

    let empty = CString::new("   ").unwrap();
    assert_eq!(codex_steer_turn(1, empty.as_ptr()), 2);

    let text = CString::new("Please change direction.").unwrap();
    assert_eq!(codex_steer_turn(u64::MAX, text.as_ptr()), 6);
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

    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        vec![KIND_ERROR]
    );
    assert!(events[0].1.contains("invalid model-context pointer"));
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

    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        vec![KIND_ERROR]
    );
    assert!(events[0].1.contains("failed to resume model context from"));
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
