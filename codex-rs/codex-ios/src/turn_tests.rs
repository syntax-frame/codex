use std::ffi::CString;
use std::path::Path;

use codex_exec_server::SshAuthentication;
use codex_exec_server::SshTmuxMode;
use codex_protocol::openai_models::ReasoningEffort;

use super::codex_steer_turn;
use super::parse_reasoning_effort;
use super::parse_ssh_authentication;
use super::parse_tmux_mode;
use super::read_thread_pointer;
use super::validate_relative_rollout_path;
use super::write_thread_pointer;

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
