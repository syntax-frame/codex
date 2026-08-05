use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::watch;

use super::ChannelCommand;
use super::ExecProcessImpl;
use super::PROCESS_EVENT_CHANNEL_CAPACITY;
use super::RETAINED_OUTPUT_BYTES_PER_PROCESS;
use super::SharedState;
use super::SshLaunchMode;
use super::SshProcess;
use super::SshProcessBackend;
use super::SshTmuxMode;
use super::TestLaunchers;
use super::launch_mode;
use crate::ExecParams;
use crate::ExecutionIdentity;
use crate::ProcessId;
use crate::SshAuthentication;
use crate::process::ExecProcessEventLog;
use codex_utils_path_uri::PathUri;

fn backend_with_counted_launchers(
    tmux_mode: SshTmuxMode,
) -> (SshProcessBackend, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let tmux_launches = Arc::new(AtomicUsize::new(0));
    let direct_launches = Arc::new(AtomicUsize::new(0));
    let tmux_counter = Arc::clone(&tmux_launches);
    let direct_counter = Arc::clone(&direct_launches);
    let mut backend = SshProcessBackend::with_authentication_and_keys(
        "unused.invalid",
        22,
        "test",
        SshAuthentication::Password("unused".to_string()),
        None,
        "test-connection",
        "test-session",
        tmux_mode,
    );
    backend.test_launchers = Some(TestLaunchers {
        tmux: Arc::new(move |_params| {
            tmux_counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(crate::ExecServerError::Protocol(
                    "ssh tmux_required: unavailable: test".to_string(),
                ))
            })
        }),
        direct: Arc::new(move |_params| {
            direct_counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(crate::ExecServerError::Protocol(
                    "direct test launcher invoked".to_string(),
                ))
            })
        }),
    });
    (backend, tmux_launches, direct_launches)
}

fn test_exec_params(has_identity: bool) -> ExecParams {
    ExecParams {
        process_id: ProcessId::from("transient-process"),
        execution_identity: has_identity.then(|| ExecutionIdentity {
            thread_id: "thread".to_string(),
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 1,
        }),
        argv: vec!["true".to_string()],
        cwd: PathUri::from_host_native_path(std::env::temp_dir()).expect("cwd"),
        env_policy: None,
        env: HashMap::new(),
        tty: false,
        pipe_stdin: false,
        arg0: None,
        sandbox: None,
        enforce_managed_network: false,
        managed_network: None,
        network_proxy: None,
    }
}

fn process_with_command_pump() -> (Arc<SshProcess>, mpsc::Receiver<ChannelCommand>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(1);
    let (wake_tx, _wake_rx) = watch::channel(0);
    (
        Arc::new(SshProcess {
            process_id: ProcessId::from("process"),
            tty: false,
            tmux: true,
            events: ExecProcessEventLog::new(
                PROCESS_EVENT_CHANNEL_CAPACITY,
                RETAINED_OUTPUT_BYTES_PER_PROCESS,
            ),
            wake_tx,
            output_notify: Arc::new(Notify::new()),
            state: Arc::new(StdMutex::new(SharedState::default())),
            cmd_tx,
        }),
        cmd_rx,
    )
}

#[test]
fn durable_execution_identity_requires_tmux_for_every_saved_mode() {
    assert_eq!(
        launch_mode(SshTmuxMode::Required, true).expect("required"),
        SshLaunchMode::Tmux
    );
    assert_eq!(
        launch_mode(SshTmuxMode::Preferred, true).expect("preferred"),
        SshLaunchMode::Tmux
    );
    assert!(launch_mode(SshTmuxMode::Disabled, true).is_err());
}

#[test]
fn legacy_execution_preserves_the_existing_mode_matrix() {
    assert_eq!(
        launch_mode(SshTmuxMode::Required, false).expect("required"),
        SshLaunchMode::Tmux
    );
    assert_eq!(
        launch_mode(SshTmuxMode::Preferred, false).expect("preferred"),
        SshLaunchMode::PreferredWithLegacyFallback
    );
    assert_eq!(
        launch_mode(SshTmuxMode::Disabled, false).expect("disabled"),
        SshLaunchMode::Direct
    );
}

#[test]
fn backend_rechecks_identity_after_any_client_preflight() {
    let saved_mode = SshTmuxMode::Preferred;
    assert_eq!(
        launch_mode(saved_mode, false).expect("legacy preflight"),
        SshLaunchMode::PreferredWithLegacyFallback
    );
    assert_eq!(
        launch_mode(saved_mode, true).expect("backend durable check"),
        SshLaunchMode::Tmux
    );
}

#[tokio::test]
async fn backend_launch_counters_enforce_durable_tmux_without_direct_fallback() {
    let (preferred, preferred_tmux, preferred_direct) =
        backend_with_counted_launchers(SshTmuxMode::Preferred);
    let Err(preferred_error) = preferred.start(test_exec_params(true)).await else {
        panic!("unavailable tmux must fail durable launch");
    };
    assert!(preferred_error.to_string().contains("tmux_required"));
    assert_eq!(
        (
            preferred_tmux.load(Ordering::SeqCst),
            preferred_direct.load(Ordering::SeqCst),
        ),
        (1, 0)
    );

    let (disabled, disabled_tmux, disabled_direct) =
        backend_with_counted_launchers(SshTmuxMode::Disabled);
    let Err(disabled_error) = disabled.start(test_exec_params(true)).await else {
        panic!("disabled tmux must reject durable launch");
    };
    assert!(disabled_error.to_string().contains("requires tmux"));
    assert_eq!(
        (
            disabled_tmux.load(Ordering::SeqCst),
            disabled_direct.load(Ordering::SeqCst),
        ),
        (0, 0)
    );

    let (legacy, legacy_tmux, legacy_direct) =
        backend_with_counted_launchers(SshTmuxMode::Preferred);
    let Err(legacy_error) = legacy.start(test_exec_params(false)).await else {
        panic!("legacy fallback reaches direct test launcher");
    };
    assert!(legacy_error.to_string().contains("direct test launcher"));
    assert_eq!(
        (
            legacy_tmux.load(Ordering::SeqCst),
            legacy_direct.load(Ordering::SeqCst),
        ),
        (1, 1)
    );
}

#[tokio::test]
async fn terminate_waits_for_remote_acknowledgement() {
    let (process, mut commands) = process_with_command_pump();
    let termination =
        tokio::spawn(async move { ExecProcessImpl::terminate(process.as_ref()).await });

    let Some(ChannelCommand::Terminate { ack }) = commands.recv().await else {
        panic!("expected acknowledged termination");
    };
    assert!(!termination.is_finished());
    ack.send(Ok(())).expect("deliver acknowledgement");

    termination
        .await
        .expect("termination task")
        .expect("acknowledged termination");
}

#[tokio::test]
async fn terminate_propagates_remote_failure() {
    let (process, mut commands) = process_with_command_pump();
    let termination =
        tokio::spawn(async move { ExecProcessImpl::terminate(process.as_ref()).await });

    let Some(ChannelCommand::Terminate { ack }) = commands.recv().await else {
        panic!("expected acknowledged termination");
    };
    ack.send(Err("remote kill failed".to_string()))
        .expect("deliver failure");

    let error = termination
        .await
        .expect("termination task")
        .expect_err("termination must fail");
    assert!(error.to_string().contains("remote kill failed"));
}
