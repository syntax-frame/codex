use super::process::UnifiedExecProcess;
use crate::unified_exec::UnifiedExecError;
use codex_exec_server::ExecProcess;
use codex_exec_server::ExecProcessEventReceiver;
use codex_exec_server::ExecProcessFuture;
use codex_exec_server::ExecServerError;
use codex_exec_server::ProcessId;
use codex_exec_server::ProcessSignal;
use codex_exec_server::ProcessSignalOutcome;
use codex_exec_server::ReadResponse;
use codex_exec_server::StartedExecProcess;
use codex_exec_server::WriteResponse;
use codex_exec_server::WriteStatus;
use pretty_assertions::assert_eq;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::watch;

struct MockExecProcess {
    process_id: ProcessId,
    write_response: WriteResponse,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
    read_responses: Mutex<VecDeque<ReadResponse>>,
    terminate_error: Option<String>,
    terminate_count: Arc<AtomicUsize>,
    terminate_started: Option<Arc<Notify>>,
    allow_terminate: Option<Arc<Notify>>,
    wake_tx: watch::Sender<u64>,
}

impl MockExecProcess {
    async fn read(&self) -> Result<ReadResponse, ExecServerError> {
        Ok(self
            .read_responses
            .lock()
            .await
            .pop_front()
            .unwrap_or(ReadResponse {
                chunks: Vec::new(),
                next_seq: 1,
                exited: false,
                exit_code: None,
                closed: false,
                failure: None,
                sandbox_denied: false,
            }))
    }

    async fn terminate(&self) -> Result<(), ExecServerError> {
        self.terminate_count.fetch_add(1, Ordering::SeqCst);
        if let Some(terminate_started) = &self.terminate_started {
            terminate_started.notify_one();
        }
        if let Some(allow_terminate) = &self.allow_terminate {
            allow_terminate.notified().await;
        }
        if let Some(message) = &self.terminate_error {
            return Err(ExecServerError::Protocol(message.clone()));
        }
        Ok(())
    }
}

impl ExecProcess for MockExecProcess {
    fn process_id(&self) -> &ProcessId {
        &self.process_id
    }

    fn subscribe_wake(&self) -> watch::Receiver<u64> {
        self.wake_tx.subscribe()
    }

    fn subscribe_events(&self) -> ExecProcessEventReceiver {
        ExecProcessEventReceiver::empty()
    }

    fn read(
        &self,
        _after_seq: Option<u64>,
        _max_bytes: Option<usize>,
        _wait_ms: Option<u64>,
    ) -> ExecProcessFuture<'_, ReadResponse> {
        Box::pin(MockExecProcess::read(self))
    }

    fn write(&self, chunk: Vec<u8>) -> ExecProcessFuture<'_, WriteResponse> {
        Box::pin(async move {
            self.writes.lock().await.push(chunk);
            Ok(self.write_response.clone())
        })
    }

    fn signal(&self, _signal: ProcessSignal) -> ExecProcessFuture<'_, ProcessSignalOutcome> {
        Box::pin(async { Ok(ProcessSignalOutcome::Accepted) })
    }

    fn terminate(&self) -> ExecProcessFuture<'_, ()> {
        Box::pin(MockExecProcess::terminate(self))
    }
}

pub(super) async fn remote_process(
    write_status: WriteStatus,
    terminate_error: Option<String>,
) -> UnifiedExecProcess {
    remote_process_with_drop_policy(write_status, terminate_error, false)
        .await
        .0
}

pub(crate) async fn remote_process_with_drop_policy(
    write_status: WriteStatus,
    terminate_error: Option<String>,
    detach_on_drop: bool,
) -> (UnifiedExecProcess, Arc<AtomicUsize>) {
    let (process, terminate_count, _writes) =
        remote_process_with_write_log(write_status, terminate_error, detach_on_drop).await;
    (process, terminate_count)
}

pub(crate) async fn remote_process_with_write_log(
    write_status: WriteStatus,
    terminate_error: Option<String>,
    detach_on_drop: bool,
) -> (
    UnifiedExecProcess,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let (wake_tx, _wake_rx) = watch::channel(0);
    let terminate_count = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(Mutex::new(Vec::new()));
    let started = StartedExecProcess {
        process: Arc::new(MockExecProcess {
            process_id: "test-process".to_string().into(),
            write_response: WriteResponse {
                status: write_status,
            },
            writes: Arc::clone(&writes),
            read_responses: Mutex::new(VecDeque::new()),
            terminate_error,
            terminate_count: Arc::clone(&terminate_count),
            terminate_started: None,
            allow_terminate: None,
            wake_tx,
        }),
    };

    let process = UnifiedExecProcess::from_exec_server_started(started, detach_on_drop)
        .await
        .expect("remote process should start");
    (process, terminate_count, writes)
}

#[tokio::test]
async fn durable_remote_process_detaches_without_termination_on_drop() {
    let (process, terminate_count) =
        remote_process_with_drop_policy(WriteStatus::Accepted, None, true).await;

    drop(process);
    tokio::task::yield_now().await;

    assert_eq!(terminate_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_termination_still_terminates_durable_remote_process() {
    let (process, terminate_count) =
        remote_process_with_drop_policy(WriteStatus::Accepted, None, true).await;

    process
        .terminate_confirmed()
        .await
        .expect("explicit termination");

    assert_eq!(terminate_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_confirmed_termination_shares_the_same_failure() {
    let (wake_tx, _wake_rx) = watch::channel(0);
    let terminate_count = Arc::new(AtomicUsize::new(0));
    let terminate_started = Arc::new(Notify::new());
    let allow_terminate = Arc::new(Notify::new());
    let process = Arc::new(
        UnifiedExecProcess::from_exec_server_started(
            StartedExecProcess {
                process: Arc::new(MockExecProcess {
                    process_id: "concurrent-terminate".to_string().into(),
                    write_response: WriteResponse {
                        status: WriteStatus::Accepted,
                    },
                    writes: Arc::new(Mutex::new(Vec::new())),
                    read_responses: Mutex::new(VecDeque::new()),
                    terminate_error: Some("terminate unavailable".to_string()),
                    terminate_count: Arc::clone(&terminate_count),
                    terminate_started: Some(Arc::clone(&terminate_started)),
                    allow_terminate: Some(Arc::clone(&allow_terminate)),
                    wake_tx,
                }),
            },
            false,
        )
        .await
        .expect("remote process should start"),
    );

    let first_process = Arc::clone(&process);
    let first = tokio::spawn(async move { first_process.terminate_confirmed().await });
    terminate_started.notified().await;
    let second_process = Arc::clone(&process);
    let second = tokio::spawn(async move { second_process.terminate_confirmed().await });
    tokio::task::yield_now().await;
    allow_terminate.notify_one();

    let first_error = first.await.expect("first task").expect_err("first failure");
    let second_error = second
        .await
        .expect("second task")
        .expect_err("second failure");
    assert_eq!(first_error.to_string(), second_error.to_string());
    assert_eq!(terminate_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fire_and_forget_and_confirmed_termination_share_completion() {
    let (wake_tx, _wake_rx) = watch::channel(0);
    let terminate_count = Arc::new(AtomicUsize::new(0));
    let terminate_started = Arc::new(Notify::new());
    let allow_terminate = Arc::new(Notify::new());
    let process = UnifiedExecProcess::from_exec_server_started(
        StartedExecProcess {
            process: Arc::new(MockExecProcess {
                process_id: "mixed-terminate".to_string().into(),
                write_response: WriteResponse {
                    status: WriteStatus::Accepted,
                },
                writes: Arc::new(Mutex::new(Vec::new())),
                read_responses: Mutex::new(VecDeque::new()),
                terminate_error: Some("terminate unavailable".to_string()),
                terminate_count: Arc::clone(&terminate_count),
                terminate_started: Some(Arc::clone(&terminate_started)),
                allow_terminate: Some(Arc::clone(&allow_terminate)),
                wake_tx,
            }),
        },
        false,
    )
    .await
    .expect("remote process should start");

    process.terminate();
    terminate_started.notified().await;
    let confirmed = process.terminate_confirmed();
    allow_terminate.notify_one();
    confirmed
        .await
        .expect_err("confirmed caller must observe fire-and-forget failure");
    assert_eq!(terminate_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn remote_write_unknown_process_marks_process_exited() {
    let process = remote_process(WriteStatus::UnknownProcess, /*terminate_error*/ None).await;

    let err = process
        .write(b"hello", None)
        .await
        .expect_err("expected write failure");

    assert!(matches!(err, UnifiedExecError::WriteToStdin));
    assert!(process.has_exited());
}

#[tokio::test]
async fn remote_write_closed_stdin_marks_process_exited() {
    let process = remote_process(WriteStatus::StdinClosed, /*terminate_error*/ None).await;

    let err = process
        .write(b"hello", None)
        .await
        .expect_err("expected write failure");

    assert!(matches!(err, UnifiedExecError::WriteToStdin));
    assert!(process.has_exited());
}

#[tokio::test]
async fn fail_and_terminate_preserves_failure_message() {
    let process = remote_process(WriteStatus::Accepted, /*terminate_error*/ None).await;

    process.fail_and_terminate("network denied".to_string());
    process.fail_and_terminate("second failure".to_string());

    assert!(process.has_exited());
    assert_eq!(
        process.failure_message(),
        Some("network denied".to_string())
    );
}

#[tokio::test]
async fn remote_terminate_confirmed_updates_state_on_success_only() {
    let process = remote_process(
        WriteStatus::Accepted,
        Some("terminate unavailable".to_string()),
    )
    .await;

    let err = process
        .terminate_confirmed()
        .await
        .expect_err("expected terminate failure");

    assert!(matches!(err, UnifiedExecError::ProcessFailed { .. }));
    assert!(!process.has_exited());

    let process = remote_process(WriteStatus::Accepted, /*terminate_error*/ None).await;

    process
        .terminate_confirmed()
        .await
        .expect("terminate should succeed");

    assert!(process.has_exited());
}
