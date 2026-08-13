use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use sha2::Digest;
use sha2::Sha256;
use tokio::sync::broadcast;
use tokio::sync::watch;

use crate::ExecServerError;
use crate::ProcessId;
use crate::protocol::ByteChunk;
use crate::protocol::ExecOutputStream;
use crate::protocol::ExecParams;
use crate::protocol::ExecutionIdentity;
use crate::protocol::ProcessOutputChunk;
use crate::protocol::ProcessSignal;
use crate::protocol::ProcessSignalOutcome;
use crate::protocol::ReadResponse;
use crate::protocol::WriteResponse;
use crate::protocol::WriteStatus;

pub struct StartedExecProcess {
    pub process: Arc<dyn ExecProcess>,
}

impl StartedExecProcess {
    /// Reconstructs an already-terminal durable execution as a read-only
    /// process handle. The retained suffix starts at the latest locally
    /// committed cursor, so the next model poll receives each byte once while
    /// terminal proof and acknowledgement remain remote-authoritative.
    pub fn from_recovered_terminal(
        process_id: i32,
        output: &[u8],
        committed_output_cursor: u64,
        exit_code: i32,
        tty: bool,
    ) -> Result<Self, ExecServerError> {
        let output_len = u64::try_from(output.len()).map_err(|_| {
            ExecServerError::Protocol("recovered terminal output length is unsupported".to_string())
        })?;
        if committed_output_cursor > output_len {
            return Err(ExecServerError::Protocol(
                "recovered terminal cursor exceeds output".to_string(),
            ));
        }
        let start = usize::try_from(committed_output_cursor).map_err(|_| {
            ExecServerError::Protocol("recovered terminal cursor is unsupported".to_string())
        })?;
        let process = RecoveredTerminalExecProcess::new(
            ProcessId::new(process_id.to_string()),
            output[start..].to_vec(),
            committed_output_cursor,
            output_len,
            exit_code,
            if tty {
                ExecOutputStream::Pty
            } else {
                ExecOutputStream::Stdout
            },
        );
        Ok(Self {
            process: Arc::new(process),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreparedExecution {
    params: ExecParams,
    command_digest: String,
}

impl PreparedExecution {
    pub fn new(params: ExecParams) -> Self {
        let command_digest = canonical_command_digest(&params);
        Self {
            params,
            command_digest,
        }
    }

    pub fn params(&self) -> &ExecParams {
        &self.params
    }

    pub fn command_digest(&self) -> &str {
        &self.command_digest
    }

    pub fn original_session_id(&self) -> Option<i32> {
        self.params.process_id.as_str().parse().ok()
    }

    pub fn tty(&self) -> bool {
        self.params.tty
    }

    pub fn into_params(self) -> ExecParams {
        self.params
    }

    pub(crate) fn into_parts(self) -> (ExecParams, String) {
        (self.params, self.command_digest)
    }
}

pub fn canonical_command_digest(params: &ExecParams) -> String {
    fn write_value(output: &mut String, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                output.push('{');
                let mut fields = map.iter().collect::<Vec<_>>();
                fields.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                for (index, (key, value)) in fields.into_iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    output.push_str(
                        &serde_json::to_string(key).expect("JSON object key is serializable"),
                    );
                    output.push(':');
                    write_value(output, value);
                }
                output.push('}');
            }
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_value(output, value);
                }
                output.push(']');
            }
            scalar => output
                .push_str(&serde_json::to_string(scalar).expect("JSON scalar is serializable")),
        }
    }

    let value = serde_json::to_value(params).expect("ExecParams is JSON serializable");
    let mut canonical = String::from("agentapp-tmux-command-v2:");
    write_value(&mut canonical, &value);
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionRequest {
    pub identity: ExecutionIdentity,
    pub expected_command_digest: String,
    pub original_session_id: Option<i32>,
    pub committed_output_cursor: u64,
    pub tty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveredExecutionStatus {
    Missing,
    Prepared,
    LaunchInterrupted,
    Running,
    Exited(i32),
    Terminated,
    /// Exact ownership and death were proven, but no trustworthy natural
    /// exit or delivered-signal status survived on the remote host.
    RecoveryLost,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteExecution {
    pub turn_id: String,
    pub call_id: String,
    pub attempt_generation: u32,
    /// Locally durable launch authority. This must never be populated from the
    /// remote descriptor being reconciled.
    pub expected_command_digest: Option<String>,
    pub expected_session_id: Option<i32>,
    pub expected_tty: Option<bool>,
    pub protocol_evidence: RemoteExecutionProtocolEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteExecutionProtocolEvidence {
    V2Proven,
    LegacyUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWriteInteraction {
    pub call_id: String,
    pub turn_id: String,
    pub session_id: i32,
    pub input_is_empty: bool,
    /// True only for a build-121+ turn whose protocol marker guarantees that
    /// remote nonempty stdin cannot precede its durable write intent.
    pub pre_send_intent_required: bool,
    /// True only after the exact persisted intent has been validated against
    /// the function call and committed background execution.
    pub pre_send_intent_persisted: bool,
    pub protocol_evidence: RemoteExecutionProtocolEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryIntent {
    Foreground,
    BackgroundPoll {
        session_id: i32,
        committed_output_cursor: u64,
    },
    AmbiguousNonemptyStdin {
        session_id: i32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationRequest {
    pub thread_id: String,
    pub incomplete_executions: Vec<IncompleteExecution>,
    pub pending_writes: Vec<PendingWriteInteraction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalAcknowledgementProof {
    pub range_start: u64,
    pub range_end: u64,
    pub output_sha256: String,
    pub status: RecoveredExecutionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredExecutionAcknowledgement {
    token: String,
    terminal_proof: Option<TerminalAcknowledgementProof>,
}

impl RecoveredExecutionAcknowledgement {
    /// Reconstructs a backend-issued token for durable transport or test doubles.
    ///
    /// Backends still validate the token against their owned completed descriptor.
    pub fn new(value: String) -> Self {
        Self {
            token: value,
            terminal_proof: None,
        }
    }

    pub fn with_terminal_proof(mut self, terminal_proof: TerminalAcknowledgementProof) -> Self {
        self.terminal_proof = Some(terminal_proof);
        self
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.token
    }

    /// Returns the opaque backend token that must be persisted before the
    /// recovered descriptor can be acknowledged and retired.
    pub fn persistence_token(&self) -> &str {
        &self.token
    }

    pub fn terminal_proof(&self) -> Option<&TerminalAcknowledgementProof> {
        self.terminal_proof.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredExecution {
    pub identity: ExecutionIdentity,
    pub command_digest: Option<String>,
    pub output: Vec<u8>,
    pub status: RecoveredExecutionStatus,
    pub terminal_verified_dead: bool,
    pub session_id: Option<i32>,
    pub committed_output_cursor: u64,
    pub delivery_unknown: bool,
    pub acknowledgement: RecoveredExecutionAcknowledgement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationSelection {
    NotLaunched,
    Selected(u32),
    NeedsTerminalVerification(u32),
}

pub fn select_execution_generation(
    generation_zero: &RecoveredExecution,
    generation_one: &RecoveredExecution,
) -> Result<GenerationSelection, String> {
    use RecoveredExecutionStatus::*;
    match (&generation_zero.status, &generation_one.status) {
        (Missing, Missing) => Ok(GenerationSelection::NotLaunched),
        (Missing, _) => Err("generation one exists while generation zero is missing".to_string()),
        (Prepared | Running, Missing) => Ok(GenerationSelection::Selected(0)),
        (Prepared | Running, _) => {
            Err("generation zero is live while generation one exists".to_string())
        }
        (Exited(_) | Terminated | RecoveryLost | LaunchInterrupted, Missing)
            if generation_zero.terminal_verified_dead =>
        {
            Ok(GenerationSelection::Selected(0))
        }
        (Exited(_) | Terminated | RecoveryLost | LaunchInterrupted, Missing) => {
            Ok(GenerationSelection::NeedsTerminalVerification(0))
        }
        (Exited(_) | Terminated | RecoveryLost | LaunchInterrupted, _)
            if !generation_zero.terminal_verified_dead =>
        {
            Ok(GenerationSelection::NeedsTerminalVerification(0))
        }
        (
            Exited(_) | Terminated | RecoveryLost | LaunchInterrupted,
            Exited(_) | Terminated | RecoveryLost | LaunchInterrupted,
        ) if !generation_one.terminal_verified_dead => {
            Ok(GenerationSelection::NeedsTerminalVerification(1))
        }
        (
            Exited(_) | Terminated | RecoveryLost | LaunchInterrupted,
            Prepared | Running | Exited(_) | Terminated | RecoveryLost | LaunchInterrupted,
        ) if generation_one.terminal_verified_dead
            || matches!(generation_one.status, Prepared | Running) =>
        {
            Ok(GenerationSelection::Selected(1))
        }
        _ => Err("descriptor generations are conflicting or unknown".to_string()),
    }
}

/// Pushed process events for consumers that want to follow process output as it
/// arrives instead of polling retained output with [`ExecProcess::read`].
///
/// The stream is scoped to one [`ExecProcess`] handle. `Output` events carry
/// stdout, stderr, or pty bytes. `Exited` reports the process exit status, while
/// `Closed` means all output streams have ended and no more output events will
/// arrive. `Failed` is used when the process session cannot continue, for
/// example because the remote environment connection disconnected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecProcessEvent {
    Output(ProcessOutputChunk),
    Exited {
        seq: u64,
        exit_code: i32,
        sandbox_denied: Option<bool>,
    },
    Closed {
        seq: u64,
    },
    Failed(String),
}

/// Replay buffer plus live fan-out for pushed process events.
///
/// New subscribers first drain a bounded replay history, then continue on the
/// live broadcast channel. The history is bounded by event count and retained
/// output bytes: count protects against many tiny events, while bytes protects
/// against a few very large output chunks.
#[derive(Clone)]
pub(crate) struct ExecProcessEventLog {
    inner: Arc<ExecProcessEventLogInner>,
}

struct ExecProcessEventLogInner {
    history: StdMutex<ExecProcessEventHistory>,
    live_tx: broadcast::Sender<ExecProcessEvent>,
    event_capacity: usize,
    byte_capacity: usize,
}

#[derive(Default)]
struct ExecProcessEventHistory {
    events: VecDeque<ExecProcessEvent>,
    retained_bytes: usize,
}

impl ExecProcessEvent {
    /// Sequence number used to order process-owned events.
    ///
    /// `Failed` is intentionally unsequenced because it is synthesized by the
    /// client when the session or transport fails, not emitted by the process.
    pub(crate) fn seq(&self) -> Option<u64> {
        match self {
            ExecProcessEvent::Output(chunk) => Some(chunk.seq),
            ExecProcessEvent::Exited { seq, .. } | ExecProcessEvent::Closed { seq } => Some(*seq),
            ExecProcessEvent::Failed(_) => None,
        }
    }

    fn retained_len(&self) -> usize {
        match self {
            ExecProcessEvent::Output(chunk) => chunk.chunk.0.len(),
            ExecProcessEvent::Failed(message) => message.len(),
            ExecProcessEvent::Exited { .. } | ExecProcessEvent::Closed { .. } => 0,
        }
    }
}

impl ExecProcessEventLog {
    pub(crate) fn new(event_capacity: usize, byte_capacity: usize) -> Self {
        let (live_tx, _live_rx) = broadcast::channel(event_capacity);
        Self {
            inner: Arc::new(ExecProcessEventLogInner {
                history: StdMutex::new(ExecProcessEventHistory::default()),
                live_tx,
                event_capacity,
                byte_capacity,
            }),
        }
    }

    pub(crate) fn publish(&self, event: ExecProcessEvent) {
        let mut history = self
            .inner
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        history.retained_bytes += event.retained_len();
        history.events.push_back(event.clone());
        while history.events.len() > self.inner.event_capacity
            || history.retained_bytes > self.inner.byte_capacity
        {
            let Some(evicted) = history.events.pop_front() else {
                break;
            };
            history.retained_bytes = history
                .retained_bytes
                .saturating_sub(evicted.retained_len());
        }

        let _ = self.inner.live_tx.send(event);
    }

    pub(crate) fn subscribe(&self) -> ExecProcessEventReceiver {
        let history = self
            .inner
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let live_rx = self.inner.live_tx.subscribe();
        let replay = history.events.iter().cloned().collect();

        ExecProcessEventReceiver {
            replay,
            live_rx,
            _keepalive: None,
        }
    }
}

pub struct ExecProcessEventReceiver {
    replay: VecDeque<ExecProcessEvent>,
    live_rx: broadcast::Receiver<ExecProcessEvent>,
    _keepalive: Option<broadcast::Sender<ExecProcessEvent>>,
}

impl ExecProcessEventReceiver {
    /// Returns a receiver that remains open without yielding events.
    pub fn empty() -> Self {
        let (live_tx, live_rx) = broadcast::channel(1);
        Self {
            replay: VecDeque::new(),
            live_rx,
            _keepalive: Some(live_tx),
        }
    }

    /// Returns the next replayed or live event.
    ///
    /// `Lagged` means this receiver fell behind the bounded live channel. The
    /// caller should recover through [`ExecProcess::read`] using the last
    /// delivered sequence number, then continue receiving pushed events.
    pub async fn recv(&mut self) -> Result<ExecProcessEvent, broadcast::error::RecvError> {
        if let Some(event) = self.replay.pop_front() {
            return Ok(event);
        }

        self.live_rx.recv().await
    }
}

struct RecoveredTerminalExecProcess {
    process_id: ProcessId,
    events: ExecProcessEventLog,
    wake_tx: watch::Sender<u64>,
    output: Option<ProcessOutputChunk>,
    next_seq: u64,
    exit_code: i32,
}

impl RecoveredTerminalExecProcess {
    fn new(
        process_id: ProcessId,
        suffix: Vec<u8>,
        absolute_start: u64,
        absolute_end: u64,
        exit_code: i32,
        stream: ExecOutputStream,
    ) -> Self {
        let events = ExecProcessEventLog::new(3, suffix.len().max(1));
        let mut next_seq = 0;
        let output = if suffix.is_empty() {
            None
        } else {
            next_seq += 1;
            let output = ProcessOutputChunk {
                seq: next_seq,
                stream,
                chunk: ByteChunk(suffix),
                absolute_start: Some(absolute_start),
                absolute_end: Some(absolute_end),
            };
            events.publish(ExecProcessEvent::Output(output.clone()));
            Some(output)
        };
        next_seq += 1;
        events.publish(ExecProcessEvent::Exited {
            seq: next_seq,
            exit_code,
            sandbox_denied: Some(false),
        });
        next_seq += 1;
        events.publish(ExecProcessEvent::Closed { seq: next_seq });
        let (wake_tx, _wake_rx) = watch::channel(next_seq);
        Self {
            process_id,
            events,
            wake_tx,
            output,
            next_seq,
            exit_code,
        }
    }
}

impl ExecProcess for RecoveredTerminalExecProcess {
    fn process_id(&self) -> &ProcessId {
        &self.process_id
    }

    fn subscribe_wake(&self) -> watch::Receiver<u64> {
        self.wake_tx.subscribe()
    }

    fn subscribe_events(&self) -> ExecProcessEventReceiver {
        self.events.subscribe()
    }

    fn read(
        &self,
        after_seq: Option<u64>,
        _max_bytes: Option<usize>,
        _wait_ms: Option<u64>,
    ) -> ExecProcessFuture<'_, ReadResponse> {
        let after_seq = after_seq.unwrap_or(0);
        let chunks = self
            .output
            .iter()
            .filter(|chunk| chunk.seq > after_seq)
            .cloned()
            .collect();
        Box::pin(std::future::ready(Ok(ReadResponse {
            chunks,
            next_seq: self.next_seq,
            exited: true,
            exit_code: Some(self.exit_code),
            closed: true,
            failure: None,
            sandbox_denied: false,
        })))
    }

    fn write(&self, _chunk: Vec<u8>) -> ExecProcessFuture<'_, WriteResponse> {
        Box::pin(std::future::ready(Ok(WriteResponse {
            status: WriteStatus::StdinClosed,
        })))
    }

    fn signal(&self, _signal: ProcessSignal) -> ExecProcessFuture<'_, ProcessSignalOutcome> {
        Box::pin(std::future::ready(Ok(ProcessSignalOutcome::Accepted)))
    }

    fn terminate(&self) -> ExecProcessFuture<'_, ()> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Handle for an executor-managed process.
///
/// Implementations must support both retained-output reads and pushed events:
/// `read` is the request/response API for callers that want to page through
/// buffered output, while `subscribe_events` is the streaming API for callers
/// that want output and lifecycle changes delivered as they happen.
pub trait ExecProcess: Send + Sync {
    fn process_id(&self) -> &ProcessId;

    fn subscribe_wake(&self) -> watch::Receiver<u64>;

    fn subscribe_events(&self) -> ExecProcessEventReceiver;

    fn read(
        &self,
        after_seq: Option<u64>,
        max_bytes: Option<usize>,
        wait_ms: Option<u64>,
    ) -> ExecProcessFuture<'_, ReadResponse>;

    fn write(&self, chunk: Vec<u8>) -> ExecProcessFuture<'_, WriteResponse>;

    /// Writes stdin with a caller-stable idempotency key when the caller has
    /// durable side-effect authority. Backends without persistent execution
    /// state may use the default write path.
    fn write_with_id(
        &self,
        chunk: Vec<u8>,
        _write_id: String,
    ) -> ExecProcessFuture<'_, WriteResponse> {
        self.write(chunk)
    }

    fn signal(&self, signal: ProcessSignal) -> ExecProcessFuture<'_, ProcessSignalOutcome>;

    fn terminate(&self) -> ExecProcessFuture<'_, ()>;
}

pub type ExecProcessFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ExecServerError>> + Send + 'a>>;

pub trait ExecBackend: Send + Sync {
    fn start(&self, params: ExecParams) -> ExecBackendFuture<'_>;

    fn start_prepared(&self, prepared: PreparedExecution) -> ExecBackendFuture<'_> {
        self.start(prepared.into_params())
    }

    fn adopt_execution(&self, _request: AdoptionRequest) -> ExecBackendFuture<'_> {
        Box::pin(std::future::ready(Err(ExecServerError::Protocol(
            "execution adoption is unsupported by this backend".to_string(),
        ))))
    }

    /// Reconciles durable executor-side state before a resumed turn can issue tools.
    ///
    /// Backends without persistent process state may keep the default no-op.
    fn reconcile(&self, _request: ReconciliationRequest) -> ExecBackendReconcileFuture<'_> {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }

    fn acknowledge_consumed(
        &self,
        _acknowledgement: RecoveredExecutionAcknowledgement,
    ) -> ExecBackendAcknowledgeFuture<'_> {
        Box::pin(std::future::ready(Ok(())))
    }

    /// Deletes only the exact proof-bound acknowledgement tombstone after the
    /// caller has made its local acknowledgement marker durable.
    fn release_acknowledged(
        &self,
        _acknowledgement: RecoveredExecutionAcknowledgement,
    ) -> ExecBackendAcknowledgeFuture<'_> {
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(test)]
mod recovered_terminal_tests {
    use super::*;

    #[tokio::test]
    async fn recovered_terminal_replays_only_uncommitted_suffix_then_exit() {
        let started = StartedExecProcess::from_recovered_terminal(
            41,
            b"alreadynew",
            7,
            17,
            /*tty*/ false,
        )
        .expect("recovered terminal process");
        let response = started
            .process
            .read(None, None, None)
            .await
            .expect("read recovered terminal");

        assert_eq!(response.chunks.len(), 1);
        assert_eq!(response.chunks[0].chunk.0, b"new");
        assert_eq!(response.chunks[0].absolute_start, Some(7));
        assert_eq!(response.chunks[0].absolute_end, Some(10));
        assert!(response.exited);
        assert_eq!(response.exit_code, Some(17));
        assert!(response.closed);
        assert_eq!(
            started
                .process
                .write(b"ignored".to_vec())
                .await
                .expect("closed stdin")
                .status,
            WriteStatus::StdinClosed
        );
    }

    #[test]
    fn recovered_terminal_rejects_cursor_beyond_output() {
        assert!(
            StartedExecProcess::from_recovered_terminal(41, b"short", 6, 0, /*tty*/ true,).is_err()
        );
    }
}

pub type ExecBackendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<StartedExecProcess, ExecServerError>> + Send + 'a>>;
pub type ExecBackendReconcileFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<RecoveredExecution>, ExecServerError>> + Send + 'a>>;
pub type ExecBackendAcknowledgeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ExecServerError>> + Send + 'a>>;

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use tokio::time::Duration;
    use tokio::time::timeout;

    use super::ExecProcessEvent;
    use super::ExecProcessEventLog;
    use super::ExecProcessEventReceiver;
    use crate::protocol::ExecOutputStream;
    use crate::protocol::ProcessOutputChunk;

    #[tokio::test]
    async fn empty_event_receiver_stays_open() {
        let mut events = ExecProcessEventReceiver::empty();

        assert!(
            timeout(Duration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn event_history_replay_is_bounded_by_retained_bytes() {
        let log = ExecProcessEventLog::new(/*event_capacity*/ 8, /*byte_capacity*/ 3);

        log.publish(ExecProcessEvent::Output(ProcessOutputChunk {
            seq: 1,
            stream: ExecOutputStream::Stdout,
            chunk: b"large".to_vec().into(),
            absolute_start: None,
            absolute_end: None,
        }));
        log.publish(ExecProcessEvent::Exited {
            seq: 2,
            exit_code: 0,
            sandbox_denied: Some(false),
        });
        log.publish(ExecProcessEvent::Closed { seq: 3 });

        let mut events = log.subscribe();
        let replay = vec![
            timeout(Duration::from_secs(1), events.recv())
                .await
                .expect("exit event replay should not time out")
                .expect("exit event replay should be available"),
            timeout(Duration::from_secs(1), events.recv())
                .await
                .expect("closed event replay should not time out")
                .expect("closed event replay should be available"),
        ];

        assert_eq!(
            replay,
            vec![
                ExecProcessEvent::Exited {
                    seq: 2,
                    exit_code: 0,
                    sandbox_denied: Some(false),
                },
                ExecProcessEvent::Closed { seq: 3 },
            ]
        );
    }
}
