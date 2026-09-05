//! SSH-backed [`ExecBackend`] for the Codex agent loop.
//!
//! This runs Codex's shell tools on a remote host over SSH instead of locally.
//! It mirrors the interface that [`crate::local_process::LocalProcess`] exposes
//! ([`ExecProcess`] + [`ExecBackend`]), but the process I/O flows over a russh
//! channel rather than an OS child + PTY. The remote sshd provides the PTY, so
//! none of the local OS-PTY / sandbox machinery is reused here.
//!
//! Lifecycle:
//! - Physical transports are pooled per saved connection profile.
//! - In tmux mode, each agent has a logical session and each process has a
//!   window whose output and exit status survive transport reconnects.
//! - In direct mode, a background task owns the pooled russh channel, drains
//!   output into [`ExecProcessEventLog`], and serializes stdin/signal/terminate
//!   operations over an mpsc command channel.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use russh::ChannelMsg;
use russh::Sig;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;

use crate::ExecBackend;
use crate::ExecBackendFuture;
use crate::ExecProcess;
use crate::ExecProcessEvent;
use crate::ExecProcessEventReceiver;
use crate::ExecProcessFuture;
use crate::ExecServerError;
use crate::ProcessId;
use crate::StartedExecProcess;
use crate::process::ExecBackendReconcileFuture;
use crate::process::ExecProcessEventLog;
use crate::protocol::ExecOutputStream;
use crate::protocol::ExecParams;
use crate::protocol::ProcessOutputChunk;
use crate::protocol::ProcessSignal;
use crate::protocol::ProcessSignalOutcome;
use crate::protocol::ReadResponse;
use crate::protocol::WriteResponse;
use crate::protocol::WriteStatus;
use crate::ssh_transport::PooledSshChannel;
use crate::ssh_transport::SshAuthentication;
use crate::ssh_transport::SshTransport;
use crate::ssh_transport::classified_protocol_error;
use crate::ssh_transport::is_reconnectable_ssh_error;

#[path = "ssh_tmux.rs"]
mod tmux;

const RETAINED_OUTPUT_BYTES_PER_PROCESS: usize = 1024 * 1024;
const PROCESS_EVENT_CHANNEL_CAPACITY: usize = 256;
const SSH_START_ATTEMPTS: usize = 2;
// Include queue backpressure and monitor reconnection, while allowing a
// 90-second control command and its bounded channel close to finish.
const SSH_WRITE_ACK_TIMEOUT: Duration = Duration::from_secs(95);
const SSH_SIGNAL_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_TERMINATE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_PATH_EXPORT: &str = "export PATH=\"$HOME/bin:$HOME/.local/bin:/opt/homebrew/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}\"";

/// Whether server-mode process execution requires tmux continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshTmuxMode {
    Required,
    Preferred,
    Disabled,
}

/// Connection + auth material for opening SSH sessions.
///
/// Cloneable process backend. Physical SSH transports are pooled per saved
/// connection profile; `session_key` identifies the agent's tmux namespace.
#[derive(Clone)]
pub struct SshProcessBackend {
    transport: SshTransport,
    session_key: String,
    controller_id: String,
    tmux_mode: SshTmuxMode,
}

impl SshProcessBackend {
    /// Construct a backend that authenticates with the OpenSSH private key at
    /// `key_path`. No host-key pinning (any server key is accepted).
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        Self::with_fingerprint(host, port, user, key_path, None)
    }

    /// Like [`SshProcessBackend::new`], but pins the server host key to
    /// `host_fingerprint` when it is `Some`. The fingerprint must be in OpenSSH
    /// `SHA256:<base64nopad>` form (the `SHA256:` prefix is optional). When
    /// `None`, any host key is accepted.
    pub fn with_fingerprint(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        key_path: impl Into<String>,
        host_fingerprint: Option<String>,
    ) -> Self {
        let host = host.into();
        let user = user.into();
        let key_path = key_path.into();
        let session_key = format!("{user}@{host}:{port}:{key_path}");
        Self::with_authentication_and_keys(
            host,
            port,
            user,
            SshAuthentication::PrivateKeyPath(key_path),
            host_fingerprint,
            session_key.clone(),
            session_key,
            SshTmuxMode::Disabled,
        )
    }

    /// Like [`SshProcessBackend::with_fingerprint`], but with an explicit
    /// stable session key. iOS server mode passes a per-agent key here so the
    /// same SSH connection survives across model turns for that agent.
    pub fn with_fingerprint_and_session_key(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        key_path: impl Into<String>,
        host_fingerprint: Option<String>,
        session_key: impl Into<String>,
    ) -> Self {
        let host = host.into();
        let user = user.into();
        let session_key = session_key.into();
        let connection_key = format!("{user}@{host}:{port}");
        Self::with_authentication_and_keys(
            host,
            port,
            user,
            SshAuthentication::PrivateKeyPath(key_path.into()),
            host_fingerprint,
            connection_key,
            session_key,
            SshTmuxMode::Disabled,
        )
    }

    /// Build a backend with independent physical-connection and logical-agent
    /// keys. AgentApp passes the saved profile ID as `connection_key` and the
    /// node conversation ID as `session_key`.
    #[allow(clippy::too_many_arguments)]
    pub fn with_authentication_and_keys(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        authentication: SshAuthentication,
        host_fingerprint: Option<String>,
        connection_key: impl Into<String>,
        session_key: impl Into<String>,
        tmux_mode: SshTmuxMode,
    ) -> Self {
        Self::from_transport(
            SshTransport::new(
                connection_key,
                host,
                port,
                user,
                authentication,
                host_fingerprint,
            ),
            session_key,
            tmux_mode,
        )
    }

    pub(crate) fn from_transport(
        transport: SshTransport,
        session_key: impl Into<String>,
        tmux_mode: SshTmuxMode,
    ) -> Self {
        Self::from_transport_with_controller(
            transport,
            session_key,
            uuid::Uuid::new_v4().simple().to_string(),
            tmux_mode,
        )
    }

    pub(crate) fn from_transport_with_controller(
        transport: SshTransport,
        session_key: impl Into<String>,
        controller_id: impl Into<String>,
        tmux_mode: SshTmuxMode,
    ) -> Self {
        Self {
            transport,
            session_key: session_key.into(),
            // Ordering is established under the remote lifecycle lock. The
            // client contributes only a collision-resistant ownership token;
            // wall-clock ordering is deliberately not part of fencing.
            controller_id: controller_id.into(),
            tmux_mode,
        }
    }

    async fn start(&self, params: ExecParams) -> Result<StartedExecProcess, ExecServerError> {
        match self.tmux_mode {
            SshTmuxMode::Required => tmux::start(self.clone(), params).await,
            SshTmuxMode::Preferred => match tmux::start(self.clone(), params.clone()).await {
                Ok(process) => Ok(process),
                Err(error) if tmux::is_unavailable(&error) => {
                    tracing::warn!(
                        session_key = %self.session_key,
                        "tmux unavailable; falling back to direct ssh execution"
                    );
                    self.start_direct(params).await
                }
                Err(error) => Err(error),
            },
            SshTmuxMode::Disabled => self.start_direct(params).await,
        }
    }

    async fn start_direct(
        &self,
        params: ExecParams,
    ) -> Result<StartedExecProcess, ExecServerError> {
        let (channel, stream) = {
            let mut result = None;
            for attempt in 0..SSH_START_ATTEMPTS {
                let channel = self.transport.open_work_channel().await?;

                // The remote sshd provides the PTY; request one when the caller wants a
                // tty so interactive programs behave (line editing, signals, echo).
                if params.tty
                    && let Err(error) = channel
                        .channel()
                        .request_pty(
                            false,
                            "xterm-256color",
                            /*col_width*/ 80,
                            /*row_height*/ 24,
                            /*pix_width*/ 0,
                            /*pix_height*/ 0,
                            &[],
                        )
                        .await
                {
                    if attempt + 1 < SSH_START_ATTEMPTS && is_reconnectable_ssh_error(&error) {
                        tracing::debug!(
                            session_key = %self.session_key,
                            error = %error,
                            "retrying ssh process start after pty failure"
                        );
                        continue;
                    }
                    return Err(classified_protocol_error("request_pty", &error));
                }

                let command = build_remote_command(&params);
                if let Err(error) = channel.channel().exec(true, command).await {
                    if attempt + 1 < SSH_START_ATTEMPTS && is_reconnectable_ssh_error(&error) {
                        tracing::debug!(
                            session_key = %self.session_key,
                            error = %error,
                            "retrying ssh process start after exec failure"
                        );
                        continue;
                    }
                    return Err(classified_protocol_error("exec", &error));
                }

                let stream = if params.tty {
                    ExecOutputStream::Pty
                } else {
                    ExecOutputStream::Stdout
                };
                result = Some((channel, stream));
                break;
            }
            result.ok_or_else(|| {
                ExecServerError::Protocol("ssh process start failed: exhausted_retries".to_string())
            })?
        };

        let process_id = params.process_id.clone();

        let events = ExecProcessEventLog::new(
            PROCESS_EVENT_CHANNEL_CAPACITY,
            RETAINED_OUTPUT_BYTES_PER_PROCESS,
        );
        let (wake_tx, _wake_rx) = watch::channel(0);
        let output_notify = Arc::new(Notify::new());
        let state = Arc::new(StdMutex::new(SharedState::default()));
        let (cmd_tx, cmd_rx) = mpsc::channel::<ChannelCommand>(64);

        tokio::spawn(channel_pump(
            channel,
            stream,
            events.clone(),
            wake_tx.clone(),
            Arc::clone(&output_notify),
            Arc::clone(&state),
            cmd_rx,
        ));

        Ok(StartedExecProcess {
            process: Arc::new(SshProcess {
                process_id,
                events,
                wake_tx,
                output_notify,
                state,
                cmd_tx,
            }),
        })
    }

    pub(super) fn transport(&self) -> &SshTransport {
        &self.transport
    }

    pub(super) fn session_key(&self) -> &str {
        &self.session_key
    }

    pub(super) fn controller_id(&self) -> &str {
        &self.controller_id
    }
}

impl ExecBackend for SshProcessBackend {
    fn start(&self, params: ExecParams) -> ExecBackendFuture<'_> {
        Box::pin(SshProcessBackend::start(self, params))
    }

    fn start_prepared(&self, prepared: crate::PreparedExecution) -> ExecBackendFuture<'_> {
        Box::pin(async move {
            if prepared.params().execution_identity.is_none() {
                return SshProcessBackend::start(self, prepared.into_params()).await;
            }
            match self.tmux_mode {
                SshTmuxMode::Required | SshTmuxMode::Preferred => {
                    tmux::start_prepared(self.clone(), prepared).await
                }
                SshTmuxMode::Disabled => Err(ExecServerError::Protocol(
                    "durable SSH execution requires tmux".to_string(),
                )),
            }
        })
    }

    fn adopt_execution(&self, request: crate::AdoptionRequest) -> ExecBackendFuture<'_> {
        Box::pin(async move {
            match self.tmux_mode {
                SshTmuxMode::Required | SshTmuxMode::Preferred => {
                    tmux::adopt_execution(self.clone(), request).await
                }
                SshTmuxMode::Disabled => Err(ExecServerError::Protocol(
                    "direct SSH execution cannot be durably adopted".to_string(),
                )),
            }
        })
    }

    fn reconcile(&self, request: crate::ReconciliationRequest) -> ExecBackendReconcileFuture<'_> {
        Box::pin(async move {
            match self.tmux_mode {
                SshTmuxMode::Required | SshTmuxMode::Preferred => {
                    tmux::reconcile(self, &request).await
                }
                SshTmuxMode::Disabled => Ok(Vec::new()),
            }
        })
    }

    fn acknowledge_consumed(
        &self,
        acknowledgement: crate::RecoveredExecutionAcknowledgement,
    ) -> crate::process::ExecBackendAcknowledgeFuture<'_> {
        Box::pin(async move {
            match self.tmux_mode {
                SshTmuxMode::Required | SshTmuxMode::Preferred => {
                    tmux::acknowledge_consumed(self, &acknowledgement).await
                }
                SshTmuxMode::Disabled => Ok(()),
            }
        })
    }

    fn release_acknowledged(
        &self,
        acknowledgement: crate::RecoveredExecutionAcknowledgement,
    ) -> crate::process::ExecBackendAcknowledgeFuture<'_> {
        Box::pin(async move {
            match self.tmux_mode {
                SshTmuxMode::Required | SshTmuxMode::Preferred => {
                    tmux::release_acknowledged(self, &acknowledgement).await
                }
                SshTmuxMode::Disabled => Ok(()),
            }
        })
    }
}

/// Build the remote command line, honoring cwd and env from [`ExecParams`].
///
/// `argv` is joined with shell quoting and prefixed with a `cd` (best effort)
/// and `export`s. The whole thing runs under the remote login shell (russh
/// `exec` already passes the string to a shell).
fn build_remote_command(params: &ExecParams) -> String {
    build_remote_command_with_argv_prefix(params, "exec ")
}

fn build_remote_command_with_argv_prefix(params: &ExecParams, argv_prefix: &str) -> String {
    let mut prefix = String::new();

    if let Ok(cwd) = params.cwd.to_abs_path() {
        prefix.push_str(&format!("cd {} && ", shell_quote(&cwd.to_string_lossy())));
    }

    if !params.env.contains_key("PATH") {
        prefix.push_str(REMOTE_PATH_EXPORT);
        prefix.push_str(" && ");
    }

    let mut environment = params.env.iter().collect::<Vec<_>>();
    environment.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    for (key, value) in environment {
        prefix.push_str(&format!("export {}={} && ", key, shell_quote(value)));
    }

    let joined = params
        .argv
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");

    format!("{prefix}{argv_prefix}{joined}")
}

/// Single-quote a string for POSIX shells, escaping embedded single quotes.
fn shell_quote(s: &str) -> String {
    let escaped = s.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
}

fn with_remote_path(command: &str) -> String {
    format!("{REMOTE_PATH_EXPORT} && {command}")
}

/// Output retained for seq-numbered [`ExecProcess::read`] paging.
struct SharedState {
    output: VecDeque<RetainedChunk>,
    retained_bytes: usize,
    next_seq: u64,
    exit_code: Option<i32>,
    closed: bool,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            output: VecDeque::new(),
            retained_bytes: 0,
            // Sequence numbers start at 1, mirroring LocalProcess.
            next_seq: 1,
            exit_code: None,
            closed: false,
        }
    }
}

struct RetainedChunk {
    seq: u64,
    stream: ExecOutputStream,
    chunk: Vec<u8>,
    absolute_start: Option<u64>,
    absolute_end: Option<u64>,
}

/// Mutating channel operations are funneled to the pump task that owns the
/// russh [`Channel`].
enum ChannelCommand {
    Write {
        data: Vec<u8>,
        write_id: Option<String>,
        ack: oneshot::Sender<Result<(), String>>,
    },
    Signal {
        signal: Sig,
        ack: oneshot::Sender<Result<ProcessSignalOutcome, String>>,
    },
    Terminate {
        ack: oneshot::Sender<Result<(), String>>,
    },
}

async fn complete_queued_write(
    ack: oneshot::Sender<Result<(), String>>,
    write: impl Future<Output = Result<(), String>>,
) {
    // A caller that timed out while the pump was disconnected must not have
    // its queued input delivered after reconnection. Once execution begins,
    // losing the acknowledgement still leaves the remote outcome unknown.
    if ack.is_closed() {
        return;
    }
    let result = write.await;
    let _ = ack.send(result);
}

struct SshProcess {
    process_id: ProcessId,
    events: ExecProcessEventLog,
    wake_tx: watch::Sender<u64>,
    output_notify: Arc<Notify>,
    state: Arc<StdMutex<SharedState>>,
    cmd_tx: mpsc::Sender<ChannelCommand>,
}

#[async_trait]
impl ExecProcessImpl for SshProcess {
    async fn read(
        &self,
        after_seq: Option<u64>,
        max_bytes: Option<usize>,
        wait_ms: Option<u64>,
    ) -> Result<ReadResponse, ExecServerError> {
        let after_seq = after_seq.unwrap_or(0);
        let max_bytes = max_bytes.unwrap_or(usize::MAX);
        let wait = Duration::from_millis(wait_ms.unwrap_or(0));
        let deadline = tokio::time::Instant::now() + wait;

        loop {
            let response = {
                let state = lock(&self.state);
                let mut chunks = Vec::new();
                let mut total_bytes = 0usize;
                let mut next_seq = state.next_seq;
                for retained in state.output.iter().filter(|chunk| chunk.seq > after_seq) {
                    let chunk_len = retained.chunk.len();
                    if !chunks.is_empty() && total_bytes + chunk_len > max_bytes {
                        break;
                    }
                    total_bytes += chunk_len;
                    chunks.push(ProcessOutputChunk {
                        seq: retained.seq,
                        stream: retained.stream,
                        chunk: retained.chunk.clone().into(),
                        absolute_start: retained.absolute_start,
                        absolute_end: retained.absolute_end,
                    });
                    next_seq = retained.seq + 1;
                    if total_bytes >= max_bytes {
                        break;
                    }
                }
                if max_bytes == usize::MAX {
                    next_seq = state.next_seq;
                }
                ReadResponse {
                    chunks,
                    next_seq,
                    exited: state.exit_code.is_some(),
                    exit_code: state.exit_code,
                    closed: state.closed,
                    failure: None,
                    sandbox_denied: false,
                }
            };

            let has_new_terminal_event =
                response.exited && after_seq < response.next_seq.saturating_sub(1);
            if !response.chunks.is_empty()
                || response.closed
                || has_new_terminal_event
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(response);
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(response);
            }
            let _ = tokio::time::timeout(remaining, self.output_notify.notified()).await;
        }
    }

    async fn write(&self, chunk: Vec<u8>) -> Result<WriteResponse, ExecServerError> {
        ExecProcessImpl::write_with_id(self, chunk, None).await
    }

    async fn write_with_id(
        &self,
        chunk: Vec<u8>,
        write_id: Option<String>,
    ) -> Result<WriteResponse, ExecServerError> {
        // stdin is only writable when a tty or pipe is connected. SSH always
        // gives us a writable channel here, but reflect the closed-stream case.
        {
            let state = lock(&self.state);
            if state.closed {
                return Ok(WriteResponse {
                    status: WriteStatus::StdinClosed,
                });
            }
        }

        tokio::time::timeout(SSH_WRITE_ACK_TIMEOUT, async {
            let (ack_tx, ack_rx) = oneshot::channel();
            if self
                .cmd_tx
                .send(ChannelCommand::Write {
                    data: chunk,
                    write_id,
                    ack: ack_tx,
                })
                .await
                .is_err()
            {
                return Ok(WriteResponse {
                    status: WriteStatus::StdinClosed,
                });
            }

            match ack_rx.await {
                Ok(Ok(())) => Ok(WriteResponse {
                    status: WriteStatus::Accepted,
                }),
                Ok(Err(err)) => Err(ExecServerError::Protocol(format!("ssh stdin write: {err}"))),
                Err(_) => Ok(WriteResponse {
                    status: WriteStatus::StdinClosed,
                }),
            }
        })
        .await
        .map_err(|_| {
            ExecServerError::Protocol(
                "ssh stdin write acknowledgement timed out; remote outcome is unknown".to_string(),
            )
        })?
    }

    async fn signal(&self, signal: ProcessSignal) -> Result<ProcessSignalOutcome, ExecServerError> {
        let sig = match signal {
            ProcessSignal::Interrupt => Sig::INT,
        };
        tokio::time::timeout(SSH_SIGNAL_ACK_TIMEOUT, async {
            let (ack_tx, ack_rx) = oneshot::channel();
            self.cmd_tx
                .send(ChannelCommand::Signal {
                    signal: sig,
                    ack: ack_tx,
                })
                .await
                .map_err(|_| {
                    ExecServerError::Protocol("ssh signal: channel pump unavailable".to_string())
                })?;
            match ack_rx.await {
                Ok(Ok(outcome)) => Ok(outcome),
                Ok(Err(error)) => Err(ExecServerError::Protocol(format!("ssh signal: {error}"))),
                Err(_) => Err(ExecServerError::Protocol(
                    "ssh signal acknowledgement channel closed".to_string(),
                )),
            }
        })
        .await
        .map_err(|_| {
            ExecServerError::Protocol("ssh signal acknowledgement timed out".to_string())
        })?
    }

    async fn terminate(&self) -> Result<(), ExecServerError> {
        tokio::time::timeout(SSH_TERMINATE_ACK_TIMEOUT, async {
            let (ack_tx, ack_rx) = oneshot::channel();
            self.cmd_tx
                .send(ChannelCommand::Terminate { ack: ack_tx })
                .await
                .map_err(|_| {
                    ExecServerError::Protocol(
                        "ssh terminate failed: process command pump is unavailable".to_string(),
                    )
                })?;
            ack_rx
                .await
                .map_err(|_| {
                    ExecServerError::Protocol(
                        "ssh terminate failed: process command pump dropped acknowledgement"
                            .to_string(),
                    )
                })?
                .map_err(|message| {
                    ExecServerError::Protocol(format!("ssh terminate failed: {message}"))
                })
        })
        .await
        .map_err(|_| {
            ExecServerError::Protocol(
                "ssh terminate failed: timed out awaiting remote acknowledgement".to_string(),
            )
        })?
    }
}

/// Internal async-trait so we can write `async fn` bodies; the real
/// [`ExecProcess`] trait methods delegate to these.
#[async_trait]
trait ExecProcessImpl: Send + Sync {
    async fn read(
        &self,
        after_seq: Option<u64>,
        max_bytes: Option<usize>,
        wait_ms: Option<u64>,
    ) -> Result<ReadResponse, ExecServerError>;
    async fn write(&self, chunk: Vec<u8>) -> Result<WriteResponse, ExecServerError>;
    async fn write_with_id(
        &self,
        chunk: Vec<u8>,
        write_id: Option<String>,
    ) -> Result<WriteResponse, ExecServerError>;
    async fn signal(&self, signal: ProcessSignal) -> Result<ProcessSignalOutcome, ExecServerError>;
    async fn terminate(&self) -> Result<(), ExecServerError>;
}

impl ExecProcess for SshProcess {
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
        max_bytes: Option<usize>,
        wait_ms: Option<u64>,
    ) -> ExecProcessFuture<'_, ReadResponse> {
        Box::pin(ExecProcessImpl::read(self, after_seq, max_bytes, wait_ms))
    }

    fn write(&self, chunk: Vec<u8>) -> ExecProcessFuture<'_, WriteResponse> {
        Box::pin(ExecProcessImpl::write(self, chunk))
    }

    fn write_with_id(
        &self,
        chunk: Vec<u8>,
        write_id: String,
    ) -> ExecProcessFuture<'_, WriteResponse> {
        Box::pin(ExecProcessImpl::write_with_id(self, chunk, Some(write_id)))
    }

    fn signal(&self, signal: ProcessSignal) -> ExecProcessFuture<'_, ProcessSignalOutcome> {
        Box::pin(ExecProcessImpl::signal(self, signal))
    }

    fn terminate(&self) -> ExecProcessFuture<'_, ()> {
        Box::pin(ExecProcessImpl::terminate(self))
    }
}

/// Owns the russh channel for its whole lifetime and pumps both directions.
#[allow(clippy::too_many_arguments)]
async fn channel_pump(
    mut channel: PooledSshChannel,
    stream: ExecOutputStream,
    events: ExecProcessEventLog,
    wake_tx: watch::Sender<u64>,
    output_notify: Arc<Notify>,
    state: Arc<StdMutex<SharedState>>,
    mut cmd_rx: mpsc::Receiver<ChannelCommand>,
) {
    let mut exit_code: Option<i32> = None;
    let mut termination_ack: Option<oneshot::Sender<Result<(), String>>> = None;

    loop {
        tokio::select! {
            msg = channel.channel_mut().wait() => {
                let Some(msg) = msg else {
                    // Channel fully closed.
                    break;
                };
                match msg {
                    ChannelMsg::Data { data } => {
                        publish_output(&state, &events, &wake_tx, &output_notify, stream, data.to_vec());
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        // stderr arrives as extended data; surface it on the
                        // same stream as the rest of the output for this spike.
                        publish_output(&state, &events, &wake_tx, &output_notify, stream, data.to_vec());
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status as i32);
                        publish_exit(&state, &events, &wake_tx, &output_notify, exit_status as i32);
                    }
                    ChannelMsg::ExitSignal { .. } if exit_code.is_none() => {
                        // Process killed by a signal; treat as a non-zero exit
                        // when we have no explicit status yet.
                        exit_code = Some(-1);
                        publish_exit(&state, &events, &wake_tx, &output_notify, -1);
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        // Keep looping until `wait()` returns None (fully
                        // closed) so we don't miss a trailing ExitStatus.
                    }
                    _ => {}
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ChannelCommand::Write {
                        data,
                        write_id: _,
                        ack,
                    }) => {
                        complete_queued_write(ack, async {
                            channel
                                .channel()
                                .data(&data[..])
                                .await
                                .map_err(|e| e.to_string())
                        }).await;
                    }
                    Some(ChannelCommand::Signal { signal, ack }) => {
                        if let Err(error) = channel.channel().signal(signal).await {
                            let _ = ack.send(Err(error.to_string()));
                            continue;
                        }
                        // RFC 4254 signal requests never ask sshd for a reply.
                        // Local enqueue and a later natural exit are both
                        // insufficient delivery proof. Make the best-effort
                        // request, but never report it as acknowledged.
                        let _ = ack.send(Err(
                            "remote SSH signal delivery is unacknowledgeable".to_string(),
                        ));
                    }
                    Some(ChannelCommand::Terminate { ack }) => {
                        if termination_ack.is_some() {
                            let _ = ack.send(Err("termination is already pending".to_string()));
                            continue;
                        }
                        if let Err(error) = channel.channel().signal(Sig::TERM).await {
                            let _ = ack.send(Err(error.to_string()));
                            continue;
                        }
                        if let Err(error) = channel.channel().eof().await {
                            let _ = ack.send(Err(error.to_string()));
                            continue;
                        }
                        // Delivery of EOF/signal is not termination. Acknowledge
                        // only after the SSH channel actually closes.
                        termination_ack = Some(ack);
                    }
                    None => {
                        // All process handles dropped; nothing left to drive
                        // stdin/signals. Keep pumping output until close.
                    }
                }
            }
        }
    }

    // If the remote closed without an explicit exit status, synthesize one so
    // readers observe an `Exited` before `Closed`.
    if exit_code.is_none() {
        publish_exit(&state, &events, &wake_tx, &output_notify, 0);
    }
    if let Some(ack) = termination_ack {
        let _ = ack.send(Ok(()));
    }
    publish_closed(&state, &events, &wake_tx, &output_notify);
}

fn publish_output(
    state: &Arc<StdMutex<SharedState>>,
    events: &ExecProcessEventLog,
    wake_tx: &watch::Sender<u64>,
    output_notify: &Arc<Notify>,
    stream: ExecOutputStream,
    chunk: Vec<u8>,
) {
    let output = {
        let mut state = lock(state);
        let seq = next_seq(&mut state);
        state.retained_bytes += chunk.len();
        state.output.push_back(RetainedChunk {
            seq,
            stream,
            chunk: chunk.clone(),
            absolute_start: None,
            absolute_end: None,
        });
        while state.retained_bytes > RETAINED_OUTPUT_BYTES_PER_PROCESS {
            let Some(evicted) = state.output.pop_front() else {
                break;
            };
            state.retained_bytes = state.retained_bytes.saturating_sub(evicted.chunk.len());
        }
        let _ = wake_tx.send(seq);
        ProcessOutputChunk {
            seq,
            stream,
            chunk: chunk.into(),
            absolute_start: None,
            absolute_end: None,
        }
    };
    events.publish(ExecProcessEvent::Output(output));
    output_notify.notify_waiters();
}

fn publish_output_with_absolute_range(
    state: &Arc<StdMutex<SharedState>>,
    events: &ExecProcessEventLog,
    wake_tx: &watch::Sender<u64>,
    output_notify: &Arc<Notify>,
    stream: ExecOutputStream,
    chunk: Vec<u8>,
    absolute_start: u64,
    absolute_end: u64,
) {
    let output = {
        let mut state = lock(state);
        let seq = next_seq(&mut state);
        state.retained_bytes += chunk.len();
        state.output.push_back(RetainedChunk {
            seq,
            stream,
            chunk: chunk.clone(),
            absolute_start: Some(absolute_start),
            absolute_end: Some(absolute_end),
        });
        while state.retained_bytes > RETAINED_OUTPUT_BYTES_PER_PROCESS {
            let Some(evicted) = state.output.pop_front() else {
                break;
            };
            state.retained_bytes = state.retained_bytes.saturating_sub(evicted.chunk.len());
        }
        let _ = wake_tx.send(seq);
        ProcessOutputChunk {
            seq,
            stream,
            chunk: chunk.into(),
            absolute_start: Some(absolute_start),
            absolute_end: Some(absolute_end),
        }
    };
    events.publish(ExecProcessEvent::Output(output));
    output_notify.notify_waiters();
}

fn publish_exit(
    state: &Arc<StdMutex<SharedState>>,
    events: &ExecProcessEventLog,
    wake_tx: &watch::Sender<u64>,
    output_notify: &Arc<Notify>,
    exit_code: i32,
) {
    let seq = {
        let mut state = lock(state);
        if state.exit_code.is_some() {
            return;
        }
        let seq = next_seq(&mut state);
        state.exit_code = Some(exit_code);
        let _ = wake_tx.send(seq);
        seq
    };
    events.publish(ExecProcessEvent::Exited {
        seq,
        exit_code,
        sandbox_denied: Some(false),
    });
    output_notify.notify_waiters();
}

fn publish_closed(
    state: &Arc<StdMutex<SharedState>>,
    events: &ExecProcessEventLog,
    wake_tx: &watch::Sender<u64>,
    output_notify: &Arc<Notify>,
) {
    let seq = {
        let mut state = lock(state);
        if state.closed {
            return;
        }
        let seq = next_seq(&mut state);
        state.closed = true;
        let _ = wake_tx.send(seq);
        seq
    };
    events.publish(ExecProcessEvent::Closed { seq });
    output_notify.notify_waiters();
}

#[cfg(test)]
#[path = "ssh_process_tests.rs"]
mod tests;

fn next_seq(state: &mut SharedState) -> u64 {
    let seq = state.next_seq;
    state.next_seq += 1;
    seq
}

fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
