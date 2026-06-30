//! SSH-backed [`ExecBackend`] for the Codex agent loop.
//!
//! This runs Codex's shell tools on a remote host over SSH instead of locally.
//! It mirrors the interface that [`crate::local_process::LocalProcess`] exposes
//! ([`ExecProcess`] + [`ExecBackend`]), but the process I/O flows over a russh
//! channel rather than an OS child + PTY. The remote sshd provides the PTY, so
//! none of the local OS-PTY / sandbox machinery is reused here.
//!
//! Lifecycle:
//! - [`SshProcessBackend::start`] connects, authenticates with a private key,
//!   opens a session channel, optionally requests a PTY, and execs the command
//!   built from [`ExecParams`].
//! - A single background task *owns* the russh [`Channel`] and runs a
//!   `select!` loop. It drains `Data`/`ExtendedData` into the
//!   [`ExecProcessEventLog`] (and a retained, seq-numbered output buffer for
//!   `read`), publishes `Exited` on `ExitStatus`, and `Closed` on channel
//!   close. All mutating channel operations (`write`/`signal`/`terminate`) are
//!   funneled to that task over an mpsc command channel, which sidesteps russh
//!   0.45's split between `wait(&mut self)` (reads) and `data`/`signal`/`eof`
//!   (`&self`).

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use russh::ChannelMsg;
use russh::Sig;
use russh::client;
use russh::keys::key;
use russh::keys::load_secret_key;
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
use crate::process::ExecProcessEventLog;
use crate::protocol::ExecOutputStream;
use crate::protocol::ExecParams;
use crate::protocol::ProcessOutputChunk;
use crate::protocol::ProcessSignal;
use crate::protocol::ReadResponse;
use crate::protocol::WriteResponse;
use crate::protocol::WriteStatus;

const RETAINED_OUTPUT_BYTES_PER_PROCESS: usize = 1024 * 1024;
const PROCESS_EVENT_CHANNEL_CAPACITY: usize = 256;
/// russh inactivity timeout for the control connection.
const SSH_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

/// Connection + auth material for opening SSH sessions.
///
/// Cloneable so the backend can open a fresh connection per `start()` call.
#[derive(Clone)]
pub struct SshProcessBackend {
    host: String,
    port: u16,
    user: String,
    key_path: String,
    /// Expected server host-key fingerprint in OpenSSH `SHA256:<base64nopad>`
    /// form (as printed by `ssh-keygen -lf`). When `Some`, the connection is
    /// accepted only if the server's host key fingerprint matches; when `None`,
    /// any host key is accepted (permissive).
    host_fingerprint: Option<String>,
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
        Self {
            host: host.into(),
            port,
            user: user.into(),
            key_path: key_path.into(),
            host_fingerprint: None,
        }
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
        Self {
            host: host.into(),
            port,
            user: user.into(),
            key_path: key_path.into(),
            host_fingerprint,
        }
    }

    async fn start(&self, params: ExecParams) -> Result<StartedExecProcess, ExecServerError> {
        let key_pair = load_secret_key(Path::new(&self.key_path), None)
            .map_err(|e| ExecServerError::Protocol(format!("ssh load key: {e}")))?;

        let config = Arc::new(client::Config {
            inactivity_timeout: Some(SSH_INACTIVITY_TIMEOUT),
            ..Default::default()
        });

        let handler = SshClientHandler {
            expected_fingerprint: self.host_fingerprint.clone(),
        };
        let mut session =
            client::connect(config, (self.host.as_str(), self.port), handler)
                .await
                .map_err(|e| ExecServerError::Protocol(format!("ssh connect: {e}")))?;

        let authed = session
            .authenticate_publickey(&self.user, Arc::new(key_pair))
            .await
            .map_err(|e| ExecServerError::Protocol(format!("ssh auth: {e}")))?;
        if !authed {
            return Err(ExecServerError::Protocol(
                "ssh authentication failed (publickey rejected)".to_string(),
            ));
        }

        let channel = session
            .channel_open_session()
            .await
            .map_err(|e| ExecServerError::Protocol(format!("ssh open channel: {e}")))?;

        // The remote sshd provides the PTY; request one when the caller wants a
        // tty so interactive programs behave (line editing, signals, echo).
        if params.tty {
            channel
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
                .map_err(|e| ExecServerError::Protocol(format!("ssh request pty: {e}")))?;
        }

        let command = build_remote_command(&params);
        channel
            .exec(true, command)
            .await
            .map_err(|e| ExecServerError::Protocol(format!("ssh exec: {e}")))?;

        let process_id = params.process_id.clone();
        let stream = if params.tty {
            ExecOutputStream::Pty
        } else {
            ExecOutputStream::Stdout
        };

        let events =
            ExecProcessEventLog::new(PROCESS_EVENT_CHANNEL_CAPACITY, RETAINED_OUTPUT_BYTES_PER_PROCESS);
        let (wake_tx, _wake_rx) = watch::channel(0);
        let output_notify = Arc::new(Notify::new());
        let state = Arc::new(StdMutex::new(SharedState::default()));
        let (cmd_tx, cmd_rx) = mpsc::channel::<ChannelCommand>(64);

        // Keep the russh session alive for the lifetime of the channel pump.
        // Dropping the `Handle` tears down the transport, so the pump task owns
        // it. `_session` is otherwise unused.
        tokio::spawn(channel_pump(
            session,
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
                tty: params.tty,
                events,
                wake_tx,
                output_notify,
                state,
                cmd_tx,
            }),
        })
    }
}

impl ExecBackend for SshProcessBackend {
    fn start(&self, params: ExecParams) -> ExecBackendFuture<'_> {
        Box::pin(SshProcessBackend::start(self, params))
    }
}

/// Build the remote command line, honoring cwd and env from [`ExecParams`].
///
/// `argv` is joined with shell quoting and prefixed with a `cd` (best effort)
/// and `export`s. The whole thing runs under the remote login shell (russh
/// `exec` already passes the string to a shell).
fn build_remote_command(params: &ExecParams) -> String {
    let mut prefix = String::new();

    if let Ok(cwd) = params.cwd.to_abs_path() {
        prefix.push_str(&format!("cd {} && ", shell_quote(&cwd.to_string_lossy())));
    }

    for (key, value) in &params.env {
        prefix.push_str(&format!(
            "export {}={} && ",
            key,
            shell_quote(value)
        ));
    }

    let joined = params
        .argv
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");

    format!("{prefix}exec {joined}")
}

/// Single-quote a string for POSIX shells, escaping embedded single quotes.
fn shell_quote(s: &str) -> String {
    let escaped = s.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
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
}

/// Mutating channel operations are funneled to the pump task that owns the
/// russh [`Channel`].
enum ChannelCommand {
    Write {
        data: Vec<u8>,
        ack: oneshot::Sender<Result<(), String>>,
    },
    Signal(Sig),
    Eof,
}

struct SshProcess {
    process_id: ProcessId,
    tty: bool,
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

        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(ChannelCommand::Write {
                data: chunk,
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
    }

    async fn signal(&self, signal: ProcessSignal) -> Result<(), ExecServerError> {
        let sig = match signal {
            ProcessSignal::Interrupt => Sig::INT,
        };
        // Best effort: try the SSH signal request; if the channel is gone, fall
        // back to injecting Ctrl-C into stdin (only meaningful with a PTY, but
        // harmless otherwise). Either way report success.
        if self.cmd_tx.send(ChannelCommand::Signal(sig)).await.is_err() {
            tracing::debug!("ssh signal: channel pump gone, dropping signal");
            return Ok(());
        }
        if self.tty {
            let (ack_tx, _ack_rx) = oneshot::channel();
            let _ = self
                .cmd_tx
                .send(ChannelCommand::Write {
                    data: vec![0x03],
                    ack: ack_tx,
                })
                .await;
        }
        Ok(())
    }

    async fn terminate(&self) -> Result<(), ExecServerError> {
        // Send EOF to close stdin; the pump task closes the channel when the
        // remote side finishes. Best effort.
        let _ = self.cmd_tx.send(ChannelCommand::Eof).await;
        Ok(())
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
    async fn signal(&self, signal: ProcessSignal) -> Result<(), ExecServerError>;
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

    fn signal(&self, signal: ProcessSignal) -> ExecProcessFuture<'_, ()> {
        Box::pin(ExecProcessImpl::signal(self, signal))
    }

    fn terminate(&self) -> ExecProcessFuture<'_, ()> {
        Box::pin(ExecProcessImpl::terminate(self))
    }
}

struct SshClientHandler {
    /// Expected host-key fingerprint in OpenSSH `SHA256:<base64nopad>` form. The
    /// `SHA256:` prefix is optional. When `None`, any host key is accepted.
    expected_fingerprint: Option<String>,
}

#[async_trait]
impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.expected_fingerprint {
            // No pin configured: permissive (matches the host spike behavior).
            None => Ok(true),
            Some(expected) => {
                // russh's `PublicKey::fingerprint()` returns the base64 (no
                // padding) SHA256 of the serialized public key — i.e. exactly
                // what OpenSSH's `ssh-keygen -lf` prints after the `SHA256:`
                // prefix. Compare against the expected fingerprint, tolerating
                // an optional leading `SHA256:`.
                let actual = server_public_key.fingerprint();
                let expected = expected
                    .strip_prefix("SHA256:")
                    .unwrap_or(expected.as_str());
                Ok(actual == expected)
            }
        }
    }
}

/// Owns the russh channel for its whole lifetime and pumps both directions.
#[allow(clippy::too_many_arguments)]
async fn channel_pump(
    _session: client::Handle<SshClientHandler>,
    mut channel: russh::Channel<client::Msg>,
    stream: ExecOutputStream,
    events: ExecProcessEventLog,
    wake_tx: watch::Sender<u64>,
    output_notify: Arc<Notify>,
    state: Arc<StdMutex<SharedState>>,
    mut cmd_rx: mpsc::Receiver<ChannelCommand>,
) {
    let mut exit_code: Option<i32> = None;

    loop {
        tokio::select! {
            msg = channel.wait() => {
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
                    Some(ChannelCommand::Write { data, ack }) => {
                        let result = channel
                            .data(&data[..])
                            .await
                            .map_err(|e| e.to_string());
                        let _ = ack.send(result);
                    }
                    Some(ChannelCommand::Signal(sig)) => {
                        let _ = channel.signal(sig).await;
                    }
                    Some(ChannelCommand::Eof) => {
                        let _ = channel.eof().await;
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

fn next_seq(state: &mut SharedState) -> u64 {
    let seq = state.next_seq;
    state.next_seq += 1;
    seq
}

fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
