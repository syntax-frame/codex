//! Shared, pooled SSH transport for remote exec and SFTP backends.
//!
//! A pool is keyed by the saved AgentApp connection profile, not by an agent.
//! Agents still have independent process state, but their SSH channels share a
//! bounded set of authenticated TCP transports. This avoids handshake bursts
//! and server-side `MaxStartups` pressure while preserving channel isolation.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use russh::ChannelMsg;
use russh::client;
use russh::client::KeyboardInteractiveAuthResponse;
use russh::keys::key;
use russh::keys::load_secret_key;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;

use crate::ExecServerError;

const SSH_POOL_CONNECTIONS: usize = 32;
const SSH_WORK_CHANNELS_PER_CONNECTION: usize = 7;
const SSH_CONTROL_CHANNELS_PER_CONNECTION: usize = 1;
const SSH_CONTROL_OPERATIONS_PER_POOL: usize = 8;
const SSH_CONNECT_CONCURRENCY: usize = 4;
const SSH_CONNECT_ATTEMPTS: usize = 3;
const SSH_OPEN_CHANNEL_ATTEMPTS: usize = 8;
const SSH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const SSH_KEEPALIVE_MAX: usize = 3;
const SSH_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const SSH_COMMAND_OUTPUT_LIMIT: usize = 1024 * 1024;

static SSH_POOLS: OnceLock<StdMutex<HashMap<String, Arc<SshConnectionPool>>>> = OnceLock::new();
static SSH_CONNECT_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
static SSH_RETRY_JITTER: AtomicU64 = AtomicU64::new(0);

/// Authentication material used when a pooled transport must reconnect.
///
/// Secrets are intentionally redacted from `Debug` output.
#[derive(Clone)]
pub enum SshAuthentication {
    PrivateKeyPath(String),
    Password(String),
}

impl fmt::Debug for SshAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateKeyPath(_) => formatter.write_str("PrivateKeyPath(<redacted>)"),
            Self::Password(_) => formatter.write_str("Password(<redacted>)"),
        }
    }
}

/// Cloneable access to a per-server pool of authenticated SSH transports.
#[derive(Clone)]
pub(crate) struct SshTransport {
    config: Arc<SshConnectionConfig>,
    pool: Arc<SshConnectionPool>,
}

impl SshTransport {
    pub(crate) fn new(
        connection_key: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        authentication: SshAuthentication,
        host_fingerprint: Option<String>,
    ) -> Self {
        let connection_key = connection_key.into();
        let host = host.into();
        let user = user.into();
        let pool_key = format!(
            "{}|{}@{}:{}|{}",
            connection_key,
            user,
            host,
            port,
            host_fingerprint.as_deref().unwrap_or("")
        );
        let pool = shared_pool(&pool_key);
        Self {
            config: Arc::new(SshConnectionConfig {
                pool_key,
                host,
                port,
                user,
                authentication,
                host_fingerprint,
            }),
            pool,
        }
    }

    pub(crate) async fn open_work_channel(&self) -> Result<PooledSshChannel, ExecServerError> {
        self.pool
            .open_channel(&self.config, ChannelPurpose::Work)
            .await
    }

    pub(crate) async fn open_control_channel(&self) -> Result<PooledSshChannel, ExecServerError> {
        self.pool
            .open_channel(&self.config, ChannelPurpose::Control)
            .await
    }

    pub(crate) async fn exec_control(
        &self,
        command: &str,
        input: Option<&[u8]>,
    ) -> Result<SshCommandOutput, ExecServerError> {
        let mut leased = self.open_control_channel().await?;
        leased
            .channel()
            .exec(true, command)
            .await
            .map_err(|error| classified_protocol_error("exec", &error))?;

        if let Some(input) = input {
            leased
                .channel()
                .data(input)
                .await
                .map_err(|error| classified_protocol_error("stdin", &error))?;
            leased
                .channel()
                .eof()
                .await
                .map_err(|error| classified_protocol_error("stdin_eof", &error))?;
        }

        let mut output = Vec::new();
        let mut exit_code = None;
        while let Some(message) = leased.channel_mut().wait().await {
            match message {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    if output.len().saturating_add(data.len()) > SSH_COMMAND_OUTPUT_LIMIT {
                        return Err(ExecServerError::Protocol(
                            "ssh control command exceeded 1 MiB output limit".to_string(),
                        ));
                    }
                    output.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status as i32);
                }
                ChannelMsg::ExitSignal { .. } if exit_code.is_none() => {
                    exit_code = Some(-1);
                }
                _ => {}
            }
        }

        Ok(SshCommandOutput {
            output,
            exit_code: exit_code.unwrap_or(-1),
        })
    }
}

pub(crate) struct SshCommandOutput {
    pub(crate) output: Vec<u8>,
    pub(crate) exit_code: i32,
}

struct SshConnectionConfig {
    pool_key: String,
    host: String,
    port: u16,
    user: String,
    authentication: SshAuthentication,
    host_fingerprint: Option<String>,
}

struct SshConnectionPool {
    slots: Vec<Arc<SshConnectionSlot>>,
    control_permits: Arc<Semaphore>,
    wait_cursor: AtomicUsize,
}

impl SshConnectionPool {
    fn new() -> Self {
        let slots = (0..SSH_POOL_CONNECTIONS)
            .map(|index| Arc::new(SshConnectionSlot::new(index)))
            .collect();
        Self {
            slots,
            control_permits: Arc::new(Semaphore::new(SSH_CONTROL_OPERATIONS_PER_POOL)),
            wait_cursor: AtomicUsize::new(0),
        }
    }

    async fn open_channel(
        &self,
        config: &SshConnectionConfig,
        purpose: ChannelPurpose,
    ) -> Result<PooledSshChannel, ExecServerError> {
        let mut pool_control_permit = match purpose {
            ChannelPurpose::Work => None,
            ChannelPurpose::Control => Some(
                Arc::clone(&self.control_permits)
                    .acquire_owned()
                    .await
                    .map_err(|error| classified_protocol_error("control_wait", &error))?,
            ),
        };

        for attempt in 0..SSH_OPEN_CHANNEL_ATTEMPTS {
            let mut last_failure = None;

            // Keep each transport below OpenSSH's default MaxSessions value so
            // sshd and out-of-band administration retain channel headroom.
            for slot in &self.slots {
                let Some(permit) = slot.try_acquire(purpose) else {
                    continue;
                };
                match slot.open(config, permit).await {
                    Ok(channel) => {
                        return Ok(channel.with_pool_control_permit(pool_control_permit.take()));
                    }
                    Err(failure) if failure.retryable || failure.capacity => {
                        last_failure = Some(failure);
                    }
                    Err(failure) => return Err(failure.error),
                }
            }

            // Every local permit is occupied. Wait for one bounded slot rather
            // than creating an unbounded physical transport.
            if last_failure.is_none() {
                let index = self.wait_cursor.fetch_add(1, Ordering::Relaxed) % self.slots.len();
                let slot = &self.slots[index];
                let permit = slot.acquire(purpose).await?;
                match slot.open(config, permit).await {
                    Ok(channel) => {
                        return Ok(channel.with_pool_control_permit(pool_control_permit.take()));
                    }
                    Err(failure) if failure.retryable || failure.capacity => {
                        last_failure = Some(failure);
                    }
                    Err(failure) => return Err(failure.error),
                }
            }

            let Some(failure) = last_failure else {
                continue;
            };
            if attempt + 1 == SSH_OPEN_CHANNEL_ATTEMPTS {
                return Err(failure.error);
            }
            retry_delay(attempt).await;
        }

        unreachable!("channel retry loop always returns")
    }
}

#[derive(Clone, Copy)]
enum ChannelPurpose {
    Work,
    Control,
}

struct SshConnectionSlot {
    index: usize,
    session: StdMutex<Option<client::Handle<SshClientHandler>>>,
    open_permit: Arc<Semaphore>,
    work_permits: Arc<Semaphore>,
    control_permits: Arc<Semaphore>,
}

impl SshConnectionSlot {
    fn new(index: usize) -> Self {
        Self {
            index,
            session: StdMutex::new(None),
            open_permit: Arc::new(Semaphore::new(1)),
            work_permits: Arc::new(Semaphore::new(SSH_WORK_CHANNELS_PER_CONNECTION)),
            control_permits: Arc::new(Semaphore::new(SSH_CONTROL_CHANNELS_PER_CONNECTION)),
        }
    }

    fn semaphore(&self, purpose: ChannelPurpose) -> &Arc<Semaphore> {
        match purpose {
            ChannelPurpose::Work => &self.work_permits,
            ChannelPurpose::Control => &self.control_permits,
        }
    }

    fn try_acquire(&self, purpose: ChannelPurpose) -> Option<OwnedSemaphorePermit> {
        Arc::clone(self.semaphore(purpose)).try_acquire_owned().ok()
    }

    async fn acquire(
        &self,
        purpose: ChannelPurpose,
    ) -> Result<OwnedSemaphorePermit, ExecServerError> {
        Arc::clone(self.semaphore(purpose))
            .acquire_owned()
            .await
            .map_err(|error| classified_protocol_error("pool_wait", &error))
    }

    async fn open(
        &self,
        config: &SshConnectionConfig,
        permit: OwnedSemaphorePermit,
    ) -> Result<PooledSshChannel, TransportFailure> {
        // russh's Handle is not cloneable. Serialize only the short channel-open
        // operation, moving the handle out of the synchronous slot mutex before
        // every network await. Established channels remain fully concurrent.
        let _open_permit = Arc::clone(&self.open_permit)
            .acquire_owned()
            .await
            .map_err(|error| TransportFailure {
                error: classified_protocol_error("slot_wait", &error),
                retryable: true,
                capacity: false,
            })?;

        for attempt in 0..2 {
            let session = match self.take_live_session() {
                Some(session) => session,
                None => {
                    tracing::debug!(
                        pool_key = %config.pool_key,
                        slot = self.index,
                        "opening pooled ssh transport"
                    );
                    connect_authenticated(config).await?
                }
            };

            let result = session.channel_open_session().await;
            match result {
                Ok(channel) => {
                    self.store_session(session);
                    tracing::debug!(
                        pool_key = %config.pool_key,
                        slot = self.index,
                        "opened pooled ssh channel"
                    );
                    return Ok(PooledSshChannel {
                        channel,
                        _permit: permit,
                        _pool_control_permit: None,
                    });
                }
                Err(error) if matches!(error, russh::Error::ChannelOpenFailure(_)) => {
                    self.store_session(session);
                    return Err(TransportFailure {
                        error: classified_protocol_error("open_channel", &error),
                        retryable: false,
                        capacity: true,
                    });
                }
                Err(error) if attempt == 0 && is_reconnectable_ssh_error(&error) => {
                    tracing::debug!(
                        pool_key = %config.pool_key,
                        slot = self.index,
                        error = %error,
                        "reconnecting pooled ssh transport after channel-open failure"
                    );
                }
                Err(error) => {
                    if !session.is_closed() {
                        self.store_session(session);
                    }
                    return Err(TransportFailure::from_russh("open_channel", error));
                }
            }
        }

        Err(TransportFailure {
            error: ExecServerError::Protocol(
                "ssh open channel failed: exhausted reconnect attempts".to_string(),
            ),
            retryable: true,
            capacity: false,
        })
    }

    fn take_live_session(&self) -> Option<client::Handle<SshClientHandler>> {
        let mut guard = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.take().filter(|session| !session.is_closed())
    }

    fn store_session(&self, session: client::Handle<SshClientHandler>) {
        let mut guard = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(session);
    }
}

async fn connect_authenticated(
    config: &SshConnectionConfig,
) -> Result<client::Handle<SshClientHandler>, TransportFailure> {
    let client_config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(SSH_KEEPALIVE_INTERVAL),
        keepalive_max: SSH_KEEPALIVE_MAX,
        ..Default::default()
    });

    for attempt in 0..SSH_CONNECT_ATTEMPTS {
        let permit = connect_semaphore()
            .acquire()
            .await
            .map_err(|error| TransportFailure {
                error: classified_protocol_error("connect_throttle", &error),
                retryable: true,
                capacity: false,
            })?;
        let handler = SshClientHandler {
            expected_fingerprint: config.host_fingerprint.clone(),
        };
        let mut session = match client::connect(
            Arc::clone(&client_config),
            (config.host.as_str(), config.port),
            handler,
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                let failure = TransportFailure::from_russh("connect", error);
                if attempt + 1 < SSH_CONNECT_ATTEMPTS && failure.retryable {
                    drop(permit);
                    retry_delay(attempt).await;
                    continue;
                }
                return Err(failure);
            }
        };

        let authenticated = match &config.authentication {
            SshAuthentication::PrivateKeyPath(path) => {
                let key_pair =
                    load_secret_key(Path::new(path), None).map_err(|error| TransportFailure {
                        error: classified_protocol_error("load_key", &error),
                        retryable: false,
                        capacity: false,
                    })?;
                session
                    .authenticate_publickey(&config.user, Arc::new(key_pair))
                    .await
            }
            SshAuthentication::Password(password) => {
                authenticate_password(&mut session, &config.user, password).await
            }
        };

        match authenticated {
            Ok(true) => return Ok(session),
            Ok(false) => {
                return Err(TransportFailure {
                    error: ExecServerError::Protocol(
                        "ssh auth failed: credential_rejected".to_string(),
                    ),
                    retryable: false,
                    capacity: false,
                });
            }
            Err(error) => {
                let failure = TransportFailure::from_russh("auth", error);
                if attempt + 1 < SSH_CONNECT_ATTEMPTS && failure.retryable {
                    drop(permit);
                    retry_delay(attempt).await;
                    continue;
                }
                return Err(failure);
            }
        }
    }

    Err(TransportFailure {
        error: ExecServerError::Protocol("ssh connect failed: exhausted_retries".to_string()),
        retryable: true,
        capacity: false,
    })
}

async fn authenticate_password(
    session: &mut client::Handle<SshClientHandler>,
    user: &str,
    password: &str,
) -> Result<bool, russh::Error> {
    if session.authenticate_password(user, password).await? {
        return Ok(true);
    }

    // Some PAM-backed servers expose a normal password prompt only through
    // keyboard-interactive. Support the common single-secret form without
    // pretending to handle multi-factor exchanges.
    let mut response = session
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    for _ in 0..4 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                if prompts.len() > 1 {
                    return Ok(false);
                }
                let responses = prompts
                    .iter()
                    .map(|prompt| {
                        if prompt.echo {
                            String::new()
                        } else {
                            password.to_string()
                        }
                    })
                    .collect();
                response = session
                    .authenticate_keyboard_interactive_respond(responses)
                    .await?;
            }
        }
    }
    Ok(false)
}

struct TransportFailure {
    error: ExecServerError,
    retryable: bool,
    capacity: bool,
}

impl TransportFailure {
    fn from_russh(phase: &str, error: russh::Error) -> Self {
        let retryable = is_reconnectable_ssh_error(&error);
        Self {
            error: classified_protocol_error(phase, &error),
            retryable,
            capacity: false,
        }
    }
}

fn shared_pool(pool_key: &str) -> Arc<SshConnectionPool> {
    let pools = SSH_POOLS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = pools
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .entry(pool_key.to_string())
        .or_insert_with(|| Arc::new(SshConnectionPool::new()))
        .clone()
}

fn connect_semaphore() -> &'static Semaphore {
    SSH_CONNECT_SEMAPHORE.get_or_init(|| Semaphore::new(SSH_CONNECT_CONCURRENCY))
}

async fn retry_delay(attempt: usize) {
    let factor = 1u32 << attempt.min(4);
    let jitter = SSH_RETRY_JITTER.fetch_add(37, Ordering::Relaxed) % 200;
    tokio::time::sleep(SSH_RETRY_BASE_DELAY * factor + Duration::from_millis(jitter)).await;
}

pub(crate) fn is_reconnectable_ssh_error(error: &russh::Error) -> bool {
    matches!(
        error,
        russh::Error::Disconnect
            | russh::Error::HUP
            | russh::Error::ConnectionTimeout
            | russh::Error::KeepaliveTimeout
            | russh::Error::InactivityTimeout
            | russh::Error::SendError
            | russh::Error::IO(_)
    ) || is_reconnectable_ssh_message(&error.to_string())
}

fn is_reconnectable_ssh_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("disconnected")
        || lower.contains("disconnect")
        || lower.contains("broken pipe")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("temporarily unavailable")
        || lower.contains("network is unreachable")
        || lower.contains("host is down")
}

pub(crate) fn classified_protocol_error(phase: &str, error: &dyn fmt::Display) -> ExecServerError {
    let message = error.to_string();
    let class = classify_ssh_error_message(&message);
    ExecServerError::Protocol(format!("ssh {phase} failed: {class}: {message}"))
}

fn classify_ssh_error_message(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("connection reset") {
        "server_reset"
    } else if lower.contains("connection refused") {
        "connection_refused"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("broken pipe") || lower.contains("connection closed") {
        "connection_closed"
    } else if lower.contains("disconnected") || lower.contains("disconnect") {
        "server_disconnected"
    } else if lower.contains("authentication") || lower.contains("publickey") {
        "auth"
    } else if lower.contains("fingerprint")
        || lower.contains("server key")
        || lower.contains("unknown key")
    {
        "host_key"
    } else if lower.contains("network is unreachable") || lower.contains("host is down") {
        "network_unreachable"
    } else if lower.contains("channel open") || lower.contains("resource shortage") {
        "server_channel_limit"
    } else {
        "unknown"
    }
}

struct SshClientHandler {
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
            None => Ok(true),
            Some(expected) => {
                let expected = expected
                    .strip_prefix("SHA256:")
                    .unwrap_or(expected.as_str());
                Ok(server_public_key.fingerprint() == expected)
            }
        }
    }
}

/// A channel plus the pool capacity permit held for its lifetime.
pub(crate) struct PooledSshChannel {
    channel: russh::Channel<client::Msg>,
    _permit: OwnedSemaphorePermit,
    _pool_control_permit: Option<OwnedSemaphorePermit>,
}

impl PooledSshChannel {
    fn with_pool_control_permit(mut self, permit: Option<OwnedSemaphorePermit>) -> Self {
        self._pool_control_permit = permit;
        self
    }

    pub(crate) fn channel(&self) -> &russh::Channel<client::Msg> {
        &self.channel
    }

    pub(crate) fn channel_mut(&mut self) -> &mut russh::Channel<client::Msg> {
        &mut self.channel
    }

    pub(crate) fn into_stream(self) -> PooledSshChannelStream {
        PooledSshChannelStream {
            inner: self.channel.into_stream(),
            _permit: self._permit,
            _pool_control_permit: self._pool_control_permit,
        }
    }
}

/// An SFTP-compatible stream that keeps its pool permit until the subsystem
/// closes. This replaces the previous leaked russh session handle.
pub(crate) struct PooledSshChannelStream {
    inner: russh::ChannelStream<client::Msg>,
    _permit: OwnedSemaphorePermit,
    _pool_control_permit: Option<OwnedSemaphorePermit>,
}

impl AsyncRead for PooledSshChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PooledSshChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
