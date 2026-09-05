use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use russh::Channel;
use russh::ChannelId;
use russh::CryptoVec;
use russh::server;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::sync::oneshot;

use super::super::SSH_POOL_CONNECTIONS;
use super::super::SSH_WORK_CHANNELS_PER_CONNECTION;
use super::super::SshAuthentication;
use super::super::SshTransport;
use super::connect_with_timeout;

#[derive(Clone, Copy)]
enum ServerBehavior {
    WithholdSubsystem,
    ZeroWindow,
    Ready,
}

struct SftpServer {
    behavior: ServerBehavior,
    subsystem_requested: Arc<Notify>,
    closed: Arc<Notify>,
    sftp_channel: Option<ChannelId>,
}

#[async_trait]
impl server::Handler for SftpServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel);
        session.exit_status_request(channel, /*exit_status*/ 0);
        session.eof(channel);
        session.close(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.subsystem_requested.notify_one();
        self.sftp_channel = Some(channel);
        match self.behavior {
            ServerBehavior::WithholdSubsystem => {}
            ServerBehavior::ZeroWindow | ServerBehavior::Ready => session.channel_success(channel),
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.sftp_channel == Some(channel) {
            self.closed.notify_one();
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.behavior, ServerBehavior::Ready) {
            if data.get(4) == Some(&1) {
                // SSH_FXP_VERSION, version 3, no extensions.
                session.data(channel, CryptoVec::from_slice(&[0, 0, 0, 5, 2, 0, 0, 0, 3]));
            } else {
                // A content-free SSH_FXP_STATUS(NoSuchFile) proves requests
                // still cross the bridge after its startup timer was disarmed.
                let mut response = vec![0, 0, 0, 17, 101];
                response.extend_from_slice(&data[5..9]);
                response.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
                session.data(channel, CryptoVec::from_slice(&response));
            }
        }
        Ok(())
    }
}

struct Fixture {
    transport: SshTransport,
    subsystem_requested: Arc<Notify>,
    closed: Arc<Notify>,
    shutdown: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(behavior: ServerBehavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind SSH server");
        let address = listener.local_addr().expect("SSH server address");
        let subsystem_requested = Arc::new(Notify::new());
        let closed = Arc::new(Notify::new());
        let handler = SftpServer {
            behavior,
            subsystem_requested: Arc::clone(&subsystem_requested),
            closed: Arc::clone(&closed),
            sftp_channel: None,
        };
        let config = Arc::new(server::Config {
            keys: vec![russh::keys::key::KeyPair::generate_ed25519().expect("test host key")],
            window_size: if matches!(behavior, ServerBehavior::ZeroWindow) {
                0
            } else {
                2097152
            },
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let (shutdown, shutdown_requested) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept SSH client");
            let mut session = server::run_stream(config, stream, handler)
                .await
                .expect("start SSH session");
            tokio::select! {
                _ = &mut session => {}
                _ = shutdown_requested => {
                    let _ = session.handle().disconnect(
                        russh::Disconnect::ByApplication,
                        "test completed".to_string(),
                        String::new(),
                    ).await;
                    let _ = tokio::time::timeout(Duration::from_secs(1), session).await;
                }
            }
        });
        let transport = SshTransport::new(
            uuid::Uuid::new_v4().to_string(),
            address.ip().to_string(),
            address.port(),
            "test",
            SshAuthentication::Password("test".to_string()),
            /*host_fingerprint*/ None,
        );
        transport
            .exec_control("warm", /*input*/ None)
            .await
            .expect("warm SSH connection");
        Self {
            transport,
            subsystem_requested,
            closed,
            shutdown,
            server,
        }
    }

    async fn finish(self) {
        let _ = self.shutdown.send(());
        self.server.await.expect("server shutdown");
    }
}

fn available_work_permits(transport: &SshTransport) -> usize {
    transport
        .pool
        .slots
        .iter()
        .map(|slot| slot.work_permits.available_permits())
        .sum()
}

#[tokio::test]
async fn sftp_startup_deadline_covers_ssh_handshake_and_releases_permits() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled server");
    let address = listener.local_addr().expect("server address");
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept client");
        std::future::pending::<()>().await;
    });
    let transport = SshTransport::new(
        uuid::Uuid::new_v4().to_string(),
        address.ip().to_string(),
        address.port(),
        "test",
        SshAuthentication::Password("test".to_string()),
        /*host_fingerprint*/ None,
    );
    let error = connect_with_timeout(&transport, Duration::from_millis(100))
        .await
        .err()
        .expect("stalled handshake must time out");
    assert_eq!(
        (error.kind(), error.to_string()),
        (
            io::ErrorKind::TimedOut,
            "ssh sftp startup timed out".to_string()
        )
    );
    assert_eq!(
        available_work_permits(&transport),
        SSH_POOL_CONNECTIONS * SSH_WORK_CHANNELS_PER_CONNECTION
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn sftp_startup_deadline_covers_unanswered_subsystem_and_zero_window_init() {
    for behavior in [
        ServerBehavior::WithholdSubsystem,
        ServerBehavior::ZeroWindow,
    ] {
        let fixture = Fixture::new(behavior).await;
        let error = connect_with_timeout(&fixture.transport, Duration::from_millis(100))
            .await
            .err()
            .expect("SFTP startup must time out");
        assert_eq!(
            (error.kind(), error.to_string()),
            (
                io::ErrorKind::TimedOut,
                "ssh sftp startup timed out".to_string()
            )
        );
        assert_eq!(
            available_work_permits(&fixture.transport),
            SSH_POOL_CONNECTIONS * SSH_WORK_CHANNELS_PER_CONNECTION
        );
        tokio::time::timeout(Duration::from_secs(1), fixture.closed.notified())
            .await
            .expect("timed-out SFTP channel closed remotely");
        fixture.finish().await;
    }
}

#[tokio::test]
async fn sftp_library_handshake_timeout_uses_the_stable_startup_marker() {
    let fixture = Fixture::new(ServerBehavior::WithholdSubsystem).await;
    let transport = fixture.transport.clone();
    let started_at = tokio::time::Instant::now();
    let startup =
        tokio::spawn(
            async move { connect_with_timeout(&transport, Duration::from_secs(30)).await },
        );
    tokio::time::timeout(
        Duration::from_secs(1),
        fixture.subsystem_requested.notified(),
    )
    .await
    .expect("subsystem requested");
    // Advance the library's ten-second request timer without reaching this
    // connection's thirty-second outer deadline.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    let error = startup
        .await
        .expect("startup task")
        .err()
        .expect("library timeout");
    assert!(started_at.elapsed() < Duration::from_secs(30));
    tokio::time::resume();
    assert_eq!(
        (error.kind(), error.to_string()),
        (
            io::ErrorKind::TimedOut,
            "ssh sftp startup timed out".to_string()
        )
    );
    assert_eq!(
        available_work_permits(&fixture.transport),
        SSH_POOL_CONNECTIONS * SSH_WORK_CHANNELS_PER_CONNECTION
    );
    tokio::time::timeout(Duration::from_secs(1), fixture.closed.notified())
        .await
        .expect("library timeout closes its SFTP channel");
    fixture.finish().await;
}

#[tokio::test]
async fn sftp_startup_cancellation_releases_zero_window_stream() {
    let fixture = Fixture::new(ServerBehavior::ZeroWindow).await;
    let transport = fixture.transport.clone();
    let startup =
        tokio::spawn(
            async move { connect_with_timeout(&transport, Duration::from_secs(30)).await },
        );
    tokio::time::timeout(
        Duration::from_secs(1),
        fixture.subsystem_requested.notified(),
    )
    .await
    .expect("subsystem requested");
    startup.abort();
    let _ = startup.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while available_work_permits(&fixture.transport)
            != SSH_POOL_CONNECTIONS * SSH_WORK_CHANNELS_PER_CONNECTION
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled startup releases its work permit");
    tokio::time::timeout(Duration::from_secs(1), fixture.closed.notified())
        .await
        .expect("cancelled SFTP channel closed remotely");
    fixture.finish().await;
}

#[tokio::test]
async fn sftp_startup_deadline_is_disarmed_and_session_drop_releases_permit() {
    let fixture = Fixture::new(ServerBehavior::Ready).await;
    let session = connect_with_timeout(&fixture.transport, Duration::from_millis(100))
        .await
        .expect("initialize SFTP");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let error = session
        .metadata("/probe")
        .await
        .expect_err("test server reports missing path");
    assert!(
        matches!(error, russh_sftp::client::error::Error::Status(status)
        if status.status_code == russh_sftp::protocol::StatusCode::NoSuchFile)
    );
    assert_eq!(
        available_work_permits(&fixture.transport),
        SSH_POOL_CONNECTIONS * SSH_WORK_CHANNELS_PER_CONNECTION - 1
    );
    drop(session);
    tokio::time::timeout(Duration::from_secs(1), async {
        while available_work_permits(&fixture.transport)
            != SSH_POOL_CONNECTIONS * SSH_WORK_CHANNELS_PER_CONNECTION
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping SFTP releases work permit even without server EOF");
    tokio::time::timeout(Duration::from_secs(1), fixture.closed.notified())
        .await
        .expect("dropped SFTP channel closed remotely");
    fixture.finish().await;
}
