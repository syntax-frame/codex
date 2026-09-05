use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use russh::Channel;
use russh::ChannelId;
use russh::ChannelMsg;
use russh::CryptoVec;
use russh::server;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::sync::oneshot;

use super::SSH_CONTROL_OPERATIONS_PER_POOL;
use super::SSH_WORK_CHANNELS_PER_CONNECTION;
use super::SshAuthentication;
use super::SshTransport;

struct ControlServer {
    executions: Arc<AtomicUsize>,
    closed: Arc<Notify>,
}

#[async_trait]
impl server::Handler for ControlServer {
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
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        session.channel_success(channel);
        if command == b"finish" {
            session.data(channel, CryptoVec::from_slice(b"done"));
            session.exit_status_request(channel, 7);
            session.eof(channel);
            session.close(channel);
        } else {
            session.data(channel, CryptoVec::from_slice(b"private remote output"));
            // A live SSH transport can keep sending keepalives while this
            // command never reports EOF. That must still meet the deadline.
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.closed.notify_one();
        Ok(())
    }
}

#[tokio::test]
async fn control_deadline_closes_hung_command_without_replay_and_releases_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind SSH server");
    let address = listener.local_addr().expect("SSH server address");
    let executions = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(Notify::new());
    let handler = ControlServer {
        executions: Arc::clone(&executions),
        closed: Arc::clone(&closed),
    };
    let config = Arc::new(server::Config {
        keys: vec![russh::keys::key::KeyPair::generate_ed25519().expect("test host key")],
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

    // Warm the authenticated channel first so the short test deadline measures
    // the hung command instead of depending on handshake scheduling.
    let completed = transport
        .exec_control("finish", /*input*/ None)
        .await
        .expect("control result");
    assert_eq!(
        (completed.output, completed.exit_code),
        (b"done".to_vec(), 7)
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), closed.notified()).await;
    let error = transport
        .exec_control_with_timeout("hang", /*input*/ None, Duration::from_millis(100))
        .await
        .err()
        .expect("hung control command must time out");
    assert_eq!(
        error.to_string(),
        "exec-server protocol error: ssh control command timed out; remote outcome is unknown"
    );
    tokio::time::timeout(Duration::from_secs(1), closed.notified())
        .await
        .expect("timed-out channel closed");
    assert_eq!(executions.load(Ordering::SeqCst), 2);
    assert_eq!(
        transport.pool.control_permits.available_permits(),
        SSH_CONTROL_OPERATIONS_PER_POOL
    );
    let completed = transport
        .exec_control("finish", /*input*/ None)
        .await
        .expect("later control result");
    assert_eq!(
        (completed.output, completed.exit_code),
        (b"done".to_vec(), 7)
    );
    assert_eq!(executions.load(Ordering::SeqCst), 3);

    let _ = shutdown.send(());
    server.await.expect("SSH server shutdown");
}

#[tokio::test]
async fn control_deadline_covers_a_server_that_never_finishes_ssh_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled server");
    let address = listener.local_addr().expect("stalled server address");
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
    let error = transport
        .exec_control_with_timeout(
            "must not run",
            /*input*/ None,
            Duration::from_millis(100),
        )
        .await
        .err()
        .expect("handshake must time out");
    assert_eq!(
        error.to_string(),
        "exec-server protocol error: ssh control channel acquisition timed out"
    );
    assert_eq!(
        transport.pool.control_permits.available_permits(),
        SSH_CONTROL_OPERATIONS_PER_POOL
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn control_deadline_covers_waiting_for_shared_pool_capacity() {
    let transport = SshTransport::new(
        uuid::Uuid::new_v4().to_string(),
        "127.0.0.1",
        1,
        "test",
        SshAuthentication::Password("test".to_string()),
        /*host_fingerprint*/ None,
    );
    let permits = transport
        .pool
        .control_permits
        .acquire_many(SSH_CONTROL_OPERATIONS_PER_POOL as u32)
        .await
        .expect("occupy pool");
    let error = transport
        .exec_control_with_timeout(
            "must not run",
            /*input*/ None,
            Duration::from_millis(10),
        )
        .await
        .err()
        .expect("pool wait must time out");
    assert_eq!(
        error.to_string(),
        "exec-server protocol error: ssh control channel acquisition timed out"
    );
    drop(permits);
    assert_eq!(
        transport.pool.control_permits.available_permits(),
        SSH_CONTROL_OPERATIONS_PER_POOL
    );
}

struct DelayedOpenServer {
    opens: Arc<AtomicUsize>,
    open_requested: Arc<Notify>,
    confirm_open: Arc<Notify>,
    abandoned_closed: Arc<Notify>,
    abandoned_channel: Option<ChannelId>,
}

#[async_trait]
impl server::Handler for DelayedOpenServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        if self.opens.fetch_add(1, Ordering::SeqCst) == 1 {
            self.abandoned_channel = Some(channel.id());
            self.open_requested.notify_one();
            self.confirm_open.notified().await;
        }
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.abandoned_channel == Some(channel) {
            self.abandoned_closed.notify_one();
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel);
        session.data(channel, CryptoVec::from_slice(b"sibling survived"));
        Ok(())
    }
}

#[tokio::test]
async fn cancelled_channel_open_closes_late_confirmation_and_preserves_shared_session() {
    check_cancelled_channel_open(/*cancel_after_confirmation*/ false).await;
}

#[tokio::test]
async fn cancelled_unread_channel_open_result_closes_channel_and_preserves_shared_session() {
    check_cancelled_channel_open(/*cancel_after_confirmation*/ true).await;
}

async fn check_cancelled_channel_open(cancel_after_confirmation: bool) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind SSH server");
    let address = listener.local_addr().expect("SSH server address");
    let opens = Arc::new(AtomicUsize::new(0));
    let open_requested = Arc::new(Notify::new());
    let confirm_open = Arc::new(Notify::new());
    let abandoned_closed = Arc::new(Notify::new());
    let handler = DelayedOpenServer {
        opens: Arc::clone(&opens),
        open_requested: Arc::clone(&open_requested),
        confirm_open: Arc::clone(&confirm_open),
        abandoned_closed: Arc::clone(&abandoned_closed),
        abandoned_channel: None,
    };
    let config = Arc::new(server::Config {
        keys: vec![russh::keys::key::KeyPair::generate_ed25519().expect("test host key")],
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let (shutdown, shutdown_requested) = oneshot::channel();
    let server = tokio::spawn(async move {
        // Accept exactly one TCP transport. A replacement connection cannot
        // make the later open succeed, so reuse is part of the assertion.
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
    let mut sibling = transport
        .open_work_channel()
        .await
        .expect("sibling channel");
    let slot = &transport.pool.slots[0];
    tokio::time::timeout(Duration::from_secs(1), async {
        while slot.open_permit.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sibling open delivered");
    let mut pending = Box::pin(transport.open_work_channel());
    assert!(
        std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context).is_pending()))
            .await
    );
    tokio::time::timeout(Duration::from_secs(1), open_requested.notified())
        .await
        .expect("second channel open reached server");
    assert_eq!(
        (
            slot.open_permit.available_permits(),
            slot.work_permits.available_permits(),
            opens.load(Ordering::SeqCst),
        ),
        (0, SSH_WORK_CHANNELS_PER_CONNECTION - 2, 2)
    );
    if cancel_after_confirmation {
        confirm_open.notify_one();
        // Under this test's current-thread runtime the owner restores the
        // session and publishes the result before yielding to delivery_finished.
        // Deliberately never poll the waiting caller again before dropping it.
        tokio::time::timeout(Duration::from_secs(1), async {
            while slot.session.lock().expect("session slot").is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("successful result published but unread");
        assert_eq!(slot.open_permit.available_permits(), 0);
        drop(pending);
    } else {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), pending.as_mut())
                .await
                .is_err()
        );
        drop(pending);
        // Repeated cancelled callers cannot start additional owned opens while
        // this slot's first confirmation is still pending.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), transport.open_work_channel())
                .await
                .is_err()
        );
        assert_eq!(opens.load(Ordering::SeqCst), 2);
        confirm_open.notify_one();
    }
    tokio::time::timeout(Duration::from_secs(1), abandoned_closed.notified())
        .await
        .expect("late abandoned channel closed remotely");
    tokio::time::timeout(Duration::from_secs(1), async {
        while slot.open_permit.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned open completed cleanup");
    assert_eq!(
        slot.work_permits.available_permits(),
        SSH_WORK_CHANNELS_PER_CONNECTION - 1
    );
    assert!(
        slot.session
            .lock()
            .expect("session slot")
            .as_ref()
            .is_some_and(|session| !session.is_closed())
    );
    sibling
        .channel()
        .exec(true, "probe")
        .await
        .expect("use established sibling");
    let output = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match sibling.channel_mut().wait().await {
                Some(ChannelMsg::Data { data }) => break data.to_vec(),
                Some(_) => {}
                None => panic!("sibling closed during abandoned-channel cleanup"),
            }
        }
    })
    .await
    .expect("sibling response");
    assert_eq!(output, b"sibling survived".to_vec());
    let later = tokio::time::timeout(Duration::from_secs(1), transport.open_work_channel())
        .await
        .expect("reuse existing TCP session")
        .expect("later channel");
    assert_eq!(opens.load(Ordering::SeqCst), 3);
    later.channel().close().await.expect("close later channel");
    sibling.channel().close().await.expect("close sibling");
    drop(later);
    drop(sibling);
    let _ = shutdown.send(());
    server.await.expect("SSH server shutdown");
}
