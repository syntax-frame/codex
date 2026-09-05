use std::io;
use std::time::Duration;

use russh_sftp::client::SftpSession;
use tokio::io::DuplexStream;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio::time::timeout_at;

use super::PooledSshChannel;
use super::SshTransport;

const SFTP_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const SFTP_BRIDGE_CAPACITY: usize = 64 * 1024;
const SFTP_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) async fn connect_sftp(transport: &SshTransport) -> io::Result<SftpSession> {
    connect_with_timeout(transport, SFTP_STARTUP_TIMEOUT).await
}

async fn connect_with_timeout(
    transport: &SshTransport,
    timeout: Duration,
) -> io::Result<SftpSession> {
    let deadline = Instant::now() + timeout;
    let mut channel = timeout_at(deadline, transport.open_work_channel())
        .await
        .map_err(|_| startup_timeout())?
        .map_err(|error| io::Error::other(error.to_string()))?;
    // russh-sftp spawns detached readers/writers before initialization returns.
    // Retain the pooled SSH stream separately so cancellation can release it
    // even when one of those workers is blocked writing the initial packet.
    let (session_stream, bridge_stream) = tokio::io::duplex(SFTP_BRIDGE_CAPACITY);
    let (ready, readiness) = oneshot::channel();
    let supervisor = tokio::spawn(async move {
        let result = {
            let forwarding = async {
                channel
                    .channel()
                    .request_subsystem(/*want_reply*/ true, "sftp")
                    .await
                    .map_err(|error| {
                        io::Error::other(format!("ssh request sftp subsystem: {error}"))
                    })?;
                forward_session(&mut channel, bridge_stream).await;
                Ok(())
            };
            tokio::pin!(forwarding);
            tokio::select! {
                biased;
                result = readiness => {
                    if result.is_ok() {
                        // Normal filesystem transfers have no startup deadline.
                        forwarding.await
                    } else {
                        Ok(())
                    }
                }
                _ = tokio::time::sleep_until(deadline) => Err(startup_timeout()),
                result = &mut forwarding => result,
            }
        };
        // Dropping a russh channel releases local capacity but does not send
        // SSH_MSG_CHANNEL_CLOSE. Close it explicitly after releasing the copy
        // borrows, with a bound even when the transport's send queue is stuck.
        let _ = tokio::time::timeout(SFTP_CLOSE_TIMEOUT, channel.channel().close()).await;
        result
    });
    let result = timeout_at(deadline, SftpSession::new(session_stream)).await;
    match result {
        Ok(Ok(session)) => {
            if ready.send(()).is_err() {
                let _ = supervisor.await;
                return Err(if Instant::now() >= deadline {
                    startup_timeout()
                } else {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "ssh sftp startup stream closed",
                    )
                });
            }
            Ok(session)
        }
        result => {
            // Dropping this sender also closes the supervisor when the caller
            // cancels this future. Await normal error cleanup so no pool permit
            // remains held when a failed connection attempt returns.
            drop(ready);
            let supervision_result = supervisor.await;
            if Instant::now() >= deadline {
                return Err(startup_timeout());
            }
            if let Ok(Err(error)) = supervision_result {
                return Err(error);
            }
            match result {
                Ok(Err(russh_sftp::client::error::Error::Timeout)) => Err(startup_timeout()),
                Ok(Err(error)) => Err(io::Error::other(format!("sftp handshake: {error}"))),
                Err(_) => Err(startup_timeout()),
                Ok(Ok(_)) => unreachable!("successful initialization was handled above"),
            }
        }
    }
}

fn startup_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "ssh sftp startup timed out")
}

async fn forward_session(channel: &mut PooledSshChannel, bridge: DuplexStream) {
    let mut remote_write = channel.channel().make_writer();
    let mut remote_read = channel.channel_mut().make_reader();
    let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge);
    // SFTP does not retain useful half-open sessions. Stop on either EOF so
    // dropping an initialized session releases its permit even if the remote
    // server keeps its channel open forever.
    tokio::select! {
        _ = tokio::io::copy(&mut remote_read, &mut bridge_write) => {}
        _ = tokio::io::copy(&mut bridge_read, &mut remote_write) => {}
    }
}

#[cfg(test)]
#[path = "sftp_startup_tests.rs"]
mod tests;
