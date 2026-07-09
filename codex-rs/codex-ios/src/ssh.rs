//! Minimal SSH execution for "server-mode" nodes: connect to the user's machine
//! over SSH (pure-Rust `russh`, cross-compiles to iOS), authenticate with a
//! private key, run one command, and return its combined output + exit code.
//!
//! This is the engine behind the `ssh_exec` tool. Host key pinning is wired in
//! at integration time (the app stores the server's host fingerprint).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::ChannelMsg;
use russh::Disconnect;
use russh::client;
use russh::keys::key;
use russh::keys::load_secret_key;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;

/// Result of a remote command: combined stdout+stderr and the exit code.
pub struct SshOutput {
    pub output: String,
    pub exit_code: u32,
}

struct Handler;

#[async_trait]
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO(integration): pin the server's host key (the app stores its
        // fingerprint) and reject mismatches. Accept for the host-test spike.
        Ok(true)
    }
}

struct PinnedHandler {
    expected_fingerprint: Option<String>,
}

#[async_trait]
impl client::Handler for PinnedHandler {
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

/// Connect to `host:port` as `user`, authenticate with the OpenSSH private key
/// at `key_path`, run `command`, and return its combined output + exit code.
pub async fn ssh_exec(
    host: &str,
    port: u16,
    user: &str,
    key_path: &str,
    command: &str,
) -> Result<SshOutput, String> {
    let key_pair = load_secret_key(key_path, None).map_err(|e| format!("load key: {e}"))?;

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let mut session = client::connect(config, (host, port), Handler)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let authed = session
        .authenticate_publickey(user, Arc::new(key_pair))
        .await
        .map_err(|e| format!("auth: {e}"))?;
    if !authed {
        return Err("authentication failed (publickey rejected)".to_string());
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("open channel: {e}"))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("exec: {e}"))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut exit_code: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => buf.extend_from_slice(data),
            ChannelMsg::ExtendedData { ref data, .. } => buf.extend_from_slice(data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            _ => {}
        }
    }

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;

    Ok(SshOutput {
        output: String::from_utf8_lossy(&buf).into_owned(),
        exit_code: exit_code.unwrap_or(0),
    })
}

/// Upload `local_path` to `remote_path` over SFTP using the same SSH settings as
/// server-mode turns. Parent directories are created best-effort.
pub async fn ssh_upload_file(
    host: &str,
    port: u16,
    user: &str,
    key_path: &str,
    host_fingerprint: Option<String>,
    local_path: &str,
    remote_path: &str,
) -> Result<(), String> {
    let bytes = tokio::fs::read(local_path)
        .await
        .map_err(|e| format!("read local file: {e}"))?;
    let key_pair = load_secret_key(key_path, None).map_err(|e| format!("load key: {e}"))?;

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    });
    let handler = PinnedHandler {
        expected_fingerprint: host_fingerprint,
    };
    let mut session = client::connect(config, (host, port), handler)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let authed = session
        .authenticate_publickey(user, Arc::new(key_pair))
        .await
        .map_err(|e| format!("auth: {e}"))?;
    if !authed {
        return Err("authentication failed (publickey rejected)".to_string());
    }

    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("open channel: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("request sftp subsystem: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("sftp handshake: {e}"))?;

    if let Some(parent) = std::path::Path::new(remote_path).parent() {
        let mut dirs = Vec::new();
        let mut cur = Some(parent);
        while let Some(path) = cur {
            if path.parent().is_none() {
                break;
            }
            dirs.push(path.to_string_lossy().into_owned());
            cur = path.parent();
        }
        dirs.reverse();
        for dir in dirs {
            let _ = sftp.create_dir(dir).await;
        }
    }

    let mut file = sftp
        .open_with_flags(
            remote_path.to_string(),
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(|e| format!("open remote file: {e}"))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&bytes)
        .await
        .map_err(|e| format!("write remote file: {e}"))?;
    file.shutdown()
        .await
        .map_err(|e| format!("finish remote file: {e}"))?;

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    Ok(())
}
