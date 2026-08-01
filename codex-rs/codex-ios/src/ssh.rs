//! Minimal SSH execution for "server-mode" nodes: connect to the user's machine
//! over SSH (pure-Rust `russh`, cross-compiles to iOS), authenticate with a
//! private key, run one command, and return its combined output + exit code.
//!
//! This is the engine behind the `ssh_exec` tool. Host key pinning is wired in
//! at integration time (the app stores the server's host fingerprint).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codex_exec_server::SshAuthentication;
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
    authentication: &SshAuthentication,
    host_fingerprint: Option<String>,
    local_path: &str,
    remote_path: &str,
) -> Result<(), String> {
    let mut local_file = tokio::fs::File::open(local_path)
        .await
        .map_err(|e| format!("open local file: {e}"))?;

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

    let authed = match authentication {
        SshAuthentication::PrivateKeyPath(key_path) => {
            let key_pair = load_secret_key(key_path, None).map_err(|e| format!("load key: {e}"))?;
            session
                .authenticate_publickey(user, Arc::new(key_pair))
                .await
        }
        SshAuthentication::Password(password) => {
            session.authenticate_password(user, password).await
        }
    }
    .map_err(|e| format!("auth: {e}"))?;
    if !authed {
        return Err("authentication failed (credential rejected)".to_string());
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
    tokio::io::copy(&mut local_file, &mut file)
        .await
        .map_err(|e| format!("stream remote file: {e}"))?;
    file.sync_all()
        .await
        .map_err(|e| format!("sync remote file: {e}"))?;
    file.shutdown()
        .await
        .map_err(|e| format!("finish remote file: {e}"))?;

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    Ok(())
}

/// Download one regular file from a server-mode workspace over SFTP.
///
/// Both the configured workspace and requested file are canonicalized by the
/// server before the containment check. This prevents `..` and symlink escapes
/// from turning the chat attachment tool into an arbitrary remote-file reader.
pub async fn ssh_download_workspace_file(
    host: &str,
    port: u16,
    user: &str,
    authentication: &SshAuthentication,
    host_fingerprint: Option<String>,
    workspace_path: &str,
    requested_path: &str,
    local_path: &str,
    max_bytes: u64,
) -> Result<u64, String> {
    if workspace_path.trim().is_empty() {
        return Err("remote workspace path is empty".to_string());
    }
    if requested_path.trim().is_empty() {
        return Err("remote file path is empty".to_string());
    }

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

    let authed = match authentication {
        SshAuthentication::PrivateKeyPath(key_path) => {
            let key_pair = load_secret_key(key_path, None).map_err(|e| format!("load key: {e}"))?;
            session
                .authenticate_publickey(user, Arc::new(key_pair))
                .await
        }
        SshAuthentication::Password(password) => {
            session.authenticate_password(user, password).await
        }
    }
    .map_err(|e| format!("auth: {e}"))?;
    if !authed {
        return Err("authentication failed (credential rejected)".to_string());
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

    let requested = std::path::Path::new(requested_path);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::path::Path::new(workspace_path).join(requested)
    };
    let canonical_workspace = sftp
        .canonicalize(workspace_path.to_string())
        .await
        .map_err(|e| format!("resolve remote workspace: {e}"))?;
    let canonical_file = sftp
        .canonicalize(candidate.to_string_lossy().into_owned())
        .await
        .map_err(|e| format!("resolve remote file: {e}"))?;
    if !std::path::Path::new(&canonical_file)
        .starts_with(std::path::Path::new(&canonical_workspace))
    {
        return Err("remote file resolves outside this agent's workspace".to_string());
    }

    let metadata = sftp
        .metadata(canonical_file.clone())
        .await
        .map_err(|e| format!("inspect remote file: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("remote path is not a regular file".to_string());
    }
    let size = metadata.size.unwrap_or(0);
    if size > max_bytes {
        return Err(format!(
            "remote file is too large ({size} bytes; limit is {max_bytes})"
        ));
    }

    let remote_file = sftp
        .open(canonical_file)
        .await
        .map_err(|e| format!("open remote file: {e}"))?;
    let partial_path = format!("{local_path}.partial");
    let _ = tokio::fs::remove_file(&partial_path).await;
    let mut local_file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&partial_path)
        .await
        .map_err(|e| format!("create partial download: {e}"))?;

    // Bound memory use and also enforce the limit if the server omitted or
    // changed the file size after the metadata check.
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut bounded_remote = remote_file.take(max_bytes.saturating_add(1));
    let copied = match tokio::io::copy(&mut bounded_remote, &mut local_file).await {
        Ok(copied) => copied,
        Err(error) => {
            drop(local_file);
            let _ = tokio::fs::remove_file(&partial_path).await;
            return Err(format!("stream remote file: {error}"));
        }
    };
    if copied > max_bytes {
        drop(local_file);
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(format!(
            "remote file is too large ({copied} bytes read; limit is {max_bytes})"
        ));
    }
    if let Err(error) = local_file.flush().await {
        drop(local_file);
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(format!("flush downloaded file: {error}"));
    }
    if let Err(error) = local_file.sync_all().await {
        drop(local_file);
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(format!("sync downloaded file: {error}"));
    }
    drop(local_file);
    if let Err(error) = tokio::fs::rename(&partial_path, local_path).await {
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(format!("finalize downloaded file: {error}"));
    }

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await
        .map_err(|e| format!("disconnect after download: {e}"));
    Ok(copied)
}
