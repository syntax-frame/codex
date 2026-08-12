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
use sha2::Digest;
use sha2::Sha256;

/// Result of a remote command: combined stdout+stderr and the exit code.
pub struct SshOutput {
    pub output: String,
    pub exit_code: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshWorkspaceUploadReceipt {
    pub remote_path: String,
    pub size: u64,
    pub sha256: Vec<u8>,
    pub created: bool,
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

/// Atomically upload one regular file beneath an exact server workspace.
///
/// Every parent is created and canonicalized one component at a time, symlink
/// parents and destinations are rejected, and the final name becomes visible
/// only after a fully synced attempt-scoped temporary file is renamed. A retry
/// accepts an existing destination only after its size and SHA-256 exactly
/// match the local payload.
#[allow(clippy::too_many_arguments)]
pub async fn ssh_upload_workspace_file_atomic(
    host: &str,
    port: u16,
    user: &str,
    authentication: &SshAuthentication,
    host_fingerprint: Option<String>,
    local_path: &str,
    workspace_path: &str,
    relative_path: &str,
    attempt_id: &str,
    max_bytes: u64,
) -> Result<SshWorkspaceUploadReceipt, String> {
    if workspace_path.trim().is_empty() || !workspace_path.starts_with('/') {
        return Err("remote workspace must be a nonempty absolute path".to_string());
    }
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("remote upload path must be a normalized relative path".to_string());
    }
    if attempt_id.is_empty()
        || attempt_id
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err("remote upload attempt id is invalid".to_string());
    }
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

    let canonical_workspace = sftp
        .canonicalize(workspace_path.to_string())
        .await
        .map_err(|e| format!("canonicalize remote workspace: {e}"))?;
    if !canonical_workspace.starts_with('/') {
        return Err("canonical remote workspace was not absolute".to_string());
    }
    let workspace_metadata = sftp
        .metadata(canonical_workspace.clone())
        .await
        .map_err(|e| format!("inspect remote workspace: {e}"))?;
    if !workspace_metadata.is_dir() {
        return Err("remote workspace is not a directory".to_string());
    }

    let relative = std::path::Path::new(relative_path);
    let file_name = relative
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "remote upload filename is invalid".to_string())?;
    let parent = relative
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let mut canonical_parent = canonical_workspace.clone();
    for component in parent.components() {
        let component = component.as_os_str().to_string_lossy();
        let candidate = format!("{canonical_parent}/{component}");
        if !sftp
            .try_exists(candidate.clone())
            .await
            .map_err(|e| format!("inspect remote upload parent: {e}"))?
        {
            sftp.create_dir(candidate.clone())
                .await
                .map_err(|e| format!("create remote upload parent: {e}"))?;
        }
        let metadata = sftp
            .symlink_metadata(candidate.clone())
            .await
            .map_err(|e| format!("inspect remote upload parent: {e}"))?;
        if metadata.is_symlink() || !metadata.is_dir() {
            return Err("remote upload parent is not a non-symlink directory".to_string());
        }
        let resolved = sftp
            .canonicalize(candidate)
            .await
            .map_err(|e| format!("canonicalize remote upload parent: {e}"))?;
        if !std::path::Path::new(&resolved).starts_with(&canonical_workspace) {
            return Err("remote upload parent escapes the configured workspace".to_string());
        }
        canonical_parent = resolved;
    }

    let remote_path = format!("{canonical_parent}/{file_name}");
    let temporary_path = format!("{canonical_parent}/.agentapp-upload-{attempt_id}");
    if sftp
        .try_exists(temporary_path.clone())
        .await
        .map_err(|e| format!("inspect remote temporary file: {e}"))?
    {
        return Err("remote upload attempt already exists".to_string());
    }

    let mut remote_file = sftp
        .open_with_flags(
            temporary_path.clone(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        )
        .await
        .map_err(|e| format!("open remote file: {e}"))?;
    let upload_result = async {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = local_file
                .read(&mut buffer)
                .await
                .map_err(|e| format!("read local file: {e}"))?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .ok_or_else(|| "local upload size overflowed".to_string())?;
            if copied > max_bytes {
                return Err(format!("local upload exceeds {max_bytes} bytes"));
            }
            digest.update(&buffer[..read]);
            remote_file
                .write_all(&buffer[..read])
                .await
                .map_err(|e| format!("stream remote file: {e}"))?;
        }
        remote_file
            .sync_all()
            .await
            .map_err(|e| format!("sync remote file: {e}"))?;
        remote_file
            .shutdown()
            .await
            .map_err(|e| format!("finish remote file: {e}"))?;
        let expected_digest = digest.finalize().to_vec();

        if remote_regular_file_matches(&sftp, &remote_path, copied, &expected_digest).await? {
            sftp.remove_file(temporary_path.clone())
                .await
                .map_err(|e| format!("remove duplicate temporary upload: {e}"))?;
            return Ok(SshWorkspaceUploadReceipt {
                remote_path: remote_path.clone(),
                size: copied,
                sha256: expected_digest,
                created: false,
            });
        }
        if sftp
            .try_exists(remote_path.clone())
            .await
            .map_err(|e| format!("inspect remote destination: {e}"))?
        {
            return Err("remote destination exists with different content or type".to_string());
        }

        match sftp
            .rename(temporary_path.clone(), remote_path.clone())
            .await
        {
            Ok(()) => Ok(SshWorkspaceUploadReceipt {
                remote_path: remote_path.clone(),
                size: copied,
                sha256: expected_digest,
                created: true,
            }),
            Err(_rename_error)
                if remote_regular_file_matches(&sftp, &remote_path, copied, &expected_digest)
                    .await? =>
            {
                let _ = sftp.remove_file(temporary_path.clone()).await;
                Ok(SshWorkspaceUploadReceipt {
                    remote_path: remote_path.clone(),
                    size: copied,
                    sha256: expected_digest,
                    // A concurrent retry may have committed the exact bytes.
                    // Do not claim deletion authority when rename lost the race.
                    created: false,
                })
            }
            Err(rename_error) => Err(format!("commit remote upload: {rename_error}")),
        }
    }
    .await;

    if upload_result.is_err() {
        let _ = sftp.remove_file(temporary_path).await;
    }
    let receipt = upload_result?;

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    Ok(receipt)
}

/// Compensates a newly-created exact upload after the enclosing steering
/// transaction is rejected. Pre-existing idempotent destinations are never
/// removed, and a changed destination remains untouched.
#[allow(clippy::too_many_arguments)]
pub async fn ssh_rollback_workspace_file_upload(
    host: &str,
    port: u16,
    user: &str,
    authentication: &SshAuthentication,
    host_fingerprint: Option<String>,
    workspace_path: &str,
    receipt: &SshWorkspaceUploadReceipt,
) -> Result<(), String> {
    if !receipt.created {
        return Ok(());
    }
    if workspace_path.trim().is_empty() || !workspace_path.starts_with('/') {
        return Err("remote workspace must be a nonempty absolute path".to_string());
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
        .map_err(|e| format!("connect rollback: {e}"))?;
    let authed = match authentication {
        SshAuthentication::PrivateKeyPath(key_path) => {
            let key_pair =
                load_secret_key(key_path, None).map_err(|e| format!("load rollback key: {e}"))?;
            session
                .authenticate_publickey(user, Arc::new(key_pair))
                .await
        }
        SshAuthentication::Password(password) => {
            session.authenticate_password(user, password).await
        }
    }
    .map_err(|e| format!("rollback auth: {e}"))?;
    if !authed {
        return Err("rollback authentication failed".to_string());
    }
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("open rollback channel: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("request rollback sftp subsystem: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("rollback sftp handshake: {e}"))?;

    let canonical_workspace = sftp
        .canonicalize(workspace_path.to_string())
        .await
        .map_err(|e| format!("canonicalize rollback workspace: {e}"))?;
    let canonical_remote = match sftp.canonicalize(receipt.remote_path.clone()).await {
        Ok(path) => path,
        Err(_error)
            if !sftp
                .try_exists(receipt.remote_path.clone())
                .await
                .map_err(|e| format!("inspect rollback destination: {e}"))? =>
        {
            let _ = session
                .disconnect(Disconnect::ByApplication, "", "English")
                .await;
            return Ok(());
        }
        Err(error) => return Err(format!("canonicalize rollback destination: {error}")),
    };
    if !std::path::Path::new(&canonical_remote).starts_with(&canonical_workspace)
        || canonical_remote == canonical_workspace
    {
        return Err("rollback destination escapes the configured workspace".to_string());
    }
    if !remote_regular_file_matches(&sftp, &canonical_remote, receipt.size, &receipt.sha256).await?
    {
        return Err("rollback destination changed after upload".to_string());
    }
    sftp.remove_file(canonical_remote)
        .await
        .map_err(|e| format!("remove rollback destination: {e}"))?;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
    Ok(())
}

async fn remote_regular_file_matches(
    sftp: &SftpSession,
    path: &str,
    expected_size: u64,
    expected_digest: &[u8],
) -> Result<bool, String> {
    if !sftp
        .try_exists(path.to_string())
        .await
        .map_err(|e| format!("inspect remote destination: {e}"))?
    {
        return Ok(false);
    }
    let metadata = sftp
        .symlink_metadata(path.to_string())
        .await
        .map_err(|e| format!("inspect remote destination: {e}"))?;
    if metadata.is_symlink() || !metadata.is_regular() || metadata.len() != expected_size {
        return Ok(false);
    }

    use tokio::io::AsyncReadExt;
    let mut file = sftp
        .open(path.to_string())
        .await
        .map_err(|e| format!("open existing remote destination: {e}"))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|e| format!("read existing remote destination: {e}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().as_slice() == expected_digest)
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
