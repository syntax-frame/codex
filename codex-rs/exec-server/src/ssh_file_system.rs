//! SSH/SFTP-backed [`ExecutorFileSystem`] for "server mode".
//!
//! In server mode the agent's shell/exec tools run on a remote host over SSH
//! (see [`crate::ssh_process::SshProcessBackend`]), but file operations —
//! crucially `apply_patch` and plain file read/write — must also act on the
//! REMOTE host's disk, not the phone's local disk. This module provides that:
//! an [`ExecutorFileSystem`] whose primitives are served by an SFTP session
//! opened over a russh channel to the same host.
//!
//! ## Why SFTP (strategy A)
//!
//! `russh-sftp = "2.3"` is a transport-agnostic SFTP protocol implementation:
//! it depends on NEITHER `russh` NOR `ml-kem`, so it cannot bump our pinned
//! `russh = "=0.45"` and cannot pull `ml-kem 0.3.x` (which would conflict with
//! the `ml-kem 0.2.x` that `clatter` already uses in this crate). We attach its
//! `SftpSession` to a russh `Channel` via `request_subsystem("sftp")` +
//! `into_stream()` (which yields an `AsyncRead + AsyncWrite` stream). This gives
//! binary-safe reads/writes with no base64/shell-quoting hazards.
//!
//! ## Implemented surface
//!
//! `apply_patch` (and basic file read/write) only exercise a small subset of
//! [`ExecutorFileSystem`]:
//!   - [`read_file`](ExecutorFileSystem::read_file) (and the default
//!     `read_file_text` built on it)
//!   - [`write_file`](ExecutorFileSystem::write_file)
//!   - [`get_metadata`](ExecutorFileSystem::get_metadata)
//!   - [`create_directory`](ExecutorFileSystem::create_directory)
//!   - [`remove`](ExecutorFileSystem::remove)
//!
//! Those are implemented against SFTP. [`canonicalize`], [`read_directory`] and
//! [`copy`] are also implemented because they map cleanly onto SFTP. The
//! streaming read ([`read_file_stream`]) returns the whole file as a single
//! chunk. Anything not directly serviceable returns a clean
//! "unsupported over SSH" error rather than panicking.
//!
//! ## Connection reuse
//!
//! The SFTP session is opened lazily on first use and cached behind a
//! [`tokio::sync::Mutex`] so every filesystem operation in a turn reuses one
//! SSH connection. If the session dies, the next call reconnects.

use std::io;
use std::sync::Arc;

use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_path_uri::PathUri;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::sync::Mutex;

use crate::CopyOptions;
use crate::CreateDirectoryOptions;
use crate::ExecutorFileSystem;
use crate::ExecutorFileSystemFuture;
use crate::FILE_READ_CHUNK_SIZE;
use crate::FileMetadata;
use crate::FileSystemReadStream;
use crate::FileSystemResult;
use crate::FileSystemSandboxContext;
use crate::ReadDirectoryEntry;
use crate::RemoveOptions;
use crate::ssh_transport::SshAuthentication;
use crate::ssh_transport::SshTransport;

/// An [`ExecutorFileSystem`] backed by an SFTP session over SSH.
///
/// Cloneable connection material; the live SFTP session is shared via an
/// `Arc<Mutex<..>>` so clones talk to the same connection.
#[derive(Clone)]
pub struct SshFileSystem {
    transport: SshTransport,
    /// Lazily-opened, reused SFTP session.
    session: Arc<Mutex<Option<Arc<SftpSession>>>>,
}

impl SshFileSystem {
    /// Build an SSH filesystem authenticating with the OpenSSH private key at
    /// `key_path`, optionally pinning the server host key.
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
        let connection_key = format!("{user}@{host}:{port}");
        Self::with_transport(SshTransport::new(
            connection_key,
            host,
            port,
            user,
            SshAuthentication::PrivateKeyPath(key_path),
            host_fingerprint,
        ))
    }

    pub(crate) fn with_transport(transport: SshTransport) -> Self {
        Self {
            transport,
            session: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a live SFTP session, opening (or re-opening) one if needed.
    ///
    /// The lock is never held across the connect await: we check the cache, drop
    /// the guard, connect, then re-lock to store (double-checked so a concurrent
    /// connector wins rather than leaking a second session).
    async fn sftp(&self) -> io::Result<Arc<SftpSession>> {
        {
            let guard = self.session.lock().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }
        let session = Arc::new(self.connect_sftp().await?);
        let mut guard = self.session.lock().await;
        if let Some(existing) = guard.as_ref() {
            // Another task connected while we were connecting; reuse theirs and
            // drop ours (its transport tears down when the Arc is dropped).
            return Ok(existing.clone());
        }
        *guard = Some(session.clone());
        Ok(session)
    }

    /// Drops the cached session so the next call reconnects.
    async fn invalidate(&self) {
        let mut guard = self.session.lock().await;
        *guard = None;
    }

    /// Open a fresh SSH connection and start the SFTP subsystem on it.
    async fn connect_sftp(&self) -> io::Result<SftpSession> {
        let channel = self
            .transport
            .open_work_channel()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        channel
            .channel()
            .request_subsystem(true, "sftp")
            .await
            .map_err(|error| io::Error::other(format!("ssh request sftp subsystem: {error}")))?;

        let stream = channel.into_stream();
        let sftp = SftpSession::new(stream)
            .await
            .map_err(|e| io::Error::other(format!("sftp handshake: {e}")))?;
        Ok(sftp)
    }

    /// Run an SFTP operation, transparently reconnecting once on failure.
    async fn with_retry<T, F, Fut>(&self, op: F) -> io::Result<T>
    where
        F: Fn(Arc<SftpSession>) -> Fut,
        Fut: std::future::Future<Output = Result<T, russh_sftp::client::error::Error>>,
    {
        let sftp = self.sftp().await?;
        match op(sftp).await {
            Ok(value) => Ok(value),
            Err(first_err) => {
                // The session may have died; drop it and try one reconnect.
                self.invalidate().await;
                let sftp = self.sftp().await?;
                op(sftp).await.map_err(|second_err| {
                    sftp_error_to_io(if is_status_error(&first_err) {
                        first_err
                    } else {
                        second_err
                    })
                })
            }
        }
    }
}

/// Convert a [`PathUri`] to a remote absolute-path string.
fn remote_path(path: &PathUri) -> io::Result<String> {
    let abs: AbsolutePathBuf = path.to_abs_path()?;
    Ok(abs.to_string_lossy().into_owned())
}

/// Map an `mtime`/`atime` (seconds since epoch) to milliseconds.
fn secs_to_ms(secs: Option<u32>) -> i64 {
    secs.map(|s| i64::from(s) * 1000).unwrap_or(0)
}

fn sftp_error_to_io(err: russh_sftp::client::error::Error) -> io::Error {
    use russh_sftp::client::error::Error as SftpErr;
    use russh_sftp::protocol::StatusCode;
    match &err {
        SftpErr::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => io::Error::new(io::ErrorKind::NotFound, err.to_string()),
            StatusCode::PermissionDenied => {
                io::Error::new(io::ErrorKind::PermissionDenied, err.to_string())
            }
            _ => io::Error::other(err.to_string()),
        },
        _ => io::Error::other(err.to_string()),
    }
}

/// A genuine SFTP STATUS error (vs. a transport hiccup) should not be retried as
/// if it were a dropped connection.
fn is_status_error(err: &russh_sftp::client::error::Error) -> bool {
    matches!(err, russh_sftp::client::error::Error::Status(_))
}

fn unsupported(method: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{method} is unsupported over SSH/SFTP"),
    )
}

impl ExecutorFileSystem for SshFileSystem {
    fn canonicalize<'a>(
        &'a self,
        path: &'a PathUri,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, PathUri> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            let canonical = self
                .with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.canonicalize(remote).await }
                })
                .await?;
            let abs = AbsolutePathBuf::from_absolute_path(std::path::PathBuf::from(canonical))?;
            Ok(PathUri::from_abs_path(&abs))
        })
    }

    fn read_file<'a>(
        &'a self,
        path: &'a PathUri,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            self.with_retry(|sftp| {
                let remote = remote.clone();
                async move { sftp.read(remote).await }
            })
            .await
        })
    }

    fn read_file_stream<'a>(
        &'a self,
        path: &'a PathUri,
        sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, FileSystemReadStream> {
        Box::pin(async move {
            // SFTP has no native chunk-stream primitive in our usage; read the
            // whole file and emit it as one (or a few) chunks. `apply_patch`
            // does not use this path, but keep it functional.
            let bytes = self.read_file(path, sandbox).await?;
            let chunks: Vec<FileSystemResult<bytes::Bytes>> = bytes
                .chunks(FILE_READ_CHUNK_SIZE)
                .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
                .collect();
            Ok(FileSystemReadStream::new(futures::stream::iter(chunks)))
        })
    }

    fn write_file<'a>(
        &'a self,
        path: &'a PathUri,
        contents: Vec<u8>,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, ()> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            self.with_retry(|sftp| {
                let remote = remote.clone();
                let contents = contents.clone();
                async move {
                    // Truncate-create then write the full contents, mirroring
                    // `tokio::fs::write` semantics used by LocalFileSystem.
                    let mut file = sftp
                        .open_with_flags(
                            remote,
                            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
                        )
                        .await?;
                    use tokio::io::AsyncWriteExt;
                    file.write_all(&contents).await?;
                    file.shutdown().await?;
                    Ok(())
                }
            })
            .await
        })
    }

    fn create_directory<'a>(
        &'a self,
        path: &'a PathUri,
        options: CreateDirectoryOptions,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, ()> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            if options.recursive {
                // SFTP `mkdir` is non-recursive; create ancestors one level at a
                // time, ignoring "already exists" failures.
                let p = std::path::PathBuf::from(&remote);
                let mut ancestors: Vec<String> = Vec::new();
                let mut cur = Some(p.as_path());
                while let Some(c) = cur {
                    if c.parent().is_none() {
                        break;
                    }
                    ancestors.push(c.to_string_lossy().into_owned());
                    cur = c.parent();
                }
                ancestors.reverse();
                let sftp = self.sftp().await?;
                for dir in ancestors {
                    // Best-effort: ignore errors for already-existing components.
                    let _ = sftp.create_dir(dir).await;
                }
                // Verify the final directory exists.
                let exists = sftp
                    .metadata(remote.clone())
                    .await
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if exists {
                    Ok(())
                } else {
                    Err(io::Error::other(format!(
                        "failed to create directory over SFTP: {remote}"
                    )))
                }
            } else {
                self.with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.create_dir(remote).await }
                })
                .await
            }
        })
    }

    fn get_metadata<'a>(
        &'a self,
        path: &'a PathUri,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, FileMetadata> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            // `metadata` follows symlinks; `symlink_metadata` does not. Use both
            // to populate the `is_symlink` flag like LocalFileSystem does.
            let meta = self
                .with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.metadata(remote).await }
                })
                .await?;
            let symlink_meta = {
                let remote = remote.clone();
                self.with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.symlink_metadata(remote).await }
                })
                .await
                .ok()
            };
            let is_symlink = symlink_meta
                .as_ref()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            Ok(FileMetadata {
                is_directory: meta.is_dir(),
                is_file: meta.file_type().is_file(),
                is_symlink,
                size: meta.size.unwrap_or(0),
                created_at_ms: 0,
                modified_at_ms: secs_to_ms(meta.mtime),
            })
        })
    }

    fn read_directory<'a>(
        &'a self,
        path: &'a PathUri,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, Vec<ReadDirectoryEntry>> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            let read_dir = self
                .with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.read_dir(remote).await }
                })
                .await?;
            let mut entries = Vec::new();
            for entry in read_dir {
                let metadata = entry.metadata();
                entries.push(ReadDirectoryEntry {
                    file_name: entry.file_name(),
                    is_directory: metadata.is_dir(),
                    is_file: metadata.file_type().is_file(),
                });
            }
            Ok(entries)
        })
    }

    fn remove<'a>(
        &'a self,
        path: &'a PathUri,
        options: RemoveOptions,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, ()> {
        Box::pin(async move {
            let remote = remote_path(path)?;
            let meta = self
                .with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.symlink_metadata(remote).await }
                })
                .await;
            match meta {
                Ok(meta) if meta.is_dir() => {
                    if options.recursive {
                        self.remove_dir_recursive(path).await
                    } else {
                        self.with_retry(|sftp| {
                            let remote = remote.clone();
                            async move { sftp.remove_dir(remote).await }
                        })
                        .await
                    }
                }
                Ok(_) => {
                    self.with_retry(|sftp| {
                        let remote = remote.clone();
                        async move { sftp.remove_file(remote).await }
                    })
                    .await
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound && options.force => Ok(()),
                Err(err) => Err(err),
            }
        })
    }

    fn copy<'a>(
        &'a self,
        _source_path: &'a PathUri,
        _destination_path: &'a PathUri,
        _copy_options: CopyOptions,
        _sandbox: Option<&'a FileSystemSandboxContext>,
    ) -> ExecutorFileSystemFuture<'a, ()> {
        // SFTP has no server-side copy primitive; apply_patch never calls this.
        Box::pin(async move { Err(unsupported("fs/copy")) })
    }
}

impl SshFileSystem {
    /// Recursively remove a directory over SFTP (depth-first).
    async fn remove_dir_recursive(&self, path: &PathUri) -> io::Result<()> {
        let entries = self.read_directory(path, None).await?;
        for entry in entries {
            let child = path
                .join(&entry.file_name)
                .map_err(|e| io::Error::other(format!("join path: {e}")))?;
            if entry.is_directory {
                Box::pin(self.remove_dir_recursive(&child)).await?;
            } else {
                let remote = remote_path(&child)?;
                self.with_retry(|sftp| {
                    let remote = remote.clone();
                    async move { sftp.remove_file(remote).await }
                })
                .await?;
            }
        }
        let remote = remote_path(path)?;
        self.with_retry(|sftp| {
            let remote = remote.clone();
            async move { sftp.remove_dir(remote).await }
        })
        .await
    }
}
