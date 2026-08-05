use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// Cross-process advisory lock for every mutation of one logical rollout.
///
/// Plain and compressed representations derive the same stable sidecar path.
pub(crate) struct RolloutLock {
    _file: File,
}

impl RolloutLock {
    pub(crate) fn acquire(path: &Path) -> io::Result<Self> {
        let plain_path = crate::compression::plain_rollout_path(path);
        let lock_path = lock_path(plain_path.as_path());
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        file.lock()?;
        Ok(Self { _file: file })
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}
