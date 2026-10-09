//! The instance lock: an advisory lock on `<state_dir>/hopae.lock`, held for
//! the life of the process. Two processes on one SQLite store are refused
//! (scenario 013-A2); the operating system drops the lock when the process dies.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::Context;

/// Another instance holds the lock.
#[derive(Debug, thiserror::Error)]
#[error("store locked by another instance")]
pub struct StoreLocked;

pub struct InstanceLock {
    _file: File,
}

/// Take the lock, creating `state_dir` (mode 0700) if needed.
pub fn acquire(state_dir: &Path) -> anyhow::Result<InstanceLock> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
        .with_context(|| format!("creating state directory {}", state_dir.display()))?;
    let path = state_dir.join("hopae.lock");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(InstanceLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(StoreLocked.into()),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_second_holder_is_refused_until_the_first_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let first = acquire(&state).unwrap();
        let err = acquire(&state).err().expect("second lock must fail");
        assert!(err.downcast_ref::<StoreLocked>().is_some(), "{err:#}");
        drop(first);
        acquire(&state).unwrap();
    }
}
