//! Where the agent's socket lives, and making sure nobody else can reach it.
//!
//! `$PRIVE_AGENT_DIR` if set, else `$XDG_RUNTIME_DIR/prive` (a per-user tmpfs on most Linux
//! systems), else `<temp dir>/prive-<uid>`. The directory must belong to us and be mode 0700;
//! if it exists with anything looser, prive refuses to use it rather than fix it silently.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub fn agent_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PRIVE_AGENT_DIR") {
        return PathBuf::from(d);
    }
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(d).join("prive");
    }
    std::env::temp_dir().join(format!("prive-{}", nix::unistd::getuid()))
}

pub fn socket_path() -> PathBuf {
    agent_dir().join("agent.sock")
}

/// Create the directory (0700) if needed, then check it is ours and private.
pub fn ensure_private(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    check_private(dir)
}

pub fn check_private(dir: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(dir).with_context(|| format!("checking {}", dir.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if meta.uid() != nix::unistd::getuid().as_raw() {
        bail!("{} belongs to another user; not using it", dir.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        bail!(
            "{} is mode {mode:o}; it must be 700 (chmod 700 it, or remove it)",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_a_private_directory() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("a/b/prive");
        ensure_private(&dir).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        ensure_private(&dir).unwrap(); // and again, once it exists
    }

    #[test]
    fn refuses_a_directory_others_can_open() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("prive");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let err = ensure_private(&dir).unwrap_err().to_string();
        assert!(err.contains("mode 755"), "{err}");
    }

    #[test]
    fn refuses_a_symlink() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        ensure_private(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(check_private(&link).is_err());
    }
}
