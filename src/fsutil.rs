//! Writing files that hold secrets: owner-only permissions, never a half-written file.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Create a new file at `path` from `bytes`, refusing to replace an existing one.
///
/// The data goes to a temporary file in the same directory (mode 0600 on Unix, so nobody else
/// can read it even for a moment), is flushed to disk, and is then renamed into place, so a
/// crash never leaves a truncated database behind.
pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(!path.exists(), "{} already exists", path.display());
    let dir = parent_dir(path);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let tmp = temp_path(path);
    let result = (|| -> Result<()> {
        let mut f = open_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        // Re-check right before the rename: on Unix rename would silently replace a file that
        // appeared in the meantime.
        anyhow::ensure!(!path.exists(), "{} already exists", path.display());
        fs::rename(&tmp, path)?;
        sync_dir(&dir);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database".into());
    parent_dir(path).join(format!(".{name}.prive-tmp-{}", std::process::id()))
}

fn open_private(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_once_and_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.kdbx");
        write_new_file(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        assert!(write_new_file(&p, b"two").is_err());
        assert_eq!(fs::read(&p).unwrap(), b"one");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("prive-tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn new_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.kdbx");
        write_new_file(&p, b"secret").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
