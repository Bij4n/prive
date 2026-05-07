use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

pub struct VaultSync {
    repo_dir: PathBuf,
}

#[derive(Debug)]
pub struct SyncStatus {
    pub is_initialized: bool,
    pub has_remote: bool,
    pub last_sync: Option<DateTime<Utc>>,
    pub is_dirty: bool,
}

impl VaultSync {
    pub fn new(repo_dir: PathBuf) -> Self {
        Self { repo_dir }
    }

    /// Check if the data directory has been initialized as a git repo.
    pub fn is_initialized(&self) -> bool {
        self.repo_dir.join(".git").exists()
    }

    /// Initialize a git repo in the data directory, add a remote, and create a
    /// `.gitignore` that only tracks `*.pv` files.
    pub fn init(&self, remote_url: &str) -> Result<()> {
        if self.is_initialized() {
            anyhow::bail!("Sync is already initialized in {}", self.repo_dir.display());
        }

        std::fs::create_dir_all(&self.repo_dir).context("Failed to create data directory")?;

        self.run_git(&["init"])?;

        // Set repo-local identity if no global config exists, so commits work
        // on systems (e.g. CI runners) without a configured git identity.
        if self.run_git(&["config", "user.email"]).is_err() {
            let _ = self.run_git(&["config", "user.email", "prive-sync@localhost"]);
            let _ = self.run_git(&["config", "user.name", "Prive Sync"]);
        }

        // Create .gitignore that only tracks *.pv files
        let gitignore_path = self.repo_dir.join(".gitignore");
        std::fs::write(
            &gitignore_path,
            "# Only track encrypted vault files\n*\n!*.pv\n!.gitignore\n",
        )
        .context("Failed to write .gitignore")?;

        self.run_git(&["remote", "add", "origin", remote_url])?;

        // Initial commit with gitignore
        self.run_git(&["add", ".gitignore"])?;
        self.run_git(&["commit", "-m", "Initialize vault sync"])?;

        Ok(())
    }

    /// Stage all `.pv` files, commit with the given message, and push to the remote.
    pub fn push(&self, message: &str) -> Result<()> {
        self.ensure_initialized()?;

        self.run_git(&["add", "*.pv"])?;

        // Check if there is anything to commit
        let status_output = self.run_git(&["status", "--porcelain"])?;
        if status_output.trim().is_empty() {
            anyhow::bail!("Nothing to push — vault is up to date");
        }

        self.run_git(&["commit", "-m", message])?;
        self.run_git(&["push", "-u", "origin", "HEAD"])?;

        Ok(())
    }

    /// Pull the latest changes from the remote. Returns `true` if the vault
    /// file was updated.
    pub fn pull(&self) -> Result<bool> {
        self.ensure_initialized()?;

        // Record HEAD before pulling
        let head_before = self.run_git(&["rev-parse", "HEAD"]).unwrap_or_default();

        self.run_git(&["pull", "--rebase"])?;

        let head_after = self.run_git(&["rev-parse", "HEAD"]).unwrap_or_default();

        Ok(head_before.trim() != head_after.trim())
    }

    /// Return the current sync status.
    pub fn status(&self) -> Result<SyncStatus> {
        if !self.is_initialized() {
            return Ok(SyncStatus {
                is_initialized: false,
                has_remote: false,
                last_sync: None,
                is_dirty: false,
            });
        }

        let has_remote = self.run_git(&["remote", "get-url", "origin"]).is_ok();

        let last_sync = self
            .run_git(&["log", "-1", "--format=%aI"])
            .ok()
            .and_then(|s| {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    DateTime::parse_from_rfc3339(&trimmed)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                }
            });

        let is_dirty = self
            .run_git(&["status", "--porcelain"])
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        Ok(SyncStatus {
            is_initialized: true,
            has_remote,
            last_sync,
            is_dirty,
        })
    }

    // --- helpers ---

    fn ensure_initialized(&self) -> Result<()> {
        if !self.is_initialized() {
            anyhow::bail!("Sync not initialized. Run `prive sync init <remote-url>` first.");
        }
        Ok(())
    }

    fn run_git(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.repo_dir)
            .output()
            .with_context(|| format!("Failed to execute git {}", args.join(" ")))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("git {} failed: {}", args.join(" "), stderr.trim());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_temp_repo() -> (TempDir, VaultSync) {
        let dir = TempDir::new().unwrap();
        let sync = VaultSync::new(dir.path().to_path_buf());
        (dir, sync)
    }

    /// Create a bare remote repo and return its path.
    fn create_bare_remote() -> TempDir {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .args(["init", "--bare"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        dir
    }

    #[test]
    fn test_is_initialized_false_initially() {
        let (_dir, sync) = setup_temp_repo();
        assert!(!sync.is_initialized());
    }

    #[test]
    fn test_init_creates_git_repo() {
        let (_dir, sync) = setup_temp_repo();
        let remote = create_bare_remote();
        let remote_url = format!("file://{}", remote.path().display());

        sync.init(&remote_url).unwrap();

        assert!(sync.is_initialized());
        assert!(sync.repo_dir.join(".gitignore").exists());
    }

    #[test]
    fn test_init_twice_fails() {
        let (_dir, sync) = setup_temp_repo();
        let remote = create_bare_remote();
        let remote_url = format!("file://{}", remote.path().display());

        sync.init(&remote_url).unwrap();
        let result = sync.init(&remote_url);
        assert!(result.is_err());
    }

    #[test]
    fn test_status_uninitialized() {
        let (_dir, sync) = setup_temp_repo();
        let status = sync.status().unwrap();
        assert!(!status.is_initialized);
        assert!(!status.has_remote);
        assert!(status.last_sync.is_none());
        assert!(!status.is_dirty);
    }

    #[test]
    fn test_status_initialized() {
        let (_dir, sync) = setup_temp_repo();
        let remote = create_bare_remote();
        let remote_url = format!("file://{}", remote.path().display());

        sync.init(&remote_url).unwrap();

        let status = sync.status().unwrap();
        assert!(status.is_initialized);
        assert!(status.has_remote);
        assert!(status.last_sync.is_some());
        assert!(!status.is_dirty);
    }

    #[test]
    fn test_push_and_pull() {
        let (_dir, sync) = setup_temp_repo();
        let remote = create_bare_remote();
        let remote_url = format!("file://{}", remote.path().display());

        sync.init(&remote_url).unwrap();

        // Create a dummy .pv file
        std::fs::write(sync.repo_dir.join("test.pv"), b"encrypted-data").unwrap();

        sync.push("Add test vault").unwrap();

        // Pull should succeed (no changes)
        let changed = sync.pull().unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_push_nothing_fails() {
        let (_dir, sync) = setup_temp_repo();
        let remote = create_bare_remote();
        let remote_url = format!("file://{}", remote.path().display());

        sync.init(&remote_url).unwrap();

        let result = sync.push("Empty push");
        assert!(result.is_err());
    }
}
