//! Where the master password and key file come from.
//!
//! Password sources, first match wins:
//! 1. `--password-stdin`: the first line of stdin.
//! 2. `PRIVE_PASSWORD_FILE`: the first line of that file.
//! 3. A hidden prompt, only when stdin is a terminal. Otherwise we fail at once instead of
//!    blocking on a prompt nobody can answer.
//!
//! There is deliberately no `PRIVE_PASSWORD` variable: environment variables are readable by
//! other processes of the same user through `/proc`.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::error::Failure;

#[derive(Debug, Clone, Default)]
pub struct KeySource {
    pub password_stdin: bool,
    /// Key-file-only database: don't ask for a password at all.
    pub no_password: bool,
    pub keyfile: Option<PathBuf>,
}

pub struct Credentials {
    pub password: Option<Zeroizing<String>>,
    pub keyfile: Option<PathBuf>,
}

impl KeySource {
    pub fn credentials(&self, db_path: &Path) -> Result<Credentials> {
        let password = if self.no_password {
            None
        } else {
            let name = db_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| db_path.display().to_string());
            Some(self.password(&format!("Password for {name}: "))?)
        };
        Ok(Credentials {
            password,
            keyfile: self.keyfile.clone(),
        })
    }

    /// Credentials for a resolved target: the target's key file, and the password from the
    /// first available source.
    pub fn for_target(
        global: &crate::cli::Global,
        target: &crate::config::Target,
    ) -> Result<Credentials> {
        KeySource {
            password_stdin: global.password_stdin,
            no_password: global.no_password,
            keyfile: target.keyfile.clone(),
        }
        .credentials(&target.db)
    }

    /// Ask for a new password twice (or read it once from a non-interactive source).
    pub fn new_password(&self) -> Result<Zeroizing<String>> {
        if self.password_stdin || std::env::var_os("PRIVE_PASSWORD_FILE").is_some() {
            return self.password("");
        }
        let first = self.password("New database password: ")?;
        let second = self.password("Repeat password: ")?;
        anyhow::ensure!(*first == *second, "the passwords do not match");
        Ok(first)
    }

    fn password(&self, prompt: &str) -> Result<Zeroizing<String>> {
        if self.password_stdin {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .context("reading the password from stdin")?;
            return Ok(trim_newline(line));
        }
        if let Some(file) = std::env::var_os("PRIVE_PASSWORD_FILE") {
            let text = Zeroizing::new(
                std::fs::read_to_string(&file)
                    .with_context(|| format!("reading PRIVE_PASSWORD_FILE {}", file.display()))?,
            );
            return Ok(first_line(&text));
        }
        if !std::io::stdin().is_terminal() {
            return Err(Failure::NoTerminal.into());
        }
        let pw = rpassword::prompt_password(prompt).context("reading the password")?;
        Ok(Zeroizing::new(pw))
    }
}

/// The first line of a password file, without its line ending. Later lines are ignored, so
/// a file can carry a comment underneath.
fn first_line(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.lines().next().unwrap_or("").to_string())
}

fn trim_newline(mut s: Zeroizing<String>) -> Zeroizing<String> {
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_unix_and_windows_newlines_only() {
        assert_eq!(*trim_newline(Zeroizing::new("pw\n".into())), "pw");
        assert_eq!(*trim_newline(Zeroizing::new("pw\r\n".into())), "pw");
        assert_eq!(*trim_newline(Zeroizing::new(" pw ".into())), " pw ");
    }

    #[test]
    fn password_files_use_their_first_line() {
        assert_eq!(*first_line("hunter2\nnotes below\n"), "hunter2");
        assert_eq!(*first_line("hunter2\r\n"), "hunter2");
        assert_eq!(*first_line(""), "");
    }

    #[test]
    fn key_file_only_databases_never_ask_for_a_password() {
        let src = KeySource {
            password_stdin: false,
            no_password: true,
            keyfile: Some(PathBuf::from("db.keyx")),
        };
        // No terminal in tests: if this tried to prompt it would fail with NoTerminal.
        let creds = src.credentials(Path::new("db.kdbx")).unwrap();
        assert!(creds.password.is_none());
        assert_eq!(creds.keyfile.as_deref(), Some(Path::new("db.keyx")));
    }
}
