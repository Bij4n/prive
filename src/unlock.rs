//! Where the master password and key file come from.
//!
//! Password sources, first match wins:
//! 1. `--password-stdin`: the first line of stdin.
//! 2. `PRIVE_PASSWORD_FILE`: the first line of that file.
//! 3. The database's `password_command` from the config file: the first line it prints. It is
//!    run without a shell, with this terminal for its input and errors (so `pass` or a
//!    pinentry can still ask), and only its output is read.
//! 4. A hidden prompt, only when stdin is a terminal. Otherwise we fail at once instead of
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
    /// The config file's `password_command` for this database.
    pub password_command: Option<Vec<String>>,
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
            password_command: target.password_command.clone(),
        }
        .credentials(&target.db)
    }

    /// Ask for a new password twice (or read it once from a non-interactive source).
    pub fn new_password(&self) -> Result<Zeroizing<String>> {
        if self.password_stdin
            || std::env::var_os("PRIVE_PASSWORD_FILE").is_some()
            || self.password_command.is_some()
        {
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
        if let Some(cmd) = &self.password_command {
            return run_password_command(cmd);
        }
        if !std::io::stdin().is_terminal() {
            return Err(Failure::NoTerminal.into());
        }
        let pw = rpassword::prompt_password(prompt).context("reading the password")?;
        Ok(Zeroizing::new(pw))
    }
}

/// Run `password_command` and take the first line it prints. Its output is held in memory
/// that is wiped when freed; it never passes through a shell.
fn run_password_command(cmd: &[String]) -> Result<Zeroizing<String>> {
    let (program, args) = cmd
        .split_first()
        .context("password_command needs a program to run")?;
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .with_context(|| format!("running password_command {program}"))?;
    let bytes = Zeroizing::new(out.stdout);
    anyhow::ensure!(
        out.status.success(),
        "password_command {program} failed ({})",
        out.status
    );
    let text =
        std::str::from_utf8(&bytes).context("password_command printed something not UTF-8")?;
    let line = first_line(text);
    anyhow::ensure!(
        !line.is_empty(),
        "password_command {program} printed no password"
    );
    Ok(line)
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
            password_command: None,
        };
        // No terminal in tests: if this tried to prompt it would fail with NoTerminal.
        let creds = src.credentials(Path::new("db.kdbx")).unwrap();
        assert!(creds.password.is_none());
        assert_eq!(creds.keyfile.as_deref(), Some(Path::new("db.keyx")));
    }

    #[cfg(unix)]
    #[test]
    fn a_password_command_gives_its_first_line() {
        let cmd = |args: &[&str]| KeySource {
            password_command: Some(args.iter().map(|a| a.to_string()).collect()),
            ..KeySource::default()
        };
        if std::env::var_os("PRIVE_PASSWORD_FILE").is_some() {
            return; // that one would win
        }
        let creds = cmd(&["printf", "%s\\n%s\\n", "from-command", "second line"])
            .credentials(Path::new("db.kdbx"))
            .unwrap();
        assert_eq!(
            creds.password.as_deref().map(String::as_str),
            Some("from-command")
        );
        assert!(cmd(&["false"]).credentials(Path::new("db.kdbx")).is_err());
        assert!(
            cmd(&["true"]).credentials(Path::new("db.kdbx")).is_err(),
            "no output"
        );
        let missing = cmd(&["prive-no-such-program"])
            .credentials(Path::new("db.kdbx"))
            .err()
            .unwrap();
        assert!(format!("{missing:#}").contains("prive-no-such-program"));
    }
}
