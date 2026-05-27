//! Copying a secret to the clipboard and clearing it again.
//!
//! A command-line process exits as soon as it has printed its result, which would take the
//! clipboard contents (on X11 and Wayland) or the pending clear (everywhere) with it. So `copy`
//! starts a small detached copy of this binary (`prive __clip <seconds>`), hands it the secret over a
//! pipe, waits for it to confirm the copy worked, and returns. The helper keeps the clipboard
//! alive, then clears it after the timeout, but only if it still holds our secret: if you have
//! copied something else since, it is left alone.
//!
//! Copies are marked as "don't keep in history" where the platform supports it. Some Linux
//! clipboard managers ignore that hint and keep a copy anyway.
//!
//! For tests, `PRIVE_CLIPBOARD_FILE=<path>` replaces the system clipboard with a file.
//!

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// First argument that turns the binary into the clipboard helper.
pub const HELPER_ARG: &str = "__clip";

pub fn copy(secret: &str, seconds: u64) -> Result<()> {
    let exe = std::env::current_exe().context("finding the prive executable")?;
    let mut cmd = Command::new(exe);
    cmd.args([HELPER_ARG, &seconds.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    detach(&mut cmd);
    let mut child = cmd.spawn().context("starting the clipboard helper")?;

    {
        let mut stdin = child
            .stdin
            .take()
            .context("clipboard helper has no stdin")?;
        stdin.write_all(secret.as_bytes())?;
    } // closing stdin tells the helper the secret is complete

    // The helper answers within a moment; if the clipboard itself hangs (a Wayland session
    // with no compositor answering, say), give up rather than hang the command.
    let stdout = child
        .stdout
        .take()
        .context("clipboard helper has no stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut status = String::new();
        let _ = BufReader::new(stdout).read_line(&mut status);
        let _ = tx.send(status);
    });
    let Ok(status) = rx.recv_timeout(Duration::from_secs(10)) else {
        let _ = child.kill();
        bail!("the clipboard did not respond within 10 seconds");
    };
    match status.trim() {
        "ok" => Ok(()),
        "" => bail!("the clipboard helper exited without copying"),
        other => bail!("{}", other.trim_start_matches("err: ")),
    }
}

/// Body of the hidden `prive __clip` command.
pub fn helper(seconds: u64) -> Result<()> {
    let mut secret = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut secret)?;
    let mut out = std::io::stdout();

    let mut backend = match Backend::open() {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(out, "err: {e:#}");
            return Ok(());
        }
    };
    if let Err(e) = backend.set(&secret) {
        let _ = writeln!(out, "err: {e:#}");
        return Ok(());
    }
    // The parent reads exactly one line, so it can return as soon as this is written.
    writeln!(out, "ok")?;
    out.flush()?;

    std::thread::sleep(Duration::from_secs(seconds));
    if backend.get().is_some_and(|now| *now == *secret) {
        backend.clear();
    }
    Ok(())
}

enum Backend {
    File(PathBuf),
    System(arboard::Clipboard),
}

impl Backend {
    fn open() -> Result<Backend> {
        if let Some(p) = std::env::var_os("PRIVE_CLIPBOARD_FILE") {
            return Ok(Backend::File(PathBuf::from(p)));
        }
        arboard::Clipboard::new()
            .map(Backend::System)
            .context("no clipboard available")
    }

    fn set(&mut self, text: &str) -> Result<()> {
        let cb = match self {
            Backend::File(p) => {
                return std::fs::write(p, text).context("writing the clipboard file");
            }
            Backend::System(cb) => cb,
        };
        let set = cb.set();
        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        #[cfg(windows)]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history()
                .exclude_from_cloud()
                .exclude_from_monitoring()
        };
        set.text(text.to_string())
            .context("copying to the clipboard")
    }

    fn get(&mut self) -> Option<Zeroizing<String>> {
        match self {
            Backend::File(p) => std::fs::read_to_string(p).ok().map(Zeroizing::new),
            Backend::System(cb) => cb.get_text().ok().map(Zeroizing::new),
        }
    }

    fn clear(&mut self) {
        match self {
            Backend::File(p) => {
                let _ = std::fs::write(p, "");
            }
            Backend::System(cb) => {
                let _ = cb.clear();
            }
        }
    }
}

#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Own process group: a Ctrl-C in the terminal after we return doesn't kill the helper.
    cmd.process_group(0);
}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(not(any(unix, windows)))]
fn detach(_cmd: &mut Command) {}
