//! Copying a secret to the clipboard and clearing it again.
//!
//! A command-line process exits as soon as it has printed its result, which would take the
//! clipboard contents (on X11 and Wayland) or the pending clear (everywhere) with it. So `copy`
//! starts a small detached copy of this binary (`prive __clip`), hands it the secret over a
//! pipe, waits for it to confirm the copy worked, and returns. The helper keeps the clipboard
//! alive, then clears it after the timeout, but only if it still holds our secret: if you have
//! copied something else since, it is left alone.
//!

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub fn copy(secret: &str, seconds: u64) -> Result<()> {
    let exe = std::env::current_exe().context("finding the prive executable")?;
    let mut cmd = Command::new(exe);
    cmd.args(["__clip", "--seconds", &seconds.to_string()])
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

    let stdout = child
        .stdout
        .take()
        .context("clipboard helper has no stdout")?;
    let mut status = String::new();
    BufReader::new(stdout).read_line(&mut status)?;
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
    System(arboard::Clipboard),
}

impl Backend {
    fn open() -> Result<Backend> {
        arboard::Clipboard::new()
            .map(Backend::System)
            .context("no clipboard available")
    }

    fn set(&mut self, text: &str) -> Result<()> {
        let Backend::System(cb) = self;
        cb.set_text(text.to_string())
            .context("copying to the clipboard")
    }

    fn get(&mut self) -> Option<Zeroizing<String>> {
        let Backend::System(cb) = self;
        cb.get_text().ok().map(Zeroizing::new)
    }

    fn clear(&mut self) {
        let Backend::System(cb) = self;
        let _ = cb.clear();
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
