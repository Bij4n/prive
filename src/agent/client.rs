//! Talking to the agent from a command: start it, hand it a database, ask for entries, lock it.

use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::agent::proto::{Envelope, Request, Response, VERSION};
use crate::agent::{dir, frame};
use crate::entry::Entry;

/// First argument that turns the binary into the agent.
pub const AGENT_ARG: &str = "__agent";

/// What the agent said about a database.
pub enum Answer {
    /// The database as the agent holds it.
    Entries(Box<crate::db::Db>),
    /// Running, but not holding that database (or it changed on disk).
    Locked(String),
    NotRunning,
}

fn connect() -> Option<UnixStream> {
    let d = dir::agent_dir();
    // Never talk to a socket in a directory someone else could have prepared.
    dir::check_private(&d).ok()?;
    let s = UnixStream::connect(dir::socket_path()).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(10))).ok()?;
    Some(s)
}

/// Send one request. `Ok(None)` when no agent is running.
pub fn request(req: Request) -> Result<Option<Response>> {
    let Some(stream) = connect() else {
        return Ok(None);
    };
    let mut writer = stream.try_clone()?;
    frame::write(
        &mut writer,
        &Envelope {
            v: VERSION,
            body: req,
        },
    )?;
    let mut reader = BufReader::new(stream);
    match frame::read::<Envelope<Response>>(&mut reader)? {
        Some(env) if env.v == VERSION => Ok(Some(env.body)),
        Some(env) => bail!(
            "the agent speaks protocol {}, this prive {VERSION}; run `prive lock`",
            env.v
        ),
        None => bail!("the agent closed the connection"),
    }
}

pub fn entries(db: &Path) -> Result<Answer> {
    Ok(
        match request(Request::Entries {
            db: db.to_path_buf(),
        })? {
            None => Answer::NotRunning,
            Some(Response::Entries {
                entries,
                info,
                recycled,
            }) => Answer::Entries(Box::new(crate::db::Db {
                path: db.to_path_buf(),
                entries: entries.into_iter().map(Entry::from).collect(),
                info: *info,
                recycled,
            })),
            Some(Response::Locked { reason }) => Answer::Locked(reason),
            Some(Response::Error { message }) => bail!("agent: {message}"),
            Some(_) => bail!("agent: unexpected answer"),
        },
    )
}

/// Start the agent in the background, unless one is running. Returns once it is listening.
pub fn start(idle: Duration) -> Result<()> {
    if connect().is_some() {
        return Ok(());
    }
    let exe = std::env::current_exe().context("finding the prive executable")?;
    let mut cmd = Command::new(exe);
    cmd.args([AGENT_ARG, &idle.as_secs().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // a Ctrl-C in this terminal doesn't stop it
    }
    let mut child = cmd.spawn().context("starting the agent")?;
    let stdout = child.stdout.take().context("agent has no stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(line) if line.trim() == "ok" => Ok(()),
        Ok(line) if !line.trim().is_empty() => bail!("{}", line.trim().trim_start_matches("err: ")),
        _ => {
            let _ = child.kill();
            bail!("the agent did not start")
        }
    }
}

pub fn unlock(db: &Path, keyfile: Option<PathBuf>, password: Option<&str>) -> Result<()> {
    match request(Request::Unlock {
        db: db.to_path_buf(),
        keyfile,
        password: password.map(str::to_string),
    })? {
        Some(Response::Unlocked) => Ok(()),
        Some(Response::Error { message }) => bail!("{message}"),
        Some(_) => bail!("agent: unexpected answer"),
        None => bail!("the agent is not running"),
    }
}

/// Tell the agent to forget the database and exit. False if none was running.
pub fn lock() -> Result<bool> {
    Ok(request(Request::Lock)?.is_some())
}

/// The unlocked database and seconds until the agent locks itself, if it runs.
pub fn status() -> Result<Option<(Option<PathBuf>, u64)>> {
    Ok(match request(Request::Status)? {
        Some(Response::Status {
            db,
            idle_seconds_left,
        }) => Some((db, idle_seconds_left)),
        Some(_) => bail!("agent: unexpected answer"),
        None => None,
    })
}
