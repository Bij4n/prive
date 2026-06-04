//! The agent process: listen on the private socket, answer its own user, and exit when it
//! has been idle for the timeout or is told to lock.

use std::io::BufReader;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use crate::agent::proto::{Envelope, Request, Response, VERSION};
use crate::agent::state::State;
use crate::agent::{dir, frame, peer};

/// Run the agent until it is locked or idle for `idle`. `ready` is called once the socket is
/// listening, so whoever started the agent can stop waiting.
pub fn serve(idle: Duration, ready: impl FnOnce()) -> Result<()> {
    let socket_dir = dir::agent_dir();
    dir::ensure_private(&socket_dir)?;
    let path = dir::socket_path();
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            bail!("an agent is already running");
        }
        std::fs::remove_file(&path).context("removing a stale agent socket")?;
    }
    let listener = UnixListener::bind(&path).context("creating the agent socket")?;
    let result = run(&listener, idle, ready);
    let _ = std::fs::remove_file(&path);
    result
}

fn run(listener: &UnixListener, idle: Duration, ready: impl FnOnce()) -> Result<()> {
    let mut state = State::default();
    let mut deadline = Instant::now() + idle;
    ready();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(()); // idle too long: exit, which forgets the database
        }
        let wait = PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, wait) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("waiting for connections"),
        }
        let Ok((stream, _)) = listener.accept() else {
            continue;
        };
        if !peer::is_same_user(&stream) {
            continue; // not ours: say nothing
        }
        deadline = Instant::now() + idle;
        // A client that misbehaves only loses its own answer.
        if let Ok(true) = answer(stream, &mut state, deadline) {
            return Ok(());
        }
    }
}

/// Answer one connection. `Ok(true)` when the agent should stop.
fn answer(stream: UnixStream, state: &mut State, deadline: Instant) -> Result<bool> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let Some(req) = frame::read::<Envelope<Request>>(&mut reader)? else {
        return Ok(false);
    };
    if req.v != VERSION {
        frame::write(
            &mut writer,
            &Envelope {
                v: VERSION,
                body: Response::Error {
                    message: format!("protocol {} not supported (agent speaks {VERSION})", req.v),
                },
            },
        )?;
        return Ok(false);
    }
    let stop = matches!(req.body, Request::Lock);
    let mut resp = state.handle(req.body);
    if let Response::Status {
        idle_seconds_left, ..
    } = &mut resp
    {
        *idle_seconds_left = deadline.saturating_duration_since(Instant::now()).as_secs();
    }
    frame::write(
        &mut writer,
        &Envelope {
            v: VERSION,
            body: resp,
        },
    )?;
    Ok(stop)
}

/// True if an agent answers on the socket in `dir`.
pub fn is_running(socket: &Path) -> bool {
    UnixStream::connect(socket).is_ok()
}
