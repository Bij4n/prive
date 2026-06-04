//! Who is on the other end of a socket. The agent only answers its own user: the private
//! directory already keeps others out, and this checks again on every connection.

use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

/// The user id of the process connected to `stream`.
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .context("reading the peer's credentials")?;
        Ok(cred.uid())
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        let (uid, _) = nix::unistd::getpeereid(stream).context("reading the peer's user id")?;
        Ok(uid.as_raw())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = stream;
        anyhow::bail!("can't check who is connecting on this system")
    }
}

/// True when the peer runs as the same user as this process.
pub fn is_same_user(stream: &UnixStream) -> bool {
    peer_uid(stream).is_ok_and(|uid| uid == nix::unistd::getuid().as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_pair_is_the_same_user() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), nix::unistd::getuid().as_raw());
        assert!(is_same_user(&b));
    }
}
