//! What the agent holds and how it answers, apart from sockets (so it can be tested alone).
//!
//! It keeps one opened database. The password is used to open it and then dropped; what stays
//! in memory is the decrypted entries and a fingerprint of the file. If the file changes on
//! disk (KeePassXC saved it, Syncthing brought a new copy), the agent forgets everything and
//! asks to be unlocked again, rather than serve stale passwords.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::agent::proto::{Request, Response, WireEntry};
use crate::db::{self, Db};
use crate::entry::Entry;
use crate::error::Failure;
use crate::unlock::Credentials;

/// Enough to notice that a file was replaced or rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    len: u64,
    sha256: [u8; 32],
}

impl Fingerprint {
    pub fn of_bytes(bytes: &[u8]) -> Fingerprint {
        Fingerprint {
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    pub fn of_file(path: &Path) -> Option<Fingerprint> {
        std::fs::read(path).ok().map(|b| Fingerprint::of_bytes(&b))
    }
}

struct Open {
    db: PathBuf,
    fingerprint: Fingerprint,
    entries: Vec<Entry>,
    info: db::Info,
    recycled: Vec<String>,
}

#[derive(Default)]
pub struct State {
    open: Option<Open>,
}

/// Paths are compared after resolving `..`, symlinks and relative parts.
fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

impl State {
    pub fn database(&self) -> Option<&Path> {
        self.open.as_ref().map(|o| o.db.as_path())
    }

    pub fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::Unlock {
                db,
                keyfile,
                password,
            } => self.unlock(&db, keyfile, password.map(Zeroizing::new)),
            Request::Entries { db } => self.entries(&db),
            Request::Status => Response::Status {
                db: self.database().map(Path::to_path_buf),
                idle_seconds_left: 0,
            },
            Request::Lock => {
                self.open = None;
                Response::Bye
            }
        }
    }

    fn unlock(
        &mut self,
        path: &Path,
        keyfile: Option<PathBuf>,
        password: Option<Zeroizing<String>>,
    ) -> Response {
        let path = canonical(path);
        let bytes = match db::read_file(&path) {
            Ok(b) => b,
            Err(e) => {
                return Response::Error {
                    message: format!("{e:#}"),
                };
            }
        };
        let creds = Credentials { password, keyfile };
        match Db::from_bytes(&path, &bytes, &creds) {
            Ok(opened) => {
                self.open = Some(Open {
                    db: path,
                    fingerprint: Fingerprint::of_bytes(&bytes),
                    entries: opened.entries,
                    info: opened.info,
                    recycled: opened.recycled,
                });
                Response::Unlocked
            }
            Err(e) => {
                let message = match e.downcast_ref::<Failure>() {
                    Some(Failure::BadCredentials) => Failure::BadCredentials.to_string(),
                    _ => format!("{e:#}"),
                };
                Response::Error { message }
            }
        }
    }

    fn entries(&mut self, path: &Path) -> Response {
        let path = canonical(path);
        let Some(open) = &self.open else {
            return Response::Locked {
                reason: "no database is unlocked".into(),
            };
        };
        if open.db != path {
            return Response::Locked {
                reason: format!("{} is not the unlocked database", path.display()),
            };
        }
        if Fingerprint::of_file(&path).as_ref() != Some(&open.fingerprint) {
            self.open = None;
            return Response::Locked {
                reason: "the database changed on disk".into(),
            };
        }
        Response::Entries {
            entries: open.entries.iter().map(WireEntry::from).collect(),
            info: Box::new(open.info.clone()),
            recycled: open.recycled.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn unlock(state: &mut State, db: &Path, pw: &str) -> Response {
        state.handle(Request::Unlock {
            db: db.to_path_buf(),
            keyfile: None,
            password: Some(pw.into()),
        })
    }

    #[test]
    fn unlock_then_serve_entries() {
        let mut s = State::default();
        assert!(matches!(
            s.handle(Request::Entries {
                db: fixture("kdbx41.kdbx")
            }),
            Response::Locked { .. }
        ));
        assert!(matches!(
            unlock(&mut s, &fixture("kdbx41.kdbx"), "fixture-pass"),
            Response::Unlocked
        ));
        let Response::Entries {
            entries,
            info,
            recycled,
        } = s.handle(Request::Entries {
            db: fixture("kdbx41.kdbx"),
        })
        else {
            panic!("expected entries");
        };
        assert_eq!(entries.len(), 7);
        assert_eq!(info.format, "KDBX 4.1");
        assert_eq!(recycled.len(), 1);
        // Another database is not served from this one.
        assert!(matches!(
            s.handle(Request::Entries {
                db: fixture("kdbx31.kdbx")
            }),
            Response::Locked { .. }
        ));
    }

    #[test]
    fn a_wrong_password_keeps_it_locked() {
        let mut s = State::default();
        let Response::Error { message } = unlock(&mut s, &fixture("kdbx41.kdbx"), "nope") else {
            panic!("expected an error");
        };
        assert!(message.contains("wrong password"));
        assert!(s.database().is_none());
    }

    #[test]
    fn a_change_on_disk_locks_it() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("db.kdbx");
        std::fs::copy(fixture("kdbx41.kdbx"), &copy).unwrap();
        let mut s = State::default();
        unlock(&mut s, &copy, "fixture-pass");
        std::fs::copy(fixture("kdbx40.kdbx"), &copy).unwrap(); // "KeePassXC saved it"
        let Response::Locked { reason } = s.handle(Request::Entries { db: copy.clone() }) else {
            panic!("expected locked");
        };
        assert!(reason.contains("changed on disk"));
        assert!(s.database().is_none());
    }

    #[test]
    fn lock_forgets() {
        let mut s = State::default();
        unlock(&mut s, &fixture("kdbx41.kdbx"), "fixture-pass");
        assert!(matches!(s.handle(Request::Lock), Response::Bye));
        assert!(s.database().is_none());
    }
}
