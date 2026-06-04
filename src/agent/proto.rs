//! What the client and the agent say to each other: one JSON object per line, each way.
//! Every request carries the protocol version; an agent that speaks another version is
//! treated as absent (the client asks for the password as usual).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entry::{CustomField, Entry};

pub const VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub v: u32,
    #[serde(flatten)]
    pub body: T,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Open this database and keep it. The password is used once and dropped.
    Unlock {
        db: PathBuf,
        keyfile: Option<PathBuf>,
        password: Option<String>,
    },
    /// Every entry of the open database, if it is `db` and unchanged on disk.
    Entries {
        db: PathBuf,
    },
    Status,
    /// Forget the database and exit.
    Lock,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Unlock { db, keyfile, .. } => f
                .debug_struct("Unlock")
                .field("db", db)
                .field("keyfile", keyfile)
                .field("password", &"<hidden>")
                .finish(),
            Request::Entries { db } => f.debug_struct("Entries").field("db", db).finish(),
            Request::Status => f.write_str("Status"),
            Request::Lock => f.write_str("Lock"),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Unlocked,
    Entries {
        entries: Vec<WireEntry>,
    },
    /// Nothing open, a different database, or it changed on disk.
    Locked {
        reason: String,
    },
    Status {
        db: Option<PathBuf>,
        idle_seconds_left: u64,
    },
    Bye,
    Error {
        message: String,
    },
}

/// An entry on the wire. Secrets travel as plain JSON strings between two processes of the
/// same user over a private socket, and go straight back into `Zeroizing` on arrival.
#[derive(Serialize, Deserialize)]
pub struct WireEntry {
    pub uuid: String,
    pub group: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub password: String,
    pub tags: Vec<String>,
    pub custom: Vec<(String, String, bool)>,
    pub modified: Option<chrono::NaiveDateTime>,
    pub expires: Option<chrono::NaiveDateTime>,
    pub quality_check: bool,
    pub attachments: Vec<String>,
}

impl From<&Entry> for WireEntry {
    fn from(e: &Entry) -> Self {
        WireEntry {
            uuid: e.uuid.clone(),
            group: e.group.clone(),
            title: e.title.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            password: e.password.to_string(),
            tags: e.tags.clone(),
            custom: e
                .custom
                .iter()
                .map(|c| (c.name.clone(), c.value.to_string(), c.protected))
                .collect(),
            modified: e.modified,
            expires: e.expires,
            quality_check: e.quality_check,
            attachments: e.attachments.clone(),
        }
    }
}

impl From<WireEntry> for Entry {
    fn from(w: WireEntry) -> Self {
        Entry {
            uuid: w.uuid,
            group: w.group,
            title: w.title,
            username: w.username,
            url: w.url,
            notes: w.notes,
            password: Zeroizing::new(w.password),
            tags: w.tags,
            custom: w
                .custom
                .into_iter()
                .map(|(name, value, protected)| CustomField {
                    name,
                    value: Zeroizing::new(value),
                    protected,
                })
                .collect(),
            modified: w.modified,
            expires: w.expires,
            quality_check: w.quality_check,
            attachments: w.attachments,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_survive_the_wire() {
        let e = Entry {
            uuid: "u".into(),
            group: "Work".into(),
            title: "GitHub".into(),
            password: Zeroizing::new("pw".into()),
            custom: vec![CustomField {
                name: "otp".into(),
                value: Zeroizing::new("otpauth://totp/x?secret=A".into()),
                protected: true,
            }],
            ..Entry::default()
        };
        let line = serde_json::to_string(&Response::Entries {
            entries: vec![WireEntry::from(&e)],
        })
        .unwrap();
        let Response::Entries { entries } = serde_json::from_str(&line).unwrap() else {
            panic!("wrong response");
        };
        let back = Entry::from(entries.into_iter().next().unwrap());
        assert_eq!(back.path(), "Work/GitHub");
        assert_eq!(*back.password, "pw");
        assert!(back.custom[0].protected);
        assert!(back.quality_check);
    }

    #[test]
    fn requests_carry_a_version_and_hide_passwords_in_debug() {
        let req = Envelope {
            v: VERSION,
            body: Request::Unlock {
                db: "/x.kdbx".into(),
                keyfile: None,
                password: Some("hunter2".into()),
            },
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""v":1"#) && line.contains(r#""op":"unlock""#));
        assert!(!format!("{:?}", req.body).contains("hunter2"));
    }
}
