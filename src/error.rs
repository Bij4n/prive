//! Errors that map to specific exit codes.
//!
//! Anything else is reported as a general error (exit code 1). Usage errors come from clap and
//! exit with 2.

use std::process::ExitCode;

#[derive(Debug, thiserror::Error)]
pub enum Failure {
    #[error("no entry matches '{0}'")]
    NotFound(String),

    /// Something other than an entry isn't there: a field, a file, a code, a group. The
    /// message says what, in full.
    #[error("{0}")]
    Missing(String),

    /// Like `NotFound`, with entry paths that look like what was meant.
    #[error("no entry matches '{query}'")]
    NoSuchEntry { query: String, close: Vec<String> },

    #[error("'{query}' matches {} entries; use the full path", candidates.len())]
    Ambiguous {
        query: String,
        candidates: Vec<String>,
    },

    #[error("could not open the database: wrong password or key file")]
    BadCredentials,

    /// The user backed out of an interactive choice (Esc or Ctrl-C in the picker).
    #[error("cancelled")]
    Cancelled,

    #[error(
        "no password given: stdin is not a terminal (use --password-stdin or PRIVE_PASSWORD_FILE)"
    )]
    NoTerminal,
}

impl Failure {
    pub fn exit_code(&self) -> u8 {
        match self {
            Failure::NotFound(_) | Failure::Missing(_) | Failure::NoSuchEntry { .. } => 3,
            Failure::Ambiguous { .. } => 4,
            Failure::BadCredentials | Failure::NoTerminal => 5,
            // What shells and fzf use for an interrupted command, so `$(prive pick --print)`
            // can tell a cancel from an empty value.
            Failure::Cancelled => 130,
        }
    }
}

/// Print an error to stderr and choose the exit code.
pub fn report(err: &anyhow::Error) -> ExitCode {
    if let Some(Failure::Cancelled) = err.downcast_ref::<Failure>() {
        return ExitCode::from(130); // the user knows; no message needed
    }
    eprintln!("prive: {err}");
    for cause in err.chain().skip(1) {
        eprintln!("  caused by: {cause}");
    }
    match err.downcast_ref::<Failure>() {
        Some(f) => {
            match f {
                Failure::Ambiguous { candidates, .. } => {
                    for c in candidates {
                        eprintln!("  {c}");
                    }
                }
                Failure::NoSuchEntry { close, .. } if !close.is_empty() => {
                    eprintln!("  did you mean: {}?", close.join(", "));
                }
                _ => {}
            }
            ExitCode::from(f.exit_code())
        }
        None => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(Failure::NotFound("x".into()).exit_code(), 3);
        assert_eq!(Failure::Missing("x".into()).exit_code(), 3);
        let amb = Failure::Ambiguous {
            query: "x".into(),
            candidates: vec!["a".into(), "b".into()],
        };
        assert_eq!(amb.exit_code(), 4);
        assert_eq!(Failure::BadCredentials.exit_code(), 5);
        assert_eq!(Failure::NoTerminal.exit_code(), 5);
        assert_eq!(Failure::Cancelled.exit_code(), 130);
    }

    #[test]
    fn messages_say_what_to_do() {
        assert_eq!(
            Failure::NotFound("Work/Gitlab".into()).to_string(),
            "no entry matches 'Work/Gitlab'"
        );
        // A missing field is not a missing entry: the message is said as it is.
        assert_eq!(
            Failure::Missing("Bank: no field 'pin' (it has: title)".into()).to_string(),
            "Bank: no field 'pin' (it has: title)"
        );
        let amb = Failure::Ambiguous {
            query: "GitHub".into(),
            candidates: vec!["Work/GitHub".into(), "Personal/GitHub".into()],
        };
        assert_eq!(
            amb.to_string(),
            "'GitHub' matches 2 entries; use the full path"
        );
        assert!(Failure::NoTerminal.to_string().contains("--password-stdin"));
    }
}
