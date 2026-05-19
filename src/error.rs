//! Errors that map to specific exit codes.
//!
//! Anything else is reported as a general error (exit code 1). Usage errors come from clap and
//! exit with 2.

use std::process::ExitCode;

#[derive(Debug, thiserror::Error)]
pub enum Failure {
    #[error("no entry matches '{0}'")]
    NotFound(String),

    #[error("'{query}' matches {} entries; use the full path", candidates.len())]
    Ambiguous {
        query: String,
        candidates: Vec<String>,
    },

    #[error("could not open the database: wrong password or key file")]
    BadCredentials,

    #[error(
        "no password given: stdin is not a terminal (use --password-stdin or PRIVE_PASSWORD_FILE)"
    )]
    NoTerminal,
}

impl Failure {
    pub fn exit_code(&self) -> u8 {
        match self {
            Failure::NotFound(_) => 3,
            Failure::Ambiguous { .. } => 4,
            Failure::BadCredentials | Failure::NoTerminal => 5,
        }
    }
}

/// Print an error to stderr and choose the exit code.
pub fn report(err: &anyhow::Error) -> ExitCode {
    eprintln!("prive: {err}");
    for cause in err.chain().skip(1) {
        eprintln!("  caused by: {cause}");
    }
    match err.downcast_ref::<Failure>() {
        Some(f) => {
            if let Failure::Ambiguous { candidates, .. } = f {
                for c in candidates {
                    eprintln!("  {c}");
                }
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
        let amb = Failure::Ambiguous {
            query: "x".into(),
            candidates: vec!["a".into(), "b".into()],
        };
        assert_eq!(amb.exit_code(), 4);
        assert_eq!(Failure::BadCredentials.exit_code(), 5);
        assert_eq!(Failure::NoTerminal.exit_code(), 5);
    }
}
