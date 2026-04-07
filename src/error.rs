use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum PriveError {
    #[error("Vault not found at {path}")]
    VaultNotFound { path: String },

    #[error("Vault already exists at {path}")]
    VaultAlreadyExists { path: String },

    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Entry not found: {name}")]
    EntryNotFound { name: String },

    #[error("Entry already exists: {name}")]
    EntryAlreadyExists { name: String },

    #[error("Note not found: {title}")]
    NoteNotFound { title: String },

    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("PGP error: {0}")]
    Pgp(String),

    #[error("Sync error: {0}")]
    Sync(String),

    #[error("Attachment too large: {size} bytes (max {max} bytes)")]
    AttachmentTooLarge { size: u64, max: u64 },

    #[error("Clipboard error: {0}")]
    Clipboard(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}

impl PriveError {
    /// Returns an appropriate process exit code for this error.
    ///
    /// - 1: general / IO / serialization errors
    /// - 2: authentication failures
    /// - 3: not-found errors (vault, entry, note, key)
    pub fn exit_code(&self) -> i32 {
        match self {
            PriveError::InvalidPassword => 2,

            PriveError::VaultNotFound { .. }
            | PriveError::EntryNotFound { .. }
            | PriveError::NoteNotFound { .. }
            | PriveError::KeyNotFound { .. } => 3,

            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_general() {
        let err = PriveError::Encryption("bad data".into());
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn test_exit_code_auth() {
        let err = PriveError::InvalidPassword;
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_not_found() {
        let err = PriveError::VaultNotFound {
            path: "/tmp/v".into(),
        };
        assert_eq!(err.exit_code(), 3);

        let err = PriveError::EntryNotFound {
            name: "github".into(),
        };
        assert_eq!(err.exit_code(), 3);

        let err = PriveError::NoteNotFound {
            title: "todo".into(),
        };
        assert_eq!(err.exit_code(), 3);

        let err = PriveError::KeyNotFound {
            key_id: "ABC123".into(),
        };
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn test_display_messages() {
        let err = PriveError::VaultNotFound {
            path: "/home/user/.prive/vault.pv".into(),
        };
        assert_eq!(
            err.to_string(),
            "Vault not found at /home/user/.prive/vault.pv"
        );

        let err = PriveError::VaultAlreadyExists {
            path: "/tmp/v.pv".into(),
        };
        assert_eq!(err.to_string(), "Vault already exists at /tmp/v.pv");

        let err = PriveError::InvalidPassword;
        assert_eq!(err.to_string(), "Invalid master password");

        let err = PriveError::EntryNotFound {
            name: "github".into(),
        };
        assert_eq!(err.to_string(), "Entry not found: github");

        let err = PriveError::EntryAlreadyExists {
            name: "github".into(),
        };
        assert_eq!(err.to_string(), "Entry already exists: github");

        let err = PriveError::NoteNotFound {
            title: "my note".into(),
        };
        assert_eq!(err.to_string(), "Note not found: my note");

        let err = PriveError::AttachmentTooLarge {
            size: 2000,
            max: 1000,
        };
        assert_eq!(
            err.to_string(),
            "Attachment too large: 2000 bytes (max 1000 bytes)"
        );

        let err = PriveError::Clipboard("not available".into());
        assert_eq!(err.to_string(), "Clipboard error: not available");

        let err = PriveError::Config("missing key".into());
        assert_eq!(err.to_string(), "Config error: missing key");

        let err = PriveError::Sync("timeout".into());
        assert_eq!(err.to_string(), "Sync error: timeout");
    }

    #[test]
    fn test_io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let prive_err: PriveError = io_err.into();
        assert_eq!(prive_err.exit_code(), 1);
        assert!(prive_err.to_string().contains("file missing"));
    }

    #[test]
    fn test_general_errors_exit_code() {
        // All "general" error variants should return exit code 1
        assert_eq!(PriveError::Encryption("x".into()).exit_code(), 1);
        assert_eq!(PriveError::Decryption("x".into()).exit_code(), 1);
        assert_eq!(PriveError::Pgp("x".into()).exit_code(), 1);
        assert_eq!(PriveError::Sync("x".into()).exit_code(), 1);
        assert_eq!(PriveError::Clipboard("x".into()).exit_code(), 1);
        assert_eq!(PriveError::Config("x".into()).exit_code(), 1);
        assert_eq!(
            PriveError::AttachmentTooLarge { size: 1, max: 0 }.exit_code(),
            1
        );
        assert_eq!(
            PriveError::VaultAlreadyExists { path: "x".into() }.exit_code(),
            1
        );
        assert_eq!(
            PriveError::EntryAlreadyExists { name: "x".into() }.exit_code(),
            1
        );
    }
}
