use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum PriveError {
    #[error("Vault not found. Run `prive vault init` first.")]
    VaultNotFound,

    #[error("Vault already exists at {0}")]
    VaultAlreadyExists(String),

    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Entry already exists: {0}")]
    EntryAlreadyExists(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("PGP error: {0}")]
    Pgp(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Clipboard error: {0}")]
    Clipboard(String),
}
