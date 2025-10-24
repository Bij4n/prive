use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::cli::{DecryptArgs, EncryptArgs};
use crate::pgp::keyring::Keyring;
use crate::pgp::operations;

pub fn handle_encrypt(args: &EncryptArgs) -> Result<()> {
    let data = fs::read(&args.file)?;
    let filename = args
        .file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let encrypted = if args.symmetric {
        // Symmetric encryption with passphrase
        let passphrase = rpassword::prompt_password("Encryption passphrase: ")?;
        if passphrase.is_empty() {
            anyhow::bail!("Passphrase cannot be empty");
        }
        let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
        if passphrase != confirm {
            anyhow::bail!("Passphrases do not match");
        }
