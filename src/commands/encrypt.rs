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
        operations::encrypt_symmetric(&data, &filename, &passphrase)
            .map_err(|e| anyhow::anyhow!(e))?
    } else if !args.recipient.is_empty() {
        // PGP encryption to recipients
        let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
        let mut pub_keys = Vec::new();

        for recipient in &args.recipient {
            let key = keyring
                .load_public_key(recipient)
                .map_err(|e| anyhow::anyhow!(e))?;
            pub_keys.push(key);
        }

        let key_refs: Vec<&pgp::composed::SignedPublicKey> = pub_keys.iter().collect();
        operations::encrypt_to_keys(&data, &filename, &key_refs)
            .map_err(|e| anyhow::anyhow!(e))?
    } else {
        anyhow::bail!(
            "Specify --recipient <KEY_ID> for PGP encryption or --symmetric for passphrase encryption"
        );
    };

    let output = args.output.clone().unwrap_or_else(|| {
        let mut p = args.file.clone();
        let ext = if args.armor { "asc" } else { "pgp" };
        p.set_extension(format!(
            "{}.{ext}",
            p.extension().unwrap_or_default().to_string_lossy()
