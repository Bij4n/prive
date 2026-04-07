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
        operations::encrypt_to_keys(&data, &filename, &key_refs).map_err(|e| anyhow::anyhow!(e))?
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
        ));
        p
    });

    fs::write(&output, &encrypted)?;
    println!(
        "{} Encrypted {} -> {}",
        "✓".green(),
        args.file.display(),
        output.display()
    );

    Ok(())
}

pub fn handle_decrypt(args: &DecryptArgs) -> Result<()> {
    let encrypted_data = fs::read(&args.file)?;

    // Try to detect if it's symmetric or key-based by trying password first if no keys exist
    // For now, try key-based first, then fall back to password

    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let secret_keys = keyring.list_keys(true).map_err(|e| anyhow::anyhow!(e))?;

    let mut decrypted = None;
    let mut orig_filename = String::new();

    // Try each secret key
    for key_info in &secret_keys {
        if let Ok(secret_key) = keyring.load_secret_key(&key_info.key_id) {
            let passphrase = rpassword::prompt_password(format!(
                "Passphrase for key {} (empty if none): ",
                &key_info.key_id
            ))?;

            match operations::decrypt_with_key(&encrypted_data, &secret_key, &passphrase) {
                Ok((data, fname)) => {
                    decrypted = Some(data);
                    orig_filename = fname;
                    break;
                }
                Err(_) => continue,
            }
        }
    }

    // If no key worked, try symmetric decryption
    if decrypted.is_none() {
        let passphrase = rpassword::prompt_password("Decryption passphrase: ")?;
        match operations::decrypt_with_password(&encrypted_data, &passphrase) {
            Ok((data, fname)) => {
                decrypted = Some(data);
                orig_filename = fname;
            }
            Err(e) => {
                anyhow::bail!("Decryption failed: {e}");
            }
        }
    }

    let data = decrypted.unwrap();

    let output = args.output.clone().unwrap_or_else(|| {
        // Try to strip .pgp or .asc extension
        let stem = args.file.with_extension("");
        if stem == args.file {
            // No extension to strip, use original filename from message
            if !orig_filename.is_empty() {
                PathBuf::from(&orig_filename)
            } else {
                PathBuf::from(format!("{}.dec", args.file.display()))
            }
        } else {
            stem
        }
    });

    fs::write(&output, &data)?;
    println!(
        "{} Decrypted {} -> {}",
        "✓".green(),
        args.file.display(),
        output.display()
    );

    Ok(())
}
