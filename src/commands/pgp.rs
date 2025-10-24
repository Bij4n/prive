use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;
use pgp::types::PublicKeyTrait;

use crate::cli::PgpCommand;
use crate::pgp::generate::generate_keypair;
use crate::pgp::keyring::Keyring;

pub fn handle_pgp(cmd: &PgpCommand) -> Result<()> {
    match cmd {
        PgpCommand::Generate {
            name,
            email,
            algorithm,
            expire: _,
        } => cmd_generate(name.as_deref(), email.as_deref(), algorithm),
        PgpCommand::List { secret } => cmd_list(*secret),
        PgpCommand::Export {
            key_id,
            secret,
            output,
        } => cmd_export(key_id, *secret, output.as_deref()),
        PgpCommand::Import { file } => cmd_import(file),
        PgpCommand::Delete { key_id, force } => cmd_delete(key_id, *force),
        PgpCommand::Info { key_id } => cmd_info(key_id),
    }
}

fn cmd_generate(name: Option<&str>, email: Option<&str>, algorithm: &str) -> Result<()> {
    let name = if let Some(n) = name {
        n.to_string()
    } else {
        print!("Name: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let email = if let Some(e) = email {
        e.to_string()
    } else {
        print!("Email: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let passphrase = rpassword::prompt_password("Key passphrase (empty for none): ")?;

    println!("Generating {} keypair...", algorithm.dimmed());
    let key = generate_keypair(&name, &email, algorithm, &passphrase)
        .map_err(|e| anyhow::anyhow!(e))?;

    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let key_id = keyring
        .save_secret_key(&key)
        .map_err(|e| anyhow::anyhow!(e))?;

    let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();

    println!("{} PGP keypair generated.", "✓".green());
    println!("  Key ID:      {key_id}");
    println!("  Fingerprint: {fingerprint}");
    println!("  UID:         {name} <{email}>");

    Ok(())
}

fn cmd_list(secret_only: bool) -> Result<()> {
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let keys = keyring.list_keys(secret_only).map_err(|e| anyhow::anyhow!(e))?;

    if keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    for key in &keys {
        let type_label = if key.has_secret {
            "sec".yellow()
        } else {
            "pub".cyan()
        };
        println!("{type_label}  {}", key.key_id);
        println!("     {} {}", "Fingerprint:".dimmed(), key.fingerprint);
        println!("     {} {}", "UID:".dimmed(), key.uid);
        println!("     {} {}", "Algorithm:".dimmed(), key.algorithm);
        println!();
    }

    println!("{} key(s) total", keys.len());
    Ok(())
}

fn cmd_export(key_id: &str, secret: bool, output: Option<&std::path::Path>) -> Result<()> {
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let armored = keyring
        .export_key(key_id, secret)
        .map_err(|e| anyhow::anyhow!(e))?;

    if let Some(path) = output {
        fs::write(path, &armored)?;
        println!(
            "{} Key exported to {}",
            "✓".green(),
            path.display()
        );
    } else {
        println!("{armored}");
    }

    Ok(())
}

fn cmd_import(file: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file)?;
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let key_id = keyring
        .import_key(&content)
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Key imported: {key_id}", "✓".green());
    Ok(())
}

fn cmd_delete(key_id: &str, force: bool) -> Result<()> {
    if !force {
        print!("Delete key '{key_id}'? This cannot be undone. [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    keyring
        .delete_key(key_id)
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Key '{key_id}' deleted.", "✓".green());
    Ok(())
}

fn cmd_info(key_id: &str) -> Result<()> {
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;

    // Try secret key first
    if let Ok(key) = keyring.load_secret_key(key_id) {
        let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
        let kid = hex::encode(key.key_id().as_ref());

        println!("{} {kid}", "sec".yellow());
        println!("  {} {fingerprint}", "Fingerprint:".bold());
        println!("  {} {:?}", "Algorithm:".bold(), key.algorithm());
        println!("  {} {:?}", "Version:".bold(), key.version());

        for user in &key.details.users {
            let uid = String::from_utf8_lossy(user.id.id());
            println!("  {} {uid}", "UID:".bold());
        }

        println!("  {} {}", "Subkeys:".bold(), key.secret_subkeys.len());
        for sk in &key.secret_subkeys {
            let sk_id = hex::encode(sk.key_id().as_ref());
            println!("    {} {sk_id} ({:?})", "sub".dimmed(), sk.algorithm());
        }

        return Ok(());
    }

    // Try public key
    if let Ok(key) = keyring.load_public_key(key_id) {
        let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
        let kid = hex::encode(key.key_id().as_ref());

        println!("{} {kid}", "pub".cyan());
        println!("  {} {fingerprint}", "Fingerprint:".bold());
        println!("  {} {:?}", "Algorithm:".bold(), key.algorithm());

        for user in &key.details.users {
            let uid = String::from_utf8_lossy(user.id.id());
            println!("  {} {uid}", "UID:".bold());
        }

        println!("  {} {}", "Subkeys:".bold(), key.public_subkeys.len());
        for sk in &key.public_subkeys {
            let sk_id = hex::encode(sk.key_id().as_ref());
            println!("    {} {sk_id} ({:?})", "sub".dimmed(), sk.algorithm());
        }

        return Ok(());
    }

    anyhow::bail!("Key not found: {key_id}");
}
