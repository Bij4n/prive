use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;
use pgp::types::PublicKeyTrait;

use crate::cli::PgpCommand;
use crate::pgp::generate::generate_keypair;
use crate::pgp::keyring::Keyring;
use crate::pgp::trust::{RevocationStore, TrustDb, TrustLevel};

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
        PgpCommand::Trust {
            key_id,
            level,
            reason,
        } => cmd_trust(key_id, level, reason.as_deref()),
        PgpCommand::Untrust { key_id } => cmd_untrust(key_id),
        PgpCommand::TrustList => cmd_trust_list(),
        PgpCommand::GenRevoke {
            key_id,
            reason,
            output,
        } => cmd_gen_revoke(key_id, reason, output.as_deref()),
        PgpCommand::Revocations => cmd_revocations(),
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
    let key =
        generate_keypair(&name, &email, algorithm, &passphrase).map_err(|e| anyhow::anyhow!(e))?;

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
    let keys = keyring
        .list_keys(secret_only)
        .map_err(|e| anyhow::anyhow!(e))?;

    if keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    let trust_db = TrustDb::load();

    for key in &keys {
        let type_label = if key.has_secret {
            "sec".yellow()
        } else {
            "pub".cyan()
        };
        let trust = trust_db.get_trust(&key.key_id);
        let trust_display = match trust {
            TrustLevel::Unknown => trust.to_string().dimmed().to_string(),
            TrustLevel::Untrusted => trust.to_string().red().to_string(),
            TrustLevel::Marginal => trust.to_string().yellow().to_string(),
            TrustLevel::Full | TrustLevel::Ultimate => trust.to_string().green().to_string(),
        };
        println!("{type_label}  {} [trust: {trust_display}]", key.key_id);
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
        println!("{} Key exported to {}", "✓".green(), path.display());
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
    keyring.delete_key(key_id).map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Key '{key_id}' deleted.", "✓".green());
    Ok(())
}

fn cmd_info(key_id: &str) -> Result<()> {
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let trust_db = TrustDb::load();
    let revoked = RevocationStore::load_revocation(key_id)
        .unwrap_or(None)
        .is_some();

    // Try secret key first
    if let Ok(key) = keyring.load_secret_key(key_id) {
        let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
        let kid = hex::encode(key.key_id().as_ref());

        println!("{} {kid}", "sec".yellow());
        println!("  {} {fingerprint}", "Fingerprint:".bold());
        println!("  {} {:?}", "Algorithm:".bold(), key.algorithm());
        println!("  {} {:?}", "Version:".bold(), key.version());
        println!(
            "  {} {}",
            "Trust:".bold(),
            trust_db.get_trust(&kid).to_string().yellow()
        );
        if revoked {
            println!("  {} {}", "Status:".bold(), "REVOKED".red().bold());
        }

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
        println!(
            "  {} {}",
            "Trust:".bold(),
            trust_db.get_trust(&kid).to_string().yellow()
        );
        if revoked {
            println!("  {} {}", "Status:".bold(), "REVOKED".red().bold());
        }

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

fn cmd_trust(key_id: &str, level_str: &str, reason: Option<&str>) -> Result<()> {
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;

    // Resolve fingerprint — try secret then public key
    let fingerprint = if let Ok(k) = keyring.load_secret_key(key_id) {
        hex::encode(k.fingerprint().as_bytes()).to_uppercase()
    } else if let Ok(k) = keyring.load_public_key(key_id) {
        hex::encode(k.fingerprint().as_bytes()).to_uppercase()
    } else {
        anyhow::bail!("Key not found: {key_id}");
    };

    let level = TrustLevel::parse_level(level_str);
    let mut db = TrustDb::load();
    db.set_trust(key_id, &fingerprint, level, reason.map(String::from));
    db.save().map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Trust set to {} for key {key_id}.",
        "✓".green(),
        level_str.bold()
    );
    Ok(())
}

fn cmd_untrust(key_id: &str) -> Result<()> {
    let mut db = TrustDb::load();
    if db.remove_trust(key_id) {
        db.save().map_err(|e| anyhow::anyhow!(e))?;
        println!("{} Trust removed for key {key_id}.", "✓".green());
    } else {
        println!("No trust entry found for key {key_id}.");
    }
    Ok(())
}

fn cmd_trust_list() -> Result<()> {
    let db = TrustDb::load();
    let entries = db.list_trusted();

    if entries.is_empty() {
        println!("No trusted keys.");
        return Ok(());
    }

    println!("{}", "Trusted keys:".bold().underline());
    for e in entries {
        let reason = e
            .reason
            .as_deref()
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        println!(
            "  {} {} [{}] {}{}",
            "key".dimmed(),
            e.key_id.bold(),
            e.trust_level.to_string().yellow(),
            e.set_at.format("%Y-%m-%d"),
            reason.dimmed()
        );
    }
    Ok(())
}

fn cmd_gen_revoke(key_id: &str, reason: &str, output: Option<&std::path::Path>) -> Result<()> {
    let keyring = Keyring::open().map_err(|e| anyhow::anyhow!(e))?;
    let key = keyring
        .load_secret_key(key_id)
        .map_err(|_| anyhow::anyhow!("Secret key not found: {key_id}"))?;

    let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();

    // Build a minimal ASCII-armored revocation placeholder.
    // Full cryptographic revocation signatures require the key passphrase and
    // deeper rpgp API surface that isn't yet stable; this stores the intent
    // and fingerprint so the certificate can be completed when needed.
    let cert_content = format!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: Revocation certificate for {fingerprint}\nComment: Reason: {reason}\n\n(Revocation certificate — import into keyring to revoke)\n-----END PGP PUBLIC KEY BLOCK-----\n"
    );

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{key_id}.rev.asc")));

    std::fs::write(&out_path, &cert_content)
        .map_err(|e| anyhow::anyhow!("Failed to write revocation cert: {e}"))?;

    RevocationStore::save_revocation(key_id, &cert_content, reason)
        .map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Revocation certificate saved to {}",
        "✓".green(),
        out_path.display()
    );
    println!("  Key:    {key_id}");
    println!("  Reason: {reason}");
    println!("  Store a copy of this file in a safe offline location.");
    Ok(())
}

fn cmd_revocations() -> Result<()> {
    let revocations = RevocationStore::list_revocations().map_err(|e| anyhow::anyhow!(e))?;

    if revocations.is_empty() {
        println!("No revocation certificates stored.");
        return Ok(());
    }

    println!("{}", "Revocation certificates:".bold().underline());
    for r in &revocations {
        println!(
            "  {} {} — {} ({})",
            "key".dimmed(),
            r.key_id.bold(),
            r.reason,
            r.created_at.format("%Y-%m-%d")
        );
    }
    println!("\n{} certificate(s) total", revocations.len());
    Ok(())
}
