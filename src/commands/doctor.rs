use std::fs;

use anyhow::Result;
use colored::Colorize;

use crate::config;
use crate::pgp::keyring::Keyring;
use crate::pgp::trust::{RevocationStore, TrustDb, TrustLevel};
use crate::vault::migrate;

pub fn handle_doctor() -> Result<()> {
    println!("{}\n", "Prive Health Check".bold().underline());

    let mut issues = 0;

    // Check data directory
    let data_dir = config::data_dir();
    if data_dir.exists() {
        println!("  {} Data directory: {}", "✓".green(), data_dir.display());
    } else {
        println!(
            "  {} Data directory missing: {}",
            "✗".red(),
            data_dir.display()
        );
        issues += 1;
    }

    // Check config
    let config_path = config::config_file_path();
    if config_path.exists() {
        let cfg = config::AppConfig::load();
        println!("  {} Config file: {}", "✓".green(), config_path.display());
        if let Some(ref name) = cfg.vault.active_vault {
            println!("    Active vault: {name}");
        }
    } else {
        println!("  {} No config file (using defaults)", "○".dimmed());
    }

    // Check vault
    let vault_path = config::vault_path();
    if vault_path.exists() {
        match migrate::validate_vault_header(&vault_path) {
            Ok(info) => {
                println!(
                    "  {} Vault: {} (v{}, {} bytes)",
                    "✓".green(),
                    vault_path.display(),
                    info.version,
                    info.file_size
                );
                if info.version < migrate::CURRENT_VERSION {
                    println!(
                        "    {} Vault needs migration (v{} -> v{})",
                        "!".yellow(),
                        info.version,
                        migrate::CURRENT_VERSION
                    );
                    issues += 1;
                }
            }
            Err(e) => {
                println!("  {} Vault corrupted: {}", "✗".red(), e);
                issues += 1;
            }
        }
    } else {
        println!(
            "  {} No vault found. Run `prive vault init` to create one.",
            "○".dimmed()
        );
    }

    // Check keyring + trust status
    let keyring_dir = config::keyring_dir();
    if keyring_dir.exists() {
        let key_count = fs::read_dir(&keyring_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .is_some_and(|ext| ext == "asc")
                    })
                    .count()
            })
            .unwrap_or(0);
        println!(
            "  {} Keyring: {} ({} key files)",
            "✓".green(),
            keyring_dir.display(),
            key_count
        );

        // Check trust levels for all keys
        if let Ok(keyring) = Keyring::open()
            && let Ok(keys) = keyring.list_keys(false)
        {
            let trust_db = TrustDb::load();
            let untrusted: Vec<_> = keys
                .iter()
                .filter(|k| {
                    matches!(
                        trust_db.get_trust(&k.key_id),
                        TrustLevel::Unknown | TrustLevel::Untrusted
                    )
                })
                .collect();
            if untrusted.is_empty() {
                println!("    {} All keys have trust levels set", "✓".green());
            } else {
                println!(
                    "    {} {} key(s) without trust level (run `prive pgp trust <key_id>`)",
                    "!".yellow(),
                    untrusted.len()
                );
                issues += 1;
            }

            let revocations = RevocationStore::list_revocations().unwrap_or_default();
            if !revocations.is_empty() {
                println!(
                    "    {} {} revocation certificate(s) stored",
                    "✓".green(),
                    revocations.len()
                );
            }
        }
    } else {
        println!("  {} No keyring directory", "○".dimmed());
    }

    // Check backup directory and freshness
    let backup_dir = config::backup_dir();
    if backup_dir.exists() {
        let mut backup_entries: Vec<_> = fs::read_dir(&backup_dir)
            .map(|entries| entries.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        backup_entries.sort_by_key(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });
        let backup_count = backup_entries.len();
        println!(
            "  {} Backups: {} ({} files)",
            "✓".green(),
            backup_dir.display(),
            backup_count
        );
        // Warn if most recent backup is older than 7 days
        if let Some(latest) = backup_entries.last()
            && let Ok(modified) = latest.metadata().and_then(|m| m.modified())
            && let Ok(age) = modified.elapsed()
        {
            let days = age.as_secs() / 86400;
            if days > 7 {
                println!(
                    "    {} Most recent backup is {} days old",
                    "!".yellow(),
                    days
                );
                issues += 1;
            }
        }
    } else {
        println!(
            "  {} No backups found — run `prive backup create`",
            "○".dimmed()
        );
    }

    // Check sync
    let sync_git = config::data_dir().join(".git");
    if sync_git.exists() {
        println!("  {} Vault sync: initialized", "✓".green());
    } else {
        println!("  {} Vault sync: not configured", "○".dimmed());
    }

    // Check session agent
    if crate::session::is_agent_running() {
        println!("  {} Session agent: {}", "●".green(), "running".green());
    } else {
        println!("  {} Session agent: not running", "○".dimmed());
    }

    // Summary
    println!();
    if issues == 0 {
        println!("{}", "All checks passed.".green());
    } else {
        println!("{} {} issue(s) found.", "!".yellow(), issues);
    }

    Ok(())
}
