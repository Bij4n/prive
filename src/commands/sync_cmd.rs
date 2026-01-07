use anyhow::Result;
use colored::Colorize;

use crate::cli::SyncCommand;
use crate::config;
use crate::sync::VaultSync;

pub fn handle_sync(cmd: &SyncCommand) -> Result<()> {
    match cmd {
        SyncCommand::Init { url } => cmd_init(url),
        SyncCommand::Push => cmd_push(),
        SyncCommand::Pull => cmd_pull(),
        SyncCommand::Status => cmd_status(),
    }
}

fn cmd_init(url: &str) -> Result<()> {
    let sync = VaultSync::new(config::data_dir());
    sync.init(url)?;
    println!(
        "{} Sync initialized with remote: {}",
        "✓".green(),
        url.bold()
    );
    Ok(())
}

fn cmd_push() -> Result<()> {
    let sync = VaultSync::new(config::data_dir());
    let message = format!("Vault sync {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    sync.push(&message)?;
    println!("{} Vault pushed to remote.", "✓".green());
    Ok(())
}

fn cmd_pull() -> Result<()> {
    let sync = VaultSync::new(config::data_dir());
    let changed = sync.pull()?;
    if changed {
        println!(
            "{} Vault updated from remote.",
            "✓".green()
        );
    } else {
        println!("Already up to date.");
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    let sync = VaultSync::new(config::data_dir());
    let status = sync.status()?;

    println!("{}", "Sync Status".bold().underline());
    println!(
        "  Initialized: {}",
        if status.is_initialized {
            "yes".green().to_string()
        } else {
            "no".red().to_string()
        }
    );
    println!(
        "  Remote:      {}",
        if status.has_remote {
            "configured".green().to_string()
        } else {
            "not configured".red().to_string()
        }
    );
    println!(
        "  Last sync:   {}",
        status
            .last_sync
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".dimmed().to_string())
    );
    println!(
        "  Dirty:       {}",
        if status.is_dirty {
            "yes (uncommitted changes)".yellow().to_string()
        } else {
            "no".green().to_string()
        }
    );

    Ok(())
}
