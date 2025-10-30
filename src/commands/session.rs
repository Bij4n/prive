use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::SessionCommand;
use crate::config;
use crate::session;
use crate::vault::storage::VaultStorage;

pub fn handle_session(cmd: &SessionCommand, vault_path: Option<&Path>) -> Result<()> {
    match cmd {
        SessionCommand::Start => cmd_start(vault_path),
        SessionCommand::Stop => cmd_stop(),
        SessionCommand::Status => cmd_status(),
    }
}

fn cmd_start(vault_path: Option<&Path>) -> Result<()> {
    if session::is_agent_running() {
        println!("Agent is already running.");
        return Ok(());
    }

    let path = vault_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path);

    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;

    let cfg = config::AppConfig::load();
    let timeout = cfg.session.timeout_seconds;

    println!(
        "{} Starting agent (timeout: {}s)...",
        "✓".green(),
        timeout
    );
    println!("  Vault unlocked in memory. Other prive commands will use the agent.");
    println!("  Run `prive session stop` or wait for timeout to lock.");

    // This blocks until timeout or lock command
    session::start_agent(&vault, timeout).map_err(|e| anyhow::anyhow!(e))?;

    println!("Agent stopped.");
    Ok(())
}

fn cmd_stop() -> Result<()> {
    if session::stop_agent() {
        println!("{} Agent stopped.", "✓".green());
    } else {
        println!("No agent is running.");
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    if session::is_agent_running() {
        println!("{} Agent is {} running.", "●".green(), "running".green().bold());
    } else {
        println!("{} Agent is {}.", "○".dimmed(), "not running".dimmed());
    }
    Ok(())
}
