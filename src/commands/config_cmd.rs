use anyhow::Result;
use colored::Colorize;

use crate::cli::ConfigCommand;
use crate::config::{self, AppConfig};

pub fn handle_config(cmd: &ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::Init => cmd_init(),
        ConfigCommand::Show => cmd_show(),
        ConfigCommand::Set { pair } => cmd_set(pair),
        ConfigCommand::Reset => cmd_reset(),
    }
}

fn cmd_init() -> Result<()> {
    let path = config::config_file_path();

    if path.exists() {
        anyhow::bail!(
            "Config already exists at {}. Use 'config reset' to restore defaults.",
            path.display()
        );
    }

    let cfg = AppConfig::default();
    cfg.save().map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Config created at {}",
        "✓".green(),
        path.display()
    );
    Ok(())
}

fn cmd_show() -> Result<()> {
    let cfg = AppConfig::load();
    let toml_str =
        toml::to_string_pretty(&cfg).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))?;

    println!("{}", "Current configuration:".bold());
    println!("{}", config::config_file_path().display().to_string().dimmed());
    println!();
    println!("{toml_str}");
    Ok(())
}

fn cmd_set(pair: &str) -> Result<()> {
    let (key, value) = pair
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("Expected key=value format (e.g. 'generate.default_length=24')"))?;

    let key = key.trim();
