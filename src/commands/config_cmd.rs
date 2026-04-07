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

    println!("{} Config created at {}", "✓".green(), path.display());
    Ok(())
}

fn cmd_show() -> Result<()> {
    let cfg = AppConfig::load();
    let toml_str =
        toml::to_string_pretty(&cfg).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))?;

    println!("{}", "Current configuration:".bold());
    println!(
        "{}",
        config::config_file_path().display().to_string().dimmed()
    );
    println!();
    println!("{toml_str}");
    Ok(())
}

fn cmd_set(pair: &str) -> Result<()> {
    let (key, value) = pair.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("Expected key=value format (e.g. 'generate.default_length=24')")
    })?;

    let key = key.trim();
    let value = value.trim();

    let mut cfg = AppConfig::load();

    match key {
        "vault.path" => cfg.vault.path = Some(value.to_string()),
        "vault.argon2_time_cost" => {
            cfg.vault.argon2_time_cost =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid u32"))?;
        }
        "vault.argon2_memory_cost" => {
            cfg.vault.argon2_memory_cost =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid u32"))?;
        }
        "vault.argon2_parallelism" => {
            cfg.vault.argon2_parallelism =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid u32"))?;
        }
        "clipboard.clear_after_seconds" => {
            cfg.clipboard.clear_after_seconds =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid u64"))?;
        }
        "clipboard.auto_clear" => {
            cfg.clipboard.auto_clear =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid bool"))?;
        }
        "generate.default_length" => {
            cfg.generate.default_length = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid usize"))?;
        }
        "generate.default_no_symbols" => {
            cfg.generate.default_no_symbols =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid bool"))?;
        }
        "generate.default_no_numbers" => {
            cfg.generate.default_no_numbers =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid bool"))?;
        }
        "generate.default_no_uppercase" => {
            cfg.generate.default_no_uppercase =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid bool"))?;
        }
        "generate.default_words" => {
            cfg.generate.default_words = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid usize"))?;
        }
        "generate.default_separator" => {
            cfg.generate.default_separator = value.to_string();
        }
        "backup.auto_backup" => {
            cfg.backup.auto_backup = value.parse().map_err(|_| anyhow::anyhow!("Invalid bool"))?;
        }
        "backup.max_backups" => {
            cfg.backup.max_backups = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid usize"))?;
        }
        "session.timeout_seconds" => {
            cfg.session.timeout_seconds =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid u64"))?;
        }
        "session.agent_enabled" => {
            cfg.session.agent_enabled =
                value.parse().map_err(|_| anyhow::anyhow!("Invalid bool"))?;
        }
        _ => anyhow::bail!("Unknown config key: '{key}'"),
    }

    cfg.save().map_err(|e| anyhow::anyhow!(e))?;

    println!("{} Set {} = {}", "✓".green(), key, value);
    Ok(())
}

fn cmd_reset() -> Result<()> {
    let path = config::config_file_path();

    print!("Reset config to defaults? [y/N] ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    let cfg = AppConfig::default();
    cfg.save().map_err(|e| anyhow::anyhow!(e))?;

    println!(
        "{} Config reset to defaults at {}",
        "✓".green(),
        path.display()
    );
    Ok(())
}
