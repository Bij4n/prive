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
