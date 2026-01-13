use anyhow::Result;
use colored::Colorize;

use crate::cli::ClipCommand;
use crate::config::AppConfig;

pub fn handle_clip(cmd: &ClipCommand) -> Result<()> {
    match cmd {
        ClipCommand::Clear => cmd_clear(),
        ClipCommand::Status => cmd_status(),
    }
}

fn cmd_clear() -> Result<()> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| anyhow::anyhow!("Clipboard error: {e}"))?;
    clipboard
        .set_text("")
        .map_err(|e| anyhow::anyhow!("Clipboard error: {e}"))?;
    println!("{} Clipboard cleared.", "✓".green());
    Ok(())
}

fn cmd_status() -> Result<()> {
    let config = AppConfig::load();
    if config.clipboard.auto_clear {
        println!(
            "{} Auto-clear is {} (timeout: {}s)",
            "●".green(),
            "enabled".green().bold(),
            config.clipboard.clear_after_seconds
        );
    } else {
        println!(
            "{} Auto-clear is {}.",
            "○".dimmed(),
            "disabled".dimmed()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_status_does_not_panic() {
        // Verify status runs without error (uses default config)
        let result = cmd_status();
        assert!(result.is_ok());
    }
}
