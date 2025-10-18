use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::config::AppConfig;

pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| anyhow::anyhow!("Clipboard error: {e}"))?;
    clipboard
        .set_text(text)
        .map_err(|e| anyhow::anyhow!("Clipboard error: {e}"))?;

    let config = AppConfig::load();
    if config.clipboard.auto_clear {
        let timeout = config.clipboard.clear_after_seconds;
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(timeout));
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text("");
            }
        });
    }

    Ok(())
}

pub fn copy_to_clipboard_with_clear(text: &str, clear_seconds: u64) -> Result<()> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| anyhow::anyhow!("Clipboard error: {e}"))?;
    clipboard
        .set_text(text)
        .map_err(|e| anyhow::anyhow!("Clipboard error: {e}"))?;

    if clear_seconds > 0 {
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(clear_seconds));
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text("");
            }
        });
    }

    Ok(())
}

pub fn confirm_prompt(message: &str) -> Result<bool> {
    print!("{message} [y/N] ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

pub fn format_duration_ago(seconds: i64) -> String {
    if seconds < 60 {
        return "just now".to_string();
    }
    if seconds < 3600 {
        let mins = seconds / 60;
        return format!("{mins}m ago");
    }
    if seconds < 86400 {
        let hours = seconds / 3600;
        return format!("{hours}h ago");
    }
    let days = seconds / 86400;
    if days < 30 {
        return format!("{days}d ago");
    }
    if days < 365 {
        let months = days / 30;
        return format!("{months}mo ago");
    }
    let years = days / 365;
    format!("{years}y ago")
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
