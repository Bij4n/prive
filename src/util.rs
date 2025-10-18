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
