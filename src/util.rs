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
