//! Opening an entry's URL in the default browser.
//!
//! Only web addresses are opened. KeePass also allows `cmd://...` URLs that run a program;
//! prive refuses those, and anything else that isn't http or https, so a database can never
//! make it start something.

use std::process::Command;

use anyhow::{Context, Result, bail};

/// The address to open: http(s) URLs as they are, a bare host like `github.com` with https://
/// in front (as KeePassXC does), anything else refused.
pub fn web_url(raw: &str) -> Result<String> {
    let url = raw.trim();
    if url.is_empty() {
        bail!("the entry has no URL");
    }
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Ok(url.to_string());
    }
    if let Some((scheme, _)) = url.split_once("://") {
        bail!("won't open a '{scheme}://' URL; only http and https are opened");
    }
    if url.contains(char::is_whitespace) || url.starts_with('-') {
        bail!("'{url}' doesn't look like a web address");
    }
    Ok(format!("https://{url}"))
}

/// Hand the URL to the system's opener. No shell is involved, so nothing in the URL is
/// interpreted as a command.
pub fn open(url: &str) -> Result<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    let status = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("starting the browser")?;
    if !status.success() {
        bail!("the browser could not be started ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_addresses_only() {
        assert_eq!(
            web_url("https://github.com/login").unwrap(),
            "https://github.com/login"
        );
        assert_eq!(web_url("HTTP://example.com").unwrap(), "HTTP://example.com");
        assert_eq!(web_url(" github.com ").unwrap(), "https://github.com");
        for bad in [
            "cmd://calc.exe",
            "file:///etc/passwd",
            "javascript://x",
            "",
            "two words",
            "-flag",
        ] {
            assert!(web_url(bad).is_err(), "{bad}");
        }
    }
}
