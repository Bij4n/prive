#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::config;
use crate::vault::model::Vault;

fn socket_path() -> PathBuf {
    config::data_dir().join("agent.sock")
}

/// Check if an agent is currently running.
pub fn is_agent_running() -> bool {
    #[cfg(unix)]
    {
        let path = socket_path();
        if !path.exists() {
            return false;
        }
        // Try to connect
        match UnixStream::connect(&path) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = writeln!(stream, r#"{{"cmd":"ping"}}"#);
                let mut reader = BufReader::new(&stream);
                let mut response = String::new();
                if reader.read_line(&mut response).is_ok() {
                    response.contains("ok")
                } else {
                    false
                }
            }
            Err(_) => {
                // Stale socket, clean up
                let _ = std::fs::remove_file(&path);
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Try to get the vault from a running agent.
pub fn get_vault_from_agent() -> Option<Vault> {
    #[cfg(unix)]
    {
        let path = socket_path();
        let mut stream = UnixStream::connect(&path).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;

        writeln!(stream, r#"{{"cmd":"get_vault"}}"#).ok()?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).ok()?;

        let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;
        if let Some(vault_str) = parsed.get("vault").and_then(|v| v.as_str()) {
            serde_json::from_str(vault_str).ok()
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Stop a running agent.
pub fn stop_agent() -> bool {
    #[cfg(unix)]
    {
        let path = socket_path();
        if let Ok(mut stream) = UnixStream::connect(&path) {
            let _ = writeln!(stream, r#"{{"cmd":"lock"}}"#);
            let _ = std::fs::remove_file(&path);
            return true;
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Start the agent in the current process (blocking).
#[cfg(unix)]
pub fn start_agent(vault: &Vault, timeout_secs: u64) -> Result<(), String> {
    let path = socket_path();

    // Clean up stale socket
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create socket dir: {e}"))?;
    }

    let listener = UnixListener::bind(&path)
        .map_err(|e| format!("Failed to bind socket: {e}"))?;

    // Set permissions to user-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    let vault_json = serde_json::to_string(vault)
        .map_err(|e| format!("Serialization error: {e}"))?;

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set nonblocking: {e}"))?;

    loop {
        if start.elapsed() > timeout {
            let _ = std::fs::remove_file(&path);
            return Ok(()); // Timed out, clean exit
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                if let Err(should_exit) = handle_client(stream, &vault_json) {
                    if should_exit {
                        let _ = std::fs::remove_file(&path);
                        return Ok(());
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(unix)]
fn handle_client(
    stream: UnixStream,
    vault_json: &str,
) -> Result<(), bool> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();

    if reader.read_line(&mut line).is_err() {
        return Ok(());
    }

    let parsed: serde_json::Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let cmd = parsed.get("cmd").and_then(|v| v.as_str()).unwrap_or("");

    let mut writer = stream.try_clone().map_err(|_| false)?;

    match cmd {
        "ping" => {
            let _ = writeln!(writer, r#"{{"status":"ok"}}"#);
        }
        "get_vault" => {
            let escaped = vault_json.replace('\\', "\\\\").replace('"', "\\\"");
            let _ = writeln!(writer, r#"{{"vault":"{}"}}"#, escaped);
        }
        "lock" => {
            let _ = writeln!(writer, r#"{{"status":"locked"}}"#);
            return Err(true); // Signal to exit
        }
        _ => {
            let _ = writeln!(writer, r#"{{"error":"unknown command"}}"#);
        }
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn start_agent(_vault: &Vault, _timeout_secs: u64) -> Result<(), String> {
    Err("Agent mode is not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path() {
        let path = socket_path();
        assert!(path.to_string_lossy().contains("prive"));
        assert!(path.to_string_lossy().ends_with("agent.sock"));
    }

    #[test]
    fn test_is_agent_running_when_not_started() {
        assert!(!is_agent_running());
    }

    #[test]
    fn test_get_vault_from_agent_when_not_started() {
        assert!(get_vault_from_agent().is_none());
    }

    #[test]
    fn test_stop_agent_when_not_started() {
        assert!(!stop_agent());
    }
}
