
use crate::vault::model::{Vault, VaultEntry};

/// Import entries from a CSV file (Chrome, Bitwarden, generic format).
pub fn import_csv(content: &str) -> Result<Vec<VaultEntry>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("Failed to read CSV headers: {e}"))?
        .clone();

    let header_lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();

    // Detect format by headers
    let name_col = find_column(&header_lower, &["name", "title", "login_name"]);
    let url_col = find_column(&header_lower, &["url", "login_uri", "website"]);
    let username_col = find_column(&header_lower, &["username", "login_username", "user"]);
    let password_col = find_column(&header_lower, &["password", "login_password", "pass"]);
    let notes_col = find_column(&header_lower, &["notes", "note", "comments"]);

    let password_col = password_col.ok_or_else(|| "Could not find password column".to_string())?;

    let mut entries = Vec::new();

    for result in reader.records() {
        let record = result.map_err(|e| format!("CSV parse error: {e}"))?;

        let name = name_col
            .and_then(|i| record.get(i))
            .unwrap_or("Imported")
            .to_string();
        let url = url_col
            .and_then(|i| record.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let username = username_col
            .and_then(|i| record.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let password = record
            .get(password_col)
            .unwrap_or("")
            .to_string();
        let notes = notes_col
            .and_then(|i| record.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        if password.is_empty() {
            continue;
        }

        entries.push(VaultEntry::new(name, username, password, url, notes, vec!["imported".to_string()]));
    }

    Ok(entries)
}

/// Import from Bitwarden JSON export.
pub fn import_bitwarden_json(content: &str) -> Result<Vec<VaultEntry>, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("JSON parse error: {e}"))?;

    let items = parsed
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing 'items' array in Bitwarden export".to_string())?;

    let mut entries = Vec::new();

    for item in items {
        let item_type = item.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
        if item_type != 1 {
            continue; // Only import login items
        }

        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Untitled")
            .to_string();

        let login = item.get("login");

        let username = login
            .and_then(|l| l.get("username"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let password = login
            .and_then(|l| l.get("password"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let url = login
            .and_then(|l| l.get("uris"))
            .and_then(|v| v.as_array())
            .and_then(|uris| uris.first())
            .and_then(|u| u.get("uri"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let notes = item
            .get("notes")
            .and_then(|v| v.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty());

        let totp = login
            .and_then(|l| l.get("totp"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if password.is_empty() {
            continue;
        }

        let mut tags = vec!["imported".to_string(), "bitwarden".to_string()];
