
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
