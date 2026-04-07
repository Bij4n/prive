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
        let password = record.get(password_col).unwrap_or("").to_string();
        let notes = notes_col
            .and_then(|i| record.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        if password.is_empty() {
            continue;
        }

        entries.push(VaultEntry::new(
            name,
            username,
            password,
            url,
            notes,
            vec!["imported".to_string()],
        ));
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

        let folder_id = item.get("folderId").and_then(|v| v.as_str());
        if let Some(fid) = folder_id {
            tags.push(format!("folder:{fid}"));
        }

        let mut entry = VaultEntry::new(name, username, password, url, notes, tags);
        entry.totp_secret = totp;
        entries.push(entry);
    }

    Ok(entries)
}

/// Import from KeePass XML export.
pub fn import_keepass_xml(content: &str) -> Result<Vec<VaultEntry>, String> {
    // Simple XML parsing for KeePass format
    let mut entries = Vec::new();
    let mut in_entry = false;
    let mut current_name = String::new();
    let mut current_username = String::new();
    let mut current_password = String::new();
    let mut current_url = String::new();
    let mut current_notes = String::new();
    let mut current_key = String::new();
    let _in_value = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "<Entry>" {
            in_entry = true;
            current_name.clear();
            current_username.clear();
            current_password.clear();
            current_url.clear();
            current_notes.clear();
        } else if trimmed == "</Entry>" && in_entry {
            if !current_password.is_empty() {
                entries.push(VaultEntry::new(
                    if current_name.is_empty() {
                        "Imported".to_string()
                    } else {
                        current_name.clone()
                    },
                    if current_username.is_empty() {
                        None
                    } else {
                        Some(current_username.clone())
                    },
                    current_password.clone(),
                    if current_url.is_empty() {
                        None
                    } else {
                        Some(current_url.clone())
                    },
                    if current_notes.is_empty() {
                        None
                    } else {
                        Some(current_notes.clone())
                    },
                    vec!["imported".to_string(), "keepass".to_string()],
                ));
            }
            in_entry = false;
        } else if in_entry {
            if let Some(key) = extract_xml_value(trimmed, "Key") {
                current_key = key;
            } else if let Some(value) = extract_xml_value(trimmed, "Value") {
                match current_key.as_str() {
                    "Title" => current_name = value,
                    "UserName" => current_username = value,
                    "Password" => current_password = value,
                    "URL" => current_url = value,
                    "Notes" => current_notes = value,
                    _ => {}
                }
            }
        }
    }

    Ok(entries)
}

/// Export vault entries to CSV format.
pub fn export_csv(vault: &Vault) -> String {
    let mut output = String::from("name,username,password,url,notes,tags\n");

    for entry in &vault.entries {
        output.push_str(&format!(
            "{},{},{},{},{},{}\n",
            csv_escape(&entry.name),
            csv_escape(entry.username.as_deref().unwrap_or("")),
            csv_escape(&entry.password),
            csv_escape(entry.url.as_deref().unwrap_or("")),
            csv_escape(entry.notes.as_deref().unwrap_or("")),
            csv_escape(&entry.tags.join(";")),
        ));
    }

    output
}

/// Export vault to Bitwarden-compatible JSON.
pub fn export_bitwarden_json(vault: &Vault) -> Result<String, String> {
    let items: Vec<serde_json::Value> = vault
        .entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "type": 1,
                "name": e.name,
                "login": {
                    "username": e.username,
                    "password": e.password,
                    "uris": e.url.as_ref().map(|u| vec![serde_json::json!({"uri": u})]).unwrap_or_default(),
                    "totp": e.totp_secret,
                },
                "notes": e.notes,
            })
        })
        .collect();

    let export = serde_json::json!({
        "encrypted": false,
        "items": items,
    });

    serde_json::to_string_pretty(&export).map_err(|e| format!("JSON error: {e}"))
}

fn find_column(headers: &[String], candidates: &[&str]) -> Option<usize> {
    for candidate in candidates {
        if let Some(idx) = headers.iter().position(|h| h == *candidate) {
            return Some(idx);
        }
    }
    None
}

fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = line.find(&open)
        && let Some(end) = line.find(&close)
    {
        let value_start = start + open.len();
        if value_start < end {
            return Some(xml_unescape(&line[value_start..end]));
        }
    }
    None
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_csv_chrome_format() {
        let csv = "name,url,username,password\nGitHub,https://github.com,johnd,mypassword\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "GitHub");
        assert_eq!(entries[0].password, "mypassword");
        assert_eq!(entries[0].username.as_deref(), Some("johnd"));
    }

    #[test]
    fn test_import_csv_bitwarden_format() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,,Test,,,,https://test.com,user,pass123,\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password, "pass123");
    }

    #[test]
    fn test_import_csv_skips_empty_passwords() {
        let csv = "name,password\nEmpty,\nValid,pass123\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Valid");
    }

    #[test]
    fn test_import_bitwarden_json() {
        let json = r#"{
            "encrypted": false,
            "items": [
                {
                    "type": 1,
                    "name": "GitHub",
                    "login": {
                        "username": "johnd",
                        "password": "secret123",
                        "uris": [{"uri": "https://github.com"}]
                    },
                    "notes": null
                },
                {
                    "type": 2,
                    "name": "Secure Note"
                }
            ]
        }"#;

        let entries = import_bitwarden_json(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "GitHub");
        assert_eq!(entries[0].password, "secret123");
    }

    #[test]
    fn test_import_keepass_xml() {
        let xml = r#"<?xml version="1.0"?>
<KeePassFile>
<Root>
<Group>
<Entry>
<String>
<Key>Title</Key>
<Value>Test Entry</Value>
</String>
<String>
<Key>UserName</Key>
<Value>testuser</Value>
</String>
<String>
<Key>Password</Key>
<Value>testpass</Value>
</String>
<String>
<Key>URL</Key>
<Value>https://example.com</Value>
</String>
</Entry>
</Group>
</Root>
</KeePassFile>"#;

        let entries = import_keepass_xml(xml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Test Entry");
        assert_eq!(entries[0].password, "testpass");
    }

    #[test]
    fn test_export_csv() {
        let mut vault = Vault::new();
        vault.entries.push(VaultEntry::new(
            "GitHub".to_string(),
            Some("johnd".to_string()),
            "secret".to_string(),
            Some("https://github.com".to_string()),
            None,
            vec!["dev".to_string()],
        ));
        let csv = export_csv(&vault);
        assert!(csv.contains("GitHub"));
        assert!(csv.contains("johnd"));
        assert!(csv.contains("secret"));
    }

    #[test]
    fn test_export_bitwarden_json() {
        let mut vault = Vault::new();
        vault.entries.push(VaultEntry::new(
            "Test".to_string(),
            Some("user".to_string()),
            "pass".to_string(),
            None,
            None,
            vec![],
        ));
        let json = export_bitwarden_json(&vault).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["items"][0]["name"], "Test");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_xml_unescape() {
        assert_eq!(xml_unescape("a &amp; b"), "a & b");
        assert_eq!(xml_unescape("&lt;tag&gt;"), "<tag>");
    }
}
