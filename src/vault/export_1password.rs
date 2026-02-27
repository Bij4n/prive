use serde_json::json;

use crate::vault::model::Vault;

/// Export vault to 1Password-compatible 1PIF (JSON) format.
pub fn export_1password(vault: &Vault) -> Result<String, String> {
    let mut items = Vec::new();

    for entry in &vault.entries {
        let mut fields = vec![
            json!({
                "designation": "username",
                "name": "username",
                "type": "T",
                "value": entry.username.as_deref().unwrap_or("")
            }),
            json!({
                "designation": "password",
                "name": "password",
                "type": "P",
                "value": entry.password
            }),
        ];

        if let Some(url) = &entry.url {
            fields.push(json!({
                "designation": "url",
                "name": "url",
                "type": "T",
                "value": url
            }));
        }

        let item = json!({
            "uuid": entry.id.to_string(),
            "typeName": "webforms.WebForm",
            "title": entry.name,
            "secureContents": {
                "fields": fields,
                "notesPlain": entry.notes.as_deref().unwrap_or("")
            },
            "openContents": {
                "tags": entry.tags
            },
            "createdAt": entry.created_at.timestamp(),
            "updatedAt": entry.modified_at.timestamp(),
            "location": entry.url.as_deref().unwrap_or("")
        });

        items.push(item);
    }

    // 1PIF format: each item on its own line, separated by "***"
    let lines: Vec<String> = items
        .iter()
        .map(|item| serde_json::to_string(item).unwrap_or_default())
        .collect();

    Ok(lines.join("\n***\n"))
}

/// Export vault to 1Password CSV format (simpler alternative).
pub fn export_1password_csv(vault: &Vault) -> String {
    let mut output = String::from("title,website,username,password,notes,type\n");

    for entry in &vault.entries {
        output.push_str(&format!(
            "{},{},{},{},{},login\n",
            csv_escape(&entry.name),
            csv_escape(entry.url.as_deref().unwrap_or("")),
            csv_escape(entry.username.as_deref().unwrap_or("")),
            csv_escape(&entry.password),
            csv_escape(entry.notes.as_deref().unwrap_or("")),
        ));
    }

    // Also export secure notes
    for note in &vault.secure_notes {
        output.push_str(&format!(
            "{},,,,{},note\n",
            csv_escape(&note.title),
            csv_escape(&note.content),
        ));
    }

    output
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
    use crate::vault::model::{SecureNote, VaultEntry};

    #[test]
    fn test_export_1password_json() {
        let mut vault = Vault::new();
        vault.entries.push(VaultEntry::new(
            "GitHub".into(),
            Some("johnd".into()),
            "secret123".into(),
            Some("https://github.com".into()),
            Some("dev account".into()),
            vec!["dev".into()],
        ));

        let result = export_1password(&vault).unwrap();
        assert!(result.contains("GitHub"));
        assert!(result.contains("secret123"));
        assert!(result.contains("webforms.WebForm"));
    }

    #[test]
    fn test_export_1password_csv() {
        let mut vault = Vault::new();
        vault.entries.push(VaultEntry::new(
            "Test".into(),
            Some("user".into()),
            "pass".into(),
            Some("https://test.com".into()),
            None,
            vec![],
        ));
        vault.secure_notes.push(SecureNote::new(
            "API Key".into(),
            "sk-12345".into(),
            vec![],
        ));

        let csv = export_1password_csv(&vault);
        assert!(csv.contains("Test"));
        assert!(csv.contains("login"));
        assert!(csv.contains("API Key"));
        assert!(csv.contains("note"));
    }

    #[test]
    fn test_export_1password_empty_vault() {
        let vault = Vault::new();
        let result = export_1password(&vault).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_csv_escape_special_chars() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
