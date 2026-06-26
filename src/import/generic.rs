//! Any other CSV export, by matching its column names to KeePass's fields.
//!
//! The usual names are recognised (`title` or `name`, `username` or `login`, `url` or
//! `website`, ...), which covers the CSV exports of Bitwarden, 1Password and Dashlane among
//! others. `--map field=Column` overrides the guess for a field. Columns left over are kept as
//! custom fields.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use super::csvtable::Table;
use super::{Record, Report, title_from_url};

const FIELDS: [(&str, &[&str]); 8] = [
    ("title", &["title", "name", "entry", "account", "item"]),
    (
        "group",
        &["group", "folder", "vault", "category", "grouping"],
    ),
    (
        "username",
        &["username", "login_username", "login", "user", "email"],
    ),
    ("password", &["password", "login_password", "pass"]),
    ("url", &["url", "login_uri", "website", "uri", "site"]),
    ("notes", &["notes", "note", "comments", "comment", "extra"]),
    (
        "otp",
        &["totp", "login_totp", "otpauth", "otp", "otpsecret"],
    ),
    ("tags", &["tags", "labels"]),
];

/// `field=Column` overrides from `--map`.
pub fn parse_map(specs: &[String]) -> Result<Vec<(String, String)>> {
    specs
        .iter()
        .map(|s| {
            let Some((field, column)) = s.split_once('=') else {
                bail!("--map '{s}': expected field=Column");
            };
            let field = field.trim().to_lowercase();
            if !FIELDS.iter().any(|(f, _)| *f == field) {
                bail!(
                    "--map '{s}': unknown field '{field}' (use {})",
                    FIELDS.map(|(f, _)| f).join(", ")
                );
            }
            Ok((field, column.trim().to_string()))
        })
        .collect()
}

pub fn parse(text: &str, map: &[(String, String)]) -> Result<(Vec<Record>, Report)> {
    let table = Table::parse(text)?;
    // For each field, the column it comes from, if any.
    let column = |field: &str| -> Option<String> {
        if let Some((_, c)) = map.iter().find(|(f, _)| f == field) {
            return Some(c.clone());
        }
        let names = FIELDS.iter().find(|(f, _)| *f == field).map(|(_, n)| *n)?;
        // A column given to one field with --map is never guessed into another as well.
        let mapped = |n: &str| map.iter().any(|(_, c)| c.eq_ignore_ascii_case(n));
        names
            .iter()
            .find(|n| table.has(n) && !mapped(n))
            .map(|n| (*n).to_string())
    };
    for (field, col) in map {
        if !table.has(col) {
            bail!("--map {field}={col}: there is no column '{col}'");
        }
    }
    let Some(password_col) = column("password") else {
        bail!("no password column found; name it with --map password=COLUMN");
    };
    let cols: Vec<(&str, Option<String>)> = FIELDS.iter().map(|(f, _)| (*f, column(f))).collect();
    let used: Vec<String> = cols.iter().filter_map(|(_, c)| c.clone()).collect();
    let used_refs: Vec<&str> = used.iter().map(String::as_str).collect();
    let get = |row: &super::csvtable::Row<'_>, field: &str| -> String {
        cols.iter()
            .find(|(f, _)| *f == field)
            .and_then(|(_, c)| c.as_deref())
            .map(|c| row.get(&[c]).to_string())
            .unwrap_or_default()
    };

    let mut records = Vec::new();
    for row in table.rows() {
        let url = get(&row, "url");
        let title = match get(&row, "title") {
            t if t.is_empty() => title_from_url(&url),
            t => t,
        };
        let otp = Some(get(&row, "otp"))
            .filter(|o| !o.is_empty())
            .map(Zeroizing::new);
        let tags = get(&row, "tags")
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();
        records.push(Record {
            title,
            group: get(&row, "group").replace('\\', "/"),
            username: get(&row, "username"),
            password: Zeroizing::new(row.get(&[password_col.as_str()]).to_string()),
            url,
            notes: get(&row, "notes"),
            otp,
            tags,
            extra: row
                .others(&used_refs)
                .into_iter()
                .map(|(k, v)| (k, v, false))
                .collect(),
        });
    }
    let mapping: Vec<String> = cols
        .iter()
        .filter_map(|(f, c)| c.as_ref().map(|c| format!("{f} <- {c}")))
        .collect();
    let report = Report {
        records: records.len(),
        notes: vec![format!("columns used: {}", mapping.join(", "))],
    };
    Ok((records, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_csv_by_its_own_names() {
        let text = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    Work,1,login,GitHub,,,0,https://github.com,demo,gh-pw,JBSWY3DPEHPK3PXP\n";
        let (r, report) = parse(text, &[]).unwrap();
        assert_eq!(r[0].title, "GitHub");
        assert_eq!(r[0].group, "Work");
        assert_eq!(r[0].username, "demo");
        assert_eq!(*r[0].password, "gh-pw");
        assert!(r[0].otp.is_some());
        let kept: Vec<&str> = r[0].extra.iter().map(|(k, _, _)| k.as_str()).collect();
        assert_eq!(kept, ["favorite", "type", "reprompt"]);
        assert!(report.notes[0].contains("username <- login_username"));
    }

    #[test]
    fn onepassword_csv_and_tags() {
        let text = "Title,Website,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                    Bank,https://bank.invalid,me,b-pw,,false,false,\"money, important\",\n";
        let (r, _) = parse(text, &[]).unwrap();
        assert_eq!(r[0].url, "https://bank.invalid");
        assert_eq!(r[0].tags, ["money", "important"]);
    }

    #[test]
    fn maps_override_guesses_and_are_checked() {
        let text = "Site,Who,Secret\nexample,me,pw\n";
        assert!(parse(text, &[]).is_err(), "no password column to guess");
        let map = parse_map(&[
            "title=Site".into(),
            "username=Who".into(),
            "password=Secret".into(),
        ])
        .unwrap();
        let (r, _) = parse(text, &map).unwrap();
        assert_eq!(
            (r[0].title.as_str(), r[0].username.as_str()),
            ("example", "me")
        );
        // "Site" went to the title; it isn't also guessed as the URL.
        assert_eq!(r[0].url, "");
        assert!(parse_map(&["colour=Site".into()]).is_err());
        assert!(parse(text, &[("password".into(), "Nope".into())]).is_err());
    }
}
