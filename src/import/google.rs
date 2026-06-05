//! Google Password Manager and Chrome: Settings, Passwords, Export passwords.
//! Columns: `name,url,username,password,note` (older Chrome exports have no `note`).

use anyhow::Result;
use zeroize::Zeroizing;

use super::csvtable::Table;
use super::{Record, Report, title_from_url};

const KNOWN: [&str; 5] = ["name", "url", "username", "password", "note"];

pub fn parse(text: &str) -> Result<(Vec<Record>, Report)> {
    let table = Table::parse(text)?;
    anyhow::ensure!(
        table.has("url") && table.has("password"),
        "this doesn't look like a Google Password Manager export (no url and password columns)"
    );
    let mut records = Vec::new();
    for row in table.rows() {
        let url = row.get(&["url"]).to_string();
        let title = match row.get(&["name"]) {
            "" => title_from_url(&url),
            t => t.to_string(),
        };
        records.push(Record {
            title,
            username: row.get(&["username"]).to_string(),
            password: Zeroizing::new(row.get(&["password"]).to_string()),
            url,
            notes: row.get(&["note"]).to_string(),
            extra: row
                .others(&KNOWN)
                .into_iter()
                .map(|(k, v)| (k, v, false))
                .collect(),
            ..Record::default()
        });
    }
    let report = Report {
        records: records.len(),
        notes: Vec::new(),
    };
    Ok((records, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "name,url,username,password,note\n\
        github.com,https://github.com/login,demo,gh-pw,work account\n\
        ,https://www.example.invalid/,me,ex-pw,\n";

    #[test]
    fn reads_a_google_export() {
        let (records, report) = parse(SAMPLE).unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(records[0].title, "github.com");
        assert_eq!(records[0].username, "demo");
        assert_eq!(*records[0].password, "gh-pw");
        assert_eq!(records[0].notes, "work account");
        // No name: the site's host stands in.
        assert_eq!(records[1].title, "example.invalid");
    }

    #[test]
    fn older_chrome_exports_and_wrong_files() {
        let (records, _) = parse("name,url,username,password\nx,https://x.invalid,u,p\n").unwrap();
        assert_eq!(records[0].notes, "");
        assert!(parse("Title,Login\na,b\n").is_err());
    }
}
