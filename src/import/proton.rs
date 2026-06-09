//! Proton Pass: Settings, Export, CSV.
//! Columns: `type,name,url,email,username,password,note,totp,createTime,modifyTime,vault`.
//!
//! Each vault becomes a group. Proton keeps an email and a username per login; KeePass has
//! one username field, so the username wins and the email is kept as an `email` field (or
//! becomes the username when there is none). Proton's CSV leaves out custom fields; their
//! JSON export has them.

use std::collections::BTreeMap;

use anyhow::Result;
use zeroize::Zeroizing;

use super::csvtable::Table;
use super::{Record, Report, title_from_url};

const KNOWN: [&str; 11] = [
    "type",
    "name",
    "url",
    "email",
    "username",
    "password",
    "note",
    "totp",
    "createtime",
    "modifytime",
    "vault",
];

pub fn parse(text: &str) -> Result<(Vec<Record>, Report)> {
    let table = Table::parse(text)?;
    anyhow::ensure!(
        table.has("vault") && table.has("type") && table.has("password"),
        "this doesn't look like a Proton Pass CSV export (no type, vault and password columns)"
    );
    let mut records = Vec::new();
    let mut not_logins: BTreeMap<String, usize> = BTreeMap::new();
    for row in table.rows() {
        let kind = row.get(&["type"]).to_lowercase();
        if !kind.is_empty() && kind != "login" {
            *not_logins.entry(kind.clone()).or_default() += 1;
        }
        let url = row
            .get(&["url"])
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let title = match row.get(&["name"]) {
            "" => title_from_url(&url),
            t => t.to_string(),
        };
        let email = row.get(&["email"]);
        let user = row.get(&["username"]);
        let (username, mut extra) = match (user.is_empty(), email.is_empty()) {
            (false, false) => (
                user.to_string(),
                vec![(
                    "email".to_string(),
                    Zeroizing::new(email.to_string()),
                    false,
                )],
            ),
            (true, _) => (email.to_string(), Vec::new()),
            (false, true) => (user.to_string(), Vec::new()),
        };
        let all_urls: Vec<&str> = row.get(&["url"]).split(',').map(str::trim).collect();
        if all_urls.len() > 1 {
            extra.push((
                "other URLs".to_string(),
                Zeroizing::new(all_urls[1..].join("\n")),
                false,
            ));
        }
        extra.extend(row.others(&KNOWN).into_iter().map(|(k, v)| (k, v, false)));
        let otp = match row.get(&["totp"]) {
            "" => None,
            v => Some(Zeroizing::new(v.to_string())),
        };
        let mut tags = Vec::new();
        if !kind.is_empty() && kind != "login" {
            tags.push(kind);
        }
        records.push(Record {
            title,
            group: row.get(&["vault"]).to_string(),
            username,
            password: Zeroizing::new(row.get(&["password"]).to_string()),
            url,
            notes: row.get(&["note"]).to_string(),
            otp,
            tags,
            extra,
        });
    }
    let mut report = Report {
        records: records.len(),
        notes: Vec::new(),
    };
    for (kind, n) in not_logins {
        report.notes.push(format!(
            "{n} {kind} item(s): Proton's CSV only has their name and note; its JSON export \
             has the rest"
        ));
    }
    Ok((records, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
        login,GitHub,\"https://github.com, https://gist.github.com\",me@example.invalid,demo,gh-pw,,otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP,1716200000,1716300000,Work\n\
        login,Shop,https://shop.invalid,buyer@example.invalid,,s-pw,size M,,1716200000,1716300000,Personal\n\
        note,Wi-Fi codes,,,,,\"guest: 1234\",,1716200000,1716300000,Personal\n";

    #[test]
    fn reads_a_proton_export() {
        let (r, report) = parse(SAMPLE).unwrap();
        assert_eq!(report.records, 3);
        assert_eq!(r[0].group, "Work");
        assert_eq!(r[0].username, "demo");
        assert_eq!(r[0].url, "https://github.com");
        let names: Vec<&str> = r[0].extra.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, ["email", "other URLs"]);
        assert!(r[0].otp.is_some());
        // No username: the email takes its place.
        assert_eq!(r[1].username, "buyer@example.invalid");
        assert_eq!(r[2].tags, ["note"]);
        assert_eq!(r[2].notes, "guest: 1234");
        assert_eq!(report.notes.len(), 1);
        assert!(report.notes[0].starts_with("1 note item(s)"));
    }

    #[test]
    fn not_a_proton_file() {
        assert!(parse("url,username,password\n").is_err());
    }
}
