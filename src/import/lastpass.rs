//! LastPass: Account options, Advanced, Export (or the browser extension's Export).
//! Columns: `url,username,password,totp,extra,name,grouping,fav`.
//!
//! Folders come in `grouping` with `\` between levels. Secure notes have the URL
//! `http://sn` and their text in `extra`; structured ones (cards, addresses) put
//! `NoteType:...` and `Key:value` lines there, kept as the note text.

use anyhow::Result;
use zeroize::Zeroizing;

use super::csvtable::Table;
use super::{Record, Report, title_from_url};

const KNOWN: [&str; 8] = [
    "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
];
const SECURE_NOTE_URL: &str = "http://sn";

pub fn parse(text: &str) -> Result<(Vec<Record>, Report)> {
    let table = Table::parse(text)?;
    anyhow::ensure!(
        table.has("grouping") && table.has("extra"),
        "this doesn't look like a LastPass export (no grouping and extra columns)"
    );
    let mut records = Vec::new();
    let mut notes = 0;
    for row in table.rows() {
        let raw_url = row.get(&["url"]);
        let is_note = raw_url.eq_ignore_ascii_case(SECURE_NOTE_URL);
        let url = if is_note {
            String::new()
        } else {
            raw_url.to_string()
        };
        let title = match row.get(&["name"]) {
            "" if is_note => "Secure note".to_string(),
            "" => title_from_url(&url),
            t => t.to_string(),
        };
        let mut tags = Vec::new();
        if row.get(&["fav"]) == "1" {
            tags.push("favorite".to_string());
        }
        if is_note {
            notes += 1;
            tags.push("note".to_string());
        }
        let otp = match row.get(&["totp"]) {
            "" => None,
            v => Some(Zeroizing::new(v.to_string())),
        };
        records.push(Record {
            title,
            group: row.get(&["grouping"]).replace('\\', "/"),
            username: row.get(&["username"]).to_string(),
            password: Zeroizing::new(row.get(&["password"]).to_string()),
            url,
            notes: row.get(&["extra"]).to_string(),
            otp,
            tags,
            extra: row
                .others(&KNOWN)
                .into_iter()
                .map(|(k, v)| (k, v, false))
                .collect(),
        });
    }
    let mut report = Report {
        records: records.len(),
        notes: Vec::new(),
    };
    if notes > 0 {
        report.notes.push(format!(
            "{notes} secure note(s) came in as entries tagged \"note\", their text in the notes"
        ));
    }
    Ok((records, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "url,username,password,totp,extra,name,grouping,fav\n\
        https://github.com/login,demo,gh-pw,JBSWY3DPEHPK3PXP,,GitHub,Work\\Dev,1\n\
        http://sn,,,,\"NoteType:Credit Card\nNumber:4111\",Visa,Personal,0\n\
        https://example.invalid,me,ex-pw,,,,,0\n";

    #[test]
    fn reads_a_lastpass_export() {
        let (r, report) = parse(SAMPLE).unwrap();
        assert_eq!(report.records, 3);
        assert_eq!(r[0].group, "Work/Dev");
        assert_eq!(r[0].tags, ["favorite"]);
        assert_eq!(
            r[0].otp.as_deref().map(String::as_str),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(r[1].title, "Visa");
        assert_eq!(r[1].url, "");
        assert_eq!(r[1].tags, ["note"]);
        assert!(r[1].notes.contains("Number:4111"));
        assert_eq!(r[2].title, "example.invalid");
        assert_eq!(report.notes.len(), 1);
    }
}
