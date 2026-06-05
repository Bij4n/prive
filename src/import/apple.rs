//! Apple Passwords (macOS and iOS) and Safari: File, Export, All Passwords.
//! Columns: `Title,URL,Username,Password,Notes,OTPAuth`.

use anyhow::Result;
use zeroize::Zeroizing;

use super::csvtable::Table;
use super::{Record, Report, title_from_url};

const KNOWN: [&str; 6] = ["title", "url", "username", "password", "notes", "otpauth"];

pub fn parse(text: &str) -> Result<(Vec<Record>, Report)> {
    let table = Table::parse(text)?;
    anyhow::ensure!(
        table.has("title") && table.has("password"),
        "this doesn't look like an Apple Passwords export (no Title and Password columns)"
    );
    let mut records = Vec::new();
    for row in table.rows() {
        let url = row.get(&["url"]).to_string();
        let title = match row.get(&["title"]) {
            "" => title_from_url(&url),
            t => t.to_string(),
        };
        let otp = match row.get(&["otpauth"]) {
            "" => None,
            v => Some(Zeroizing::new(v.to_string())),
        };
        records.push(Record {
            title,
            username: row.get(&["username"]).to_string(),
            password: Zeroizing::new(row.get(&["password"]).to_string()),
            url,
            notes: row.get(&["notes"]).to_string(),
            otp,
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

    const SAMPLE: &str = "Title,URL,Username,Password,Notes,OTPAuth\n\
        github.com (demo),https://github.com/,demo,gh-pw,,otpauth://totp/GitHub:demo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n\
        Bank,https://bank.invalid/,me,b-pw,\"Account 1234\nBranch 5\",\n";

    #[test]
    fn reads_an_apple_export_with_codes() {
        let (records, report) = parse(SAMPLE).unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(records[0].title, "github.com (demo)");
        let otp = records[0].otp.as_ref().unwrap();
        assert!(otp.starts_with("otpauth://totp/"));
        // And the code it describes is readable by prive.
        assert!(crate::otp::parse_otpauth(otp).is_some());
        assert!(records[1].otp.is_none());
        assert_eq!(records[1].notes, "Account 1234\nBranch 5");
    }

    #[test]
    fn not_an_apple_file() {
        assert!(parse("name,url,username,password\n").is_err());
    }
}
