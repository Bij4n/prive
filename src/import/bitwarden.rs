//! Bitwarden's CSV export: the generic reader does the columns (`login_uri`,
//! `login_username`, ...), and this adds what only Bitwarden does. Secure notes (rows of type
//! `note`) are tagged `note`, and the custom fields Bitwarden packs into one `fields` column,
//! one `name: value` a line, become fields of their own. The CSV doesn't say which of them
//! were hidden in Bitwarden, so all are kept protected.

use anyhow::Result;
use zeroize::Zeroizing;

use super::csvtable::Table;
use super::{Record, Report};

/// The custom fields in Bitwarden's `fields` cell: `name: value` lines. A line without `: `
/// is kept whole under the name `field`.
fn split_fields(cell: &str) -> Vec<(String, Zeroizing<String>, bool)> {
    cell.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| match l.split_once(": ") {
            Some((name, value)) if !name.trim().is_empty() => (
                name.trim().to_string(),
                Zeroizing::new(value.to_string()),
                true,
            ),
            _ => ("field".to_string(), Zeroizing::new(l.to_string()), true),
        })
        .collect()
}

pub fn parse(text: &str) -> Result<(Vec<Record>, Report)> {
    let (mut records, mut report) = super::generic::parse(text, &[])?;
    let table = Table::parse(text)?;
    let mut notes = 0;
    let mut fields = 0;
    // The generic reader made one record per row, in order.
    for (record, row) in records.iter_mut().zip(table.rows()) {
        if row.get(&["type"]).trim().eq_ignore_ascii_case("note") {
            record.tags.push("note".to_string());
            notes += 1;
        }
        if let Some(i) = record
            .extra
            .iter()
            .position(|(name, _, _)| name.eq_ignore_ascii_case("fields"))
        {
            let (_, cell, _) = record.extra.remove(i);
            let found = split_fields(&cell);
            fields += found.len();
            record.extra.extend(found);
        }
    }
    if notes > 0 {
        report.notes.push(format!(
            "{} came in as entries tagged \"note\"",
            super::plural(notes, "secure note", "secure notes")
        ));
    }
    if fields > 0 {
        report.notes.push(format!(
            "{} from Bitwarden's fields column, kept protected",
            super::plural(fields, "custom field", "custom fields")
        ));
    }
    Ok((records, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n";

    #[test]
    fn notes_and_custom_fields() {
        let text = format!(
            "{HEADER}Work,0,login,AWS,,\"Account ID: 1234\nregion: eu-west-1\",0,https://aws.amazon.com,ops,pw,\n\
             ,0,note,Wi-Fi,the code is on the router,,0,,,,\n"
        );
        let (r, report) = parse(&text).unwrap();
        let names: Vec<&str> = r[0].extra.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, ["Account ID", "region"]);
        assert_eq!(*r[0].extra[1].1, "eu-west-1");
        assert!(r[0].extra.iter().all(|(_, _, secret)| *secret));
        assert_eq!(r[1].tags, ["note"]);
        assert_eq!(r[1].notes, "the code is on the router");
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.starts_with("1 secure note came in"))
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.starts_with("2 custom fields"))
        );
    }

    #[test]
    fn odd_field_lines_are_kept() {
        assert_eq!(split_fields("no colon here")[0].0, "field");
        assert!(split_fields("\n  \n").is_empty());
        assert_eq!(
            split_fields("url: https://x.invalid/a:b")[0].1.as_str(),
            "https://x.invalid/a:b"
        );
    }
}
