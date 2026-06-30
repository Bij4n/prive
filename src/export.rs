//! `prive export`: every entry with its secrets, in plain text, for moving to another app or
//! keeping a printed copy. Nothing else in prive writes secrets out like this, so the command
//! asks to be told (`--plaintext`) and never writes to a terminal.
//!
//! Values are given as they are used: field references resolved, one-time codes as otpauth
//! URIs whatever form they are stored in. The recycle bin is left out, as everywhere else.
//! Attachments and earlier versions are not exported (`prive file` and `prive history` give
//! them).

use serde::Serialize;
use zeroize::Zeroizing;

use crate::entry::Entry;

/// The output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// KeePassXC's CSV columns: Group, Title, Username, Password, URL, Notes, TOTP, Icon,
    /// Last Modified, Created (groups written without the root's name)
    Csv,
    /// One object per entry, with every custom field and its tags
    Json,
}

/// The entry's one-time code setup as an otpauth URI (it holds the secret), or nothing.
fn otp_uri(e: &Entry) -> Zeroizing<String> {
    Zeroizing::new(
        crate::otp::Totp::from_entry(e)
            .map(|t| t.to_uri(&e.title, &e.username))
            .unwrap_or_default(),
    )
}

/// Serde writes a secret straight from its wiped-on-drop buffer.
fn secret<S: serde::Serializer>(v: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v)
}

fn time(t: Option<chrono::NaiveDateTime>) -> String {
    t.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// The CSV of `entries`, references resolved against `all`, in memory that is wiped when it
/// is dropped.
pub fn csv(entries: &[&Entry], all: &[Entry]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut w = csv::WriterBuilder::new()
        .quote_style(csv::QuoteStyle::Always)
        .from_writer(Vec::new());
    w.write_record([
        "Group",
        "Title",
        "Username",
        "Password",
        "URL",
        "Notes",
        "TOTP",
        "Icon",
        "Last Modified",
        "Created",
    ])?;
    for e in entries {
        let r = |v: &str| crate::refs::resolve(all, v);
        w.write_record([
            e.group.as_str(),
            r(&e.title).as_str(),
            r(&e.username).as_str(),
            r(&e.password).as_str(),
            r(&e.url).as_str(),
            r(&e.notes).as_str(),
            otp_uri(e).as_str(),
            "0",
            time(e.modified).as_str(),
            // prive doesn't keep the creation time; KeePassXC accepts an empty one.
            "",
        ])?;
    }
    let bytes = w.into_inner().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Zeroizing::new(bytes))
}

#[derive(Serialize)]
struct JsonField<'a> {
    name: &'a str,
    #[serde(serialize_with = "secret")]
    value: Zeroizing<String>,
    protected: bool,
}

#[derive(Serialize)]
struct JsonEntry<'a> {
    path: String,
    group: &'a str,
    #[serde(serialize_with = "secret")]
    title: Zeroizing<String>,
    #[serde(serialize_with = "secret")]
    username: Zeroizing<String>,
    #[serde(serialize_with = "secret")]
    password: Zeroizing<String>,
    #[serde(serialize_with = "secret")]
    url: Zeroizing<String>,
    #[serde(serialize_with = "secret")]
    notes: Zeroizing<String>,
    #[serde(serialize_with = "secret")]
    otp: Zeroizing<String>,
    tags: &'a [String],
    fields: Vec<JsonField<'a>>,
    uuid: &'a str,
    modified: Option<String>,
    expires: Option<String>,
}

/// The JSON of `entries`, references resolved against `all`, in memory that is wiped when it
/// is dropped.
pub fn json(entries: &[&Entry], all: &[Entry]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let r = |v: &str| crate::refs::resolve(all, v);
    let list: Vec<JsonEntry<'_>> = entries
        .iter()
        .copied()
        .map(|e| JsonEntry {
            path: e.path(),
            group: &e.group,
            title: r(&e.title),
            username: r(&e.username),
            password: r(&e.password),
            url: r(&e.url),
            notes: r(&e.notes),
            otp: otp_uri(e),
            tags: &e.tags,
            fields: e
                .custom
                .iter()
                .filter(|c| !crate::otp::is_otp_field(&c.name))
                .map(|c| JsonField {
                    name: &c.name,
                    value: r(&c.value),
                    protected: c.protected,
                })
                .collect(),
            uuid: &e.uuid,
            modified: e.modified.map(|t| time(Some(t))),
            expires: e.expires.map(|t| time(Some(t))),
        })
        .collect();
    let mut bytes = serde_json::to_vec_pretty(&list)?;
    bytes.push(b'\n');
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::CustomField;

    fn sample() -> Vec<Entry> {
        vec![
            Entry {
                uuid: "00000000000000000000000000000001".into(),
                group: "Work".into(),
                title: "GitHub".into(),
                username: "demo".into(),
                password: Zeroizing::new("pa\"ss,word".into()),
                url: "https://github.com".into(),
                notes: "line one\nline two".into(),
                custom: vec![
                    CustomField {
                        name: "otp".into(),
                        value: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
                        protected: true,
                    },
                    CustomField {
                        name: "API key".into(),
                        value: Zeroizing::new("k-1".into()),
                        protected: true,
                    },
                ],
                tags: vec!["dev".into()],
                ..Entry::default()
            },
            Entry {
                uuid: "00000000000000000000000000000002".into(),
                title: "Mirror".into(),
                password: Zeroizing::new("{REF:P@I:00000000000000000000000000000001}".into()),
                ..Entry::default()
            },
        ]
    }

    #[test]
    fn csv_in_keepassxc_columns_with_references_resolved() {
        let all = sample();
        let refs: Vec<&Entry> = all.iter().collect();
        let out = csv(&refs, &all).unwrap();
        let mut r = csv::Reader::from_reader(&out[..]);
        let header: Vec<String> = r.headers().unwrap().iter().map(str::to_string).collect();
        assert_eq!(
            header[..7],
            [
                "Group", "Title", "Username", "Password", "URL", "Notes", "TOTP"
            ]
        );
        let rows: Vec<csv::StringRecord> = r.records().map(Result::unwrap).collect();
        assert_eq!(&rows[0][0], "Work");
        assert_eq!(&rows[0][3], "pa\"ss,word", "quotes and commas survive");
        assert_eq!(&rows[0][5], "line one\nline two");
        assert!(rows[0][6].starts_with("otpauth://totp/"));
        assert_eq!(&rows[1][3], "pa\"ss,word", "the reference is resolved");
    }

    #[test]
    fn an_entry_exported_alone_still_gets_what_it_refers_to() {
        let all = sample();
        let out = csv(&[&all[1]], &all).unwrap();
        let mut r = csv::Reader::from_reader(&out[..]);
        let rows: Vec<csv::StringRecord> = r.records().map(Result::unwrap).collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(&rows[0][3], "pa\"ss,word");
    }

    #[test]
    fn json_has_fields_but_not_the_otp_setting_twice() {
        let all = sample();
        let refs: Vec<&Entry> = all.iter().collect();
        let out = json(&refs, &all).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v[0]["path"], "Work/GitHub");
        assert_eq!(v[0]["password"], "pa\"ss,word");
        assert!(v[0]["otp"].as_str().unwrap().starts_with("otpauth://"));
        let names: Vec<&str> = v[0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["API key"]);
        assert_eq!(v[1]["password"], "pa\"ss,word");
    }
}
