//! Reading other password managers' exports, so their passwords can move into a KeePass
//! database. Each format becomes a list of [`Record`]s; nothing is written here.
//!
//! The rule for every format: nothing is dropped without saying so. A value with no standard
//! place becomes a custom field; anything prive can't carry over is listed in the
//! [`Report`].

pub mod apple;
pub mod bitwarden;
pub mod csvtable;
pub mod generic;
pub mod google;
pub mod lastpass;
pub mod otp;
pub mod proton;

use zeroize::Zeroizing;

/// One login (or note, card, ...) as it came out of the other app.
#[derive(Default)]
pub struct Record {
    pub title: String,
    /// Folder or vault in the other app, as a `Group/Sub` path. Empty for none.
    pub group: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    /// An `otpauth://` URI, or a bare base32 secret, as the other app gave it.
    pub otp: Option<Zeroizing<String>>,
    pub tags: Vec<String>,
    /// Anything else worth keeping, by name, with whether it is secret.
    pub extra: Vec<(String, Zeroizing<String>, bool)>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("title", &self.title)
            .field("group", &self.group)
            .field("username", &self.username)
            .field("url", &self.url)
            .field("has_otp", &self.otp.is_some())
            .field(
                "extra",
                &self.extra.iter().map(|(n, _, _)| n).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// What an import did, for the user to check.
#[derive(Debug, Default)]
pub struct Report {
    pub records: usize,
    /// One line per thing that could not be carried over, or was changed on the way.
    pub notes: Vec<String>,
}

impl Report {
    /// The summary printed after reading an export.
    pub fn render(&self, records: &[Record]) -> String {
        let with_otp = records.iter().filter(|r| r.otp.is_some()).count();
        let groups: std::collections::BTreeSet<&str> = records
            .iter()
            .map(|r| r.group.as_str())
            .filter(|g| !g.is_empty())
            .collect();
        let empty_pw = records.iter().filter(|r| r.password.is_empty()).count();
        let codes = match with_otp {
            0 => "none with one-time codes".to_string(),
            1 => "1 with a one-time code".to_string(),
            n => format!("{n} with one-time codes"),
        };
        let groups = match groups.len() {
            0 => "no groups".to_string(),
            n => format!("in {}", plural(n, "group", "groups")),
        };
        let mut out = format!(
            "{}, {codes}, {groups}\n",
            plural(self.records, "entry", "entries")
        );
        match empty_pw {
            0 => {}
            1 => out.push_str("  1 has no password (kept as it is)\n"),
            n => out.push_str(&format!("  {n} have no password (kept as they are)\n")),
        }
        for note in &self.notes {
            out.push_str(&format!("  {note}\n"));
        }
        out
    }
}

/// `1 entry`, `3 entries`.
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `import --check --list`: one line per record, as it would come across. Never a secret:
/// fields are named, not shown.
pub fn render_list(records: &[Record]) -> String {
    let mut out = String::new();
    for r in records {
        let path = if r.group.is_empty() {
            r.title.clone()
        } else {
            format!("{}/{}", r.group, r.title)
        };
        let mut line = format!("  {path}");
        if !r.username.is_empty() {
            line.push_str(&format!("  ({})", r.username));
        }
        if let Some((_, host, _)) = crate::gitcred::split_url(&r.url) {
            line.push_str(&format!("  {host}"));
        }
        if r.otp.is_some() {
            line.push_str("  2fa");
        }
        if r.password.is_empty() {
            line.push_str("  no password");
        }
        if !r.extra.is_empty() {
            let names: Vec<&str> = r.extra.iter().map(|(n, _, _)| n.as_str()).collect();
            line.push_str(&format!("  + {}", names.join(", ")));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// `import --check --json`: the report and every record, by name only. Never a password, a
/// code's secret or a field's value.
pub fn json_report(format: Format, records: &[Record], report: &Report) -> serde_json::Value {
    let list: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "title": r.title,
                "group": r.group,
                "username": r.username,
                "url": r.url,
                "tags": r.tags,
                "has_password": !r.password.is_empty(),
                "has_otp": r.otp.is_some(),
                "fields": r.extra.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "format": format.label(),
        "entries": report.records,
        "notes": report.notes,
        "records": list,
    })
}

/// The export formats prive reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Proton Pass's CSV export
    Proton,
    /// Apple Passwords / Safari's CSV export
    Apple,
    /// Google Password Manager / Chrome's CSV export
    Google,
    /// LastPass's CSV export
    Lastpass,
    /// Bitwarden's CSV export
    Bitwarden,
    /// Any other CSV (1Password, Dashlane, KeePassXC, ...), by column names.
    Csv,
}

impl Format {
    /// Every format, for whatever needs to try them all (the fuzz target does).
    pub const ALL: [Format; 6] = [
        Format::Proton,
        Format::Apple,
        Format::Google,
        Format::Lastpass,
        Format::Bitwarden,
        Format::Csv,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Format::Proton => "Proton Pass",
            Format::Apple => "Apple Passwords",
            Format::Google => "Google Password Manager",
            Format::Lastpass => "LastPass",
            Format::Bitwarden => "Bitwarden",
            Format::Csv => "CSV",
        }
    }

    /// Read an export. `map` (`field`, `Column`) pairs only apply to the generic CSV format.
    pub fn parse(
        self,
        text: &str,
        map: &[(String, String)],
    ) -> anyhow::Result<(Vec<Record>, Report)> {
        if !map.is_empty() && self != Format::Csv {
            anyhow::bail!("--map only applies with --from csv");
        }
        let (mut records, mut report) = match self {
            Format::Proton => proton::parse(text),
            Format::Apple => apple::parse(text),
            Format::Google => google::parse(text),
            Format::Lastpass => lastpass::parse(text),
            Format::Bitwarden => bitwarden::parse(text),
            Format::Csv => generic::parse(text, map),
        }?;
        tidy_otp(&mut records, &mut report);
        Ok((records, report))
    }

    /// Recognise an export from its header line. The most specific formats are checked first.
    pub fn detect(text: &str) -> Option<Format> {
        let table = csvtable::Table::parse(text).ok()?;
        if table.has("vault") && table.has("type") {
            Some(Format::Proton)
        } else if table.has("grouping") && table.has("extra") {
            Some(Format::Lastpass)
        } else if table.has("login_uri") && table.has("login_password") {
            Some(Format::Bitwarden)
        } else if is_apple(&table) {
            Some(Format::Apple)
        } else if table.has("name")
            && table.has("url")
            && table.has("password")
            && table.headers().len() <= 5
        {
            Some(Format::Google)
        } else if table.has("password") || table.has("login_password") {
            Some(Format::Csv)
        } else {
            None
        }
    }
}

/// Apple's exports have exactly these columns (the older ones without OTPAuth). Others share
/// some of them, 1Password's OTPAuth and KeePassXC's Title and Notes among them, but have
/// more (tags, groups): those go to the generic reader, which keeps them.
fn is_apple(table: &csvtable::Table) -> bool {
    const APPLE: [&str; 6] = ["title", "url", "username", "password", "notes", "otpauth"];
    let n = table.headers().len();
    (n == 6 && APPLE.iter().all(|c| table.has(c)))
        || (n == 5 && APPLE[..5].iter().all(|c| table.has(c)))
}

/// Put every one-time code into the otpauth form KeePass apps read. One that can't be read is
/// not thrown away: it stays on the entry as a field named `otp (unreadable)`, and the report
/// says which entries to fix by hand.
pub fn tidy_otp(records: &mut [Record], report: &mut Report) {
    let mut unreadable = Vec::new();
    for r in records.iter_mut() {
        let Some(raw) = r.otp.take() else { continue };
        match otp::normalize(&raw, &r.title, &r.username) {
            Some(uri) => r.otp = Some(uri),
            None => {
                unreadable.push(r.title.clone());
                r.extra.push(("otp (unreadable)".to_string(), raw, true));
            }
        }
    }
    if !unreadable.is_empty() {
        report.notes.push(format!(
            "{} couldn't be read and kept as a field to fix by hand: {}",
            plural(unreadable.len(), "one-time code", "one-time codes"),
            unreadable.join(", ")
        ));
    }
}

/// A title for an entry that came without one: the host of its URL, without `www.`.
pub fn title_from_url(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() {
        "untitled".to_string()
    } else {
        host.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_never_print_secrets() {
        let r = Record {
            title: "Bank".into(),
            password: Zeroizing::new("hunter2".into()),
            otp: Some(Zeroizing::new("otpauth://totp/x?secret=ABC".into())),
            extra: vec![("PIN".into(), Zeroizing::new("1234".into()), true)],
            ..Record::default()
        };
        let shown = format!("{r:?}");
        assert!(!shown.contains("hunter2") && !shown.contains("ABC") && !shown.contains("1234"));
        assert!(shown.contains("PIN") && shown.contains("has_otp: true"));
    }

    #[test]
    fn titles_from_urls() {
        assert_eq!(
            title_from_url("https://www.GitHub.com/login?x=1"),
            "github.com"
        );
        assert_eq!(
            title_from_url("http://user@host.invalid:8080/a"),
            "host.invalid"
        );
        assert_eq!(title_from_url("example.org"), "example.org");
        assert_eq!(title_from_url(""), "untitled");
    }

    #[test]
    fn all_lists_every_format() {
        assert_eq!(
            Format::ALL.as_slice(),
            <Format as clap::ValueEnum>::value_variants()
        );
    }

    #[test]
    fn formats_are_recognised_from_their_headers() {
        let cases = [
            (
                "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n",
                Format::Proton,
            ),
            (
                "url,username,password,totp,extra,name,grouping,fav\n",
                Format::Lastpass,
            ),
            ("Title,URL,Username,Password,Notes,OTPAuth\n", Format::Apple),
            ("Title,URL,Username,Password,Notes\n", Format::Apple),
            (
                "Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created\n",
                Format::Csv,
            ),
            // 1Password's CSV has Apple's OTPAuth column, and its own tags.
            (
                "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n",
                Format::Csv,
            ),
            ("name,url,username,password,note\n", Format::Google),
            ("name,url,username,password\n", Format::Google),
        ];
        for (header, want) in cases {
            assert_eq!(Format::detect(header), Some(want), "{header}");
        }
        assert_eq!(Format::detect("a,b,c\n"), None);
        assert_eq!(
            Format::detect(
                "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            ),
            Some(Format::Bitwarden)
        );
    }

    #[test]
    fn report_summary() {
        let (records, report) = lastpass::parse(
            "url,username,password,totp,extra,name,grouping,fav\n\
             https://a.invalid,u,p,JBSWY3DPEHPK3PXP,,A,Work,0\n\
             http://sn,,,,text,Note,Personal,0\n",
        )
        .unwrap();
        let text = report.render(&records);
        assert!(
            text.starts_with("2 entries, 1 with a one-time code, in 2 groups\n"),
            "{text}"
        );
        assert!(text.contains("1 has no password (kept as it is)"));
        assert!(text.contains("secure note"));
    }

    #[test]
    fn unreadable_codes_are_kept_and_reported() {
        let mut records = vec![
            Record {
                title: "Good".into(),
                otp: Some(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
                ..Record::default()
            },
            Record {
                title: "Bad".into(),
                otp: Some(Zeroizing::new("not base32!".into())),
                ..Record::default()
            },
        ];
        let mut report = Report::default();
        tidy_otp(&mut records, &mut report);
        assert!(
            records[0]
                .otp
                .as_ref()
                .unwrap()
                .starts_with("otpauth://totp/Good?")
        );
        assert!(records[1].otp.is_none());
        assert_eq!(records[1].extra[0].0, "otp (unreadable)");
        assert_eq!(*records[1].extra[0].1, "not base32!");
        assert!(report.notes[0].contains("Bad"));
    }
}
