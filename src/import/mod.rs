//! Reading other password managers' exports, so their passwords can move into a KeePass
//! database. Each format becomes a list of [`Record`]s; nothing is written here.
//!
//! The rule for every format: nothing is dropped without saying so. A value with no standard
//! place becomes a custom field; anything prive can't carry over is listed in the
//! [`Report`].

pub mod apple;
pub mod csvtable;
pub mod google;
pub mod lastpass;
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
        let mut out = format!(
            "{} entries, {} with one-time codes, in {} group(s)\n",
            self.records,
            with_otp,
            groups.len()
        );
        if empty_pw > 0 {
            out.push_str(&format!(
                "  {empty_pw} have no password (kept as they are)\n"
            ));
        }
        for note in &self.notes {
            out.push_str(&format!("  {note}\n"));
        }
        out
    }
}

/// The export formats prive reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Proton,
    Apple,
    Google,
    Lastpass,
}

impl Format {
    pub fn parse(self, text: &str) -> anyhow::Result<(Vec<Record>, Report)> {
        match self {
            Format::Proton => proton::parse(text),
            Format::Apple => apple::parse(text),
            Format::Google => google::parse(text),
            Format::Lastpass => lastpass::parse(text),
        }
    }

    /// Recognise an export from its header line. The most specific formats are checked first.
    pub fn detect(text: &str) -> Option<Format> {
        let table = csvtable::Table::parse(text).ok()?;
        if table.has("vault") && table.has("type") {
            Some(Format::Proton)
        } else if table.has("grouping") && table.has("extra") {
            Some(Format::Lastpass)
        } else if table.has("otpauth") || (table.has("title") && table.has("notes")) {
            Some(Format::Apple)
        } else if table.has("name") && table.has("url") && table.has("password") {
            Some(Format::Google)
        } else {
            None
        }
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
            ("name,url,username,password,note\n", Format::Google),
            ("name,url,username,password\n", Format::Google),
        ];
        for (header, want) in cases {
            assert_eq!(Format::detect(header), Some(want), "{header}");
        }
        assert_eq!(Format::detect("a,b,c\n"), None);
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
            text.starts_with("2 entries, 1 with one-time codes, in 2 group(s)\n"),
            "{text}"
        );
        assert!(text.contains("1 have no password"));
        assert!(text.contains("secure note"));
    }
}
