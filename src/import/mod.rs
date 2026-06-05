//! Reading other password managers' exports, so their passwords can move into a KeePass
//! database. Each format becomes a list of [`Record`]s; nothing is written here.
//!
//! The rule for every format: nothing is dropped without saying so. A value with no standard
//! place becomes a custom field; anything prive can't carry over is listed in the
//! [`Report`].

pub mod apple;
pub mod csvtable;
pub mod google;

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
}
