//! A git credential helper: git asks for the username and password of an HTTPS remote, and
//! prive answers from the entry whose URL has that host.
//! See <https://git-scm.com/docs/git-credential> for the protocol.

use crate::entry::Entry;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub username: String,
}

/// Git's `key=value` lines, up to a blank line or the end.
pub fn parse_request(text: &str) -> Request {
    let mut r = Request::default();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "protocol" => r.protocol = v.to_string(),
                "host" => r.host = v.to_lowercase(),
                "path" => r.path = v.to_string(),
                "username" => r.username = v.to_string(),
                _ => {}
            }
        }
    }
    r
}

/// `(scheme, host, path)` of an entry URL, the host with any port. A bare `github.com` has
/// no scheme.
pub fn split_url(url: &str) -> Option<(String, String, String)> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => (String::new(), url),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if host.is_empty() {
        return None;
    }
    Some((scheme, host.to_lowercase(), path.to_string()))
}

fn same_host(a: &str, b: &str) -> bool {
    a.trim_start_matches("www.") == b.trim_start_matches("www.")
}

/// The entries that fit a request. More than one fit only when git sent a path that tells
/// them apart (`credential.useHttpPath`).
pub fn matches<'a>(entries: &'a [Entry], req: &Request) -> Vec<&'a Entry> {
    let fits: Vec<(&Entry, String)> = entries
        .iter()
        .filter_map(|e| split_url(&e.url).map(|parts| (e, parts)))
        .filter(|(_, (scheme, host, _))| {
            same_host(host, &req.host) && (scheme.is_empty() || *scheme == req.protocol)
        })
        .filter(|(e, _)| req.username.is_empty() || e.username == req.username)
        .map(|(e, (_, _, path))| (e, path))
        .collect();
    if fits.len() > 1 && !req.path.is_empty() {
        let by_path: Vec<&Entry> = fits
            .iter()
            .filter(|(_, p)| !p.is_empty() && req.path.starts_with(p.trim_end_matches('/')))
            .map(|(e, _)| *e)
            .collect();
        if !by_path.is_empty() {
            return by_path;
        }
    }
    fits.into_iter().map(|(e, _)| e).collect()
}

/// The answer git reads.
pub fn answer(entry: &Entry) -> String {
    format!(
        "username={}\npassword={}\n",
        entry.username,
        entry.password.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn entry(title: &str, url: &str, user: &str) -> Entry {
        Entry {
            uuid: title.into(),
            title: title.into(),
            url: url.into(),
            username: user.into(),
            password: Zeroizing::new(format!("{title}-pw")),
            ..Entry::default()
        }
    }

    #[test]
    fn reads_gits_request() {
        let r = parse_request(
            "protocol=https\nhost=GitHub.com\npath=org/repo.git\nusername=demo\n\nignored=1\n",
        );
        assert_eq!(
            r,
            Request {
                protocol: "https".into(),
                host: "github.com".into(),
                path: "org/repo.git".into(),
                username: "demo".into()
            }
        );
    }

    #[test]
    fn finds_by_host_scheme_and_username() {
        let e = vec![
            entry("gh", "https://github.com/login", "demo"),
            entry("gh2", "https://www.github.com", "other"),
            entry("gl", "gitlab.com", "me"),
            entry("plain", "http://github.com", "demo"),
        ];
        let req = |host: &str, user: &str| Request {
            protocol: "https".into(),
            host: host.into(),
            username: user.into(),
            ..Request::default()
        };
        assert_eq!(matches(&e, &req("github.com", "demo")).len(), 1);
        assert_eq!(matches(&e, &req("github.com", "")).len(), 2);
        assert_eq!(
            matches(&e, &req("gitlab.com", "")).len(),
            1,
            "a bare host fits any scheme"
        );
        assert!(matches(&e, &req("example.com", "")).is_empty());
        assert_eq!(
            answer(matches(&e, &req("gitlab.com", ""))[0]),
            "username=me\npassword=gl-pw\n"
        );
    }

    #[test]
    fn a_path_tells_two_entries_on_one_host_apart() {
        let e = vec![
            entry("work", "https://git.example.invalid/work", "w"),
            entry("home", "https://git.example.invalid/home", "h"),
        ];
        let r = Request {
            protocol: "https".into(),
            host: "git.example.invalid".into(),
            path: "home/dotfiles.git".into(),
            ..Request::default()
        };
        let m = matches(&e, &r);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].title, "home");
    }
}
