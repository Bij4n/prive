//! Have I Been Pwned "Pwned Passwords" range lookups.
//!
//! Only the first five hex characters of the password's SHA-1 hash are sent. The service
//! answers with every hash suffix in that range and the match happens here. `Add-Padding`
//! asks for padded responses so their size doesn't hint at which range was asked for.
//! See <https://haveibeenpwned.com/API/v3#PwnedPasswords>.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use sha1::{Digest, Sha1};

const API: &str = "https://api.pwnedpasswords.com/range/";

/// Requests in flight at once. The range API has no rate limit; eight keeps a 5,000-entry
/// audit to well under a minute without hammering it.
const WORKERS: usize = 8;

/// How many times each password appears in known breaches (0 if none), in the same order.
/// Passwords whose hashes share a five-character prefix cost one request between them.
/// `progress(done, total)` is called as requests finish.
pub fn breach_counts(
    passwords: &[&str],
    progress: impl Fn(usize, usize) + Sync,
) -> Result<Vec<u64>> {
    breach_counts_with(passwords, fetch_range, progress)
}

/// [`breach_counts`] with the fetching passed in, so it can be tested without the network.
fn breach_counts_with(
    passwords: &[&str],
    fetch: impl Fn(&str) -> Result<String> + Sync,
    progress: impl Fn(usize, usize) + Sync,
) -> Result<Vec<u64>> {
    let hashes: Vec<String> = passwords
        .iter()
        .map(|p| hex::encode_upper(Sha1::digest(p.as_bytes())))
        .collect();
    let mut prefixes: Vec<&str> = hashes.iter().map(|h| &h[..5]).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let ranges: Mutex<HashMap<&str, Result<String>>> = Mutex::new(HashMap::new());
    std::thread::scope(|s| {
        for _ in 0..WORKERS.min(prefixes.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(prefix) = prefixes.get(i) else { break };
                    let body = fetch(prefix);
                    ranges
                        .lock()
                        .expect("no thread panics holding it")
                        .insert(prefix, body);
                    progress(done.fetch_add(1, Ordering::Relaxed) + 1, prefixes.len());
                }
            });
        }
    });
    let mut ranges = ranges.into_inner().expect("the threads have finished");
    let mut bodies: HashMap<&str, String> = HashMap::new();
    for prefix in &prefixes {
        let body = ranges.remove(prefix).expect("every prefix was fetched")?;
        bodies.insert(prefix, body);
    }
    Ok(hashes
        .iter()
        .map(|h| count_in_range(&bodies[&h[..5]], &h[5..]))
        .collect())
}

/// One HTTP client for every lookup, with a time limit: a network that hangs fails the
/// check after 30 seconds instead of keeping `audit` waiting for ever.
fn agent() -> &'static ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into()
    })
}

fn fetch_range(prefix: &str) -> Result<String> {
    agent()
        .get(format!("{API}{prefix}"))
        .header("Add-Padding", "true")
        .header("User-Agent", concat!("prive/", env!("CARGO_PKG_VERSION")))
        .call()
        .context("contacting Have I Been Pwned")?
        .body_mut()
        .read_to_string()
        .context("reading the Have I Been Pwned response")
}

fn count_in_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_passwords_one_request_per_prefix() {
        // SHA-1("password") starts 5BAA6; "hunter2" starts F3BBB.
        let asked = Mutex::new(Vec::new());
        let fetch = |prefix: &str| -> Result<String> {
            asked.lock().unwrap().push(prefix.to_string());
            Ok(match prefix {
                "5BAA6" => "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n".into(),
                _ => "0000000000000000000000000000000000A:1\r\n".into(),
            })
        };
        let counts =
            breach_counts_with(&["password", "hunter2", "password"], fetch, |_, _| {}).unwrap();
        assert_eq!(counts, [9545824, 0, 9545824]);
        let mut asked = asked.into_inner().unwrap();
        asked.sort();
        assert_eq!(
            asked,
            ["5BAA6", "F3BBB"],
            "one request each, the repeat costs none"
        );
    }

    #[test]
    fn a_failed_request_fails_the_check() {
        let fetch = |_: &str| -> Result<String> { anyhow::bail!("offline") };
        assert!(breach_counts_with(&["x"], fetch, |_, _| {}).is_err());
        assert!(
            breach_counts_with(&[], fetch, |_, _| {})
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn finds_the_suffix_in_a_range() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let body = "1D2DA4053E34E76F6576ED1DA63134B5E2A:2\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n\
                    0000000000000000000000000000000000A:0\r\n";
        assert_eq!(
            count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            9545824
        );
        assert_eq!(
            count_in_range(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"),
            9545824
        );
        assert_eq!(count_in_range(body, "FFFFF"), 0);
        // Padding rows carry a count of 0 and never match a real hash by accident.
        assert_eq!(
            count_in_range(body, "0000000000000000000000000000000000A"),
            0
        );
    }

    /// Talks to the real service, so it is opt-in: `cargo test -- --ignored`.
    #[test]
    #[ignore = "needs the network"]
    fn the_real_service_knows_a_famous_password() {
        let counts = breach_counts(&["password"], |_, _| {}).unwrap();
        assert!(counts[0] > 1_000_000);
    }
}
