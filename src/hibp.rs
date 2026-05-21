//! Have I Been Pwned "Pwned Passwords" range lookups.
//!
//! Only the first five hex characters of the password's SHA-1 hash are sent. The service
//! answers with every hash suffix in that range and the match happens here. `Add-Padding`
//! asks for padded responses so their size doesn't hint at which range was asked for.
//! See <https://haveibeenpwned.com/API/v3#PwnedPasswords>.

use std::collections::HashMap;

use anyhow::{Context, Result};
use sha1::{Digest, Sha1};

const API: &str = "https://api.pwnedpasswords.com/range/";

/// How many times the password appears in known breaches (0 if none). Lookups are cached per
/// hash for the life of `cache`, so reused passwords cost one request.
pub fn breach_count(password: &str, cache: &mut HashMap<String, u64>) -> Result<u64> {
    let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
    if let Some(n) = cache.get(&hash) {
        return Ok(*n);
    }
    let (prefix, suffix) = hash.split_at(5);
    let count = count_in_range(&fetch_range(prefix)?, suffix);
    cache.insert(hash, count);
    Ok(count)
}

fn fetch_range(prefix: &str) -> Result<String> {
    ureq::get(format!("{API}{prefix}"))
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
}
