/// PGP keyserver operations.
/// Supports querying keys.openpgp.org via HKP (HTTP Keyserver Protocol).

const DEFAULT_KEYSERVER: &str = "https://keys.openpgp.org";

pub struct KeyserverClient {
    base_url: String,
}

impl KeyserverClient {
    pub fn new() -> Self {
        Self {
            base_url: DEFAULT_KEYSERVER.to_string(),
        }
    }

    pub fn with_url(url: &str) -> Self {
        Self {
            base_url: url.trim_end_matches('/').to_string(),
        }
    }

    /// Search for a key by email or key ID.
    pub fn search(&self, query: &str) -> Result<Option<String>, String> {
        let url = format!(
            "{}/vks/v1/by-email/{}",
            self.base_url,
            urlencod(query)
        );

        let response = reqwest::blocking::Client::new()
            .get(&url)
            .header("User-Agent", "prive-password-manager")
            .send()
            .map_err(|e| format!("Keyserver request failed: {e}"))?;

        if response.status().is_success() {
            let body = response
                .text()
                .map_err(|e| format!("Failed to read response: {e}"))?;
            Ok(Some(body))
        } else if response.status().as_u16() == 404 {
            Ok(None)
        } else {
            Err(format!(
                "Keyserver returned status {}",
                response.status()
            ))
        }
    }

    /// Fetch a key by fingerprint.
    pub fn get_by_fingerprint(&self, fingerprint: &str) -> Result<Option<String>, String> {
        let clean = fingerprint.replace(' ', "").to_uppercase();
        let url = format!(
            "{}/vks/v1/by-fingerprint/{}",
            self.base_url, clean
        );

        let response = reqwest::blocking::Client::new()
            .get(&url)
            .header("User-Agent", "prive-password-manager")
            .send()
            .map_err(|e| format!("Keyserver request failed: {e}"))?;

        if response.status().is_success() {
            let body = response
                .text()
                .map_err(|e| format!("Failed to read response: {e}"))?;
            Ok(Some(body))
        } else if response.status().as_u16() == 404 {
            Ok(None)
        } else {
            Err(format!(
                "Keyserver returned status {}",
                response.status()
            ))
        }
    }

    /// Get the keyserver URL being used.
    pub fn url(&self) -> &str {
        &self.base_url
    }
}

fn urlencod(s: &str) -> String {
    s.replace('@', "%40")
        .replace('+', "%2B")
        .replace(' ', "%20")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyserver_client_new() {
        let client = KeyserverClient::new();
        assert_eq!(client.url(), DEFAULT_KEYSERVER);
    }

    #[test]
    fn test_keyserver_client_custom_url() {
        let client = KeyserverClient::with_url("https://custom.keyserver.example/");
        assert_eq!(client.url(), "https://custom.keyserver.example");
    }

    #[test]
    fn test_urlencode() {
        assert_eq!(urlencod("user@example.com"), "user%40example.com");
        assert_eq!(urlencod("hello world"), "hello%20world");
    }
}
