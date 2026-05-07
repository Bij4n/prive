//! PGP keyserver operations.
//! Supports querying keys.openpgp.org via HKP (HTTP Keyserver Protocol).

const DEFAULT_KEYSERVER: &str = "https://keys.openpgp.org";

pub struct KeyserverClient {
    base_url: String,
}

impl Default for KeyserverClient {
    fn default() -> Self {
        Self::new()
    }
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
        let url = format!("{}/vks/v1/by-email/{}", self.base_url, urlencod(query));

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
            Err(format!("Keyserver returned status {}", response.status()))
        }
    }

    /// Fetch a key by fingerprint.
    pub fn get_by_fingerprint(&self, fingerprint: &str) -> Result<Option<String>, String> {
        let clean = fingerprint.replace(' ', "").to_uppercase();
        let url = format!("{}/vks/v1/by-fingerprint/{}", self.base_url, clean);

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
            Err(format!("Keyserver returned status {}", response.status()))
        }
    }

    /// Upload a public key to the keyserver.
    ///
    /// keys.openpgp.org requires email verification after upload — the server
    /// sends a verification link to each UID address. The returned token can
    /// be used to request re-verification via /vks/v1/request-verify.
    pub fn upload(&self, armored: &str) -> Result<UploadResponse, String> {
        let url = format!("{}/vks/v1/upload", self.base_url);

        let body = serde_json::json!({ "keytext": armored });

        let response = reqwest::blocking::Client::new()
            .post(&url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "prive-password-manager")
            .body(body.to_string())
            .send()
            .map_err(|e| format!("Keyserver upload failed: {e}"))?;

        if response.status().is_success() {
            let text = response
                .text()
                .map_err(|e| format!("Failed to read response: {e}"))?;
            let parsed: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("Invalid response JSON: {e}"))?;
            Ok(UploadResponse {
                token: parsed
                    .get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                key_fpr: parsed
                    .get("key_fpr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: parsed
                    .get("status")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        } else {
            Err(format!("Keyserver returned status {}", response.status()))
        }
    }

    /// Get the keyserver URL being used.
    pub fn url(&self) -> &str {
        &self.base_url
    }
}

#[derive(Debug)]
pub struct UploadResponse {
    pub token: String,
    pub key_fpr: String,
    /// Map of email address -> verification status ("unpublished", "published", etc.)
    pub status: std::collections::HashMap<String, String>,
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
