/// Hardware key integration for vault unlock.
/// Currently a stub — prepared for Yubikey/FIDO2 integration.

pub trait HardwareKeyProvider {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn challenge_response(&self, challenge: &[u8]) -> Result<Vec<u8>, String>;
}

/// Stub provider that always reports no hardware key.
pub struct StubProvider;

impl HardwareKeyProvider for StubProvider {
    fn name(&self) -> &str {
        "none"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn challenge_response(&self, _challenge: &[u8]) -> Result<Vec<u8>, String> {
        Err("No hardware key available".to_string())
    }
}

/// Yubikey provider (stub — reports not implemented).
pub struct YubikeyProvider;

impl YubikeyProvider {
    pub fn detect() -> Option<Self> {
        // TODO: Use yubico-rs or similar to detect Yubikey
        None
    }
}

impl HardwareKeyProvider for YubikeyProvider {
    fn name(&self) -> &str {
        "yubikey"
    }

    fn is_available(&self) -> bool {
        // TODO: Actually check for Yubikey presence
        false
    }

    fn challenge_response(&self, _challenge: &[u8]) -> Result<Vec<u8>, String> {
        Err("Yubikey support not yet implemented".to_string())
    }
}

/// Get the best available hardware key provider.
pub fn get_provider() -> Box<dyn HardwareKeyProvider> {
    if let Some(yk) = YubikeyProvider::detect() {
        Box::new(yk)
    } else {
        Box::new(StubProvider)
    }
}

/// Derive additional key material from hardware key challenge-response.
/// This would be combined with the master password for enhanced security.
pub fn hardware_augmented_key(
    password: &[u8],
    provider: &dyn HardwareKeyProvider,
) -> Result<Vec<u8>, String> {
    if !provider.is_available() {
        return Err("No hardware key available".to_string());
    }

    // Use password hash as challenge
    let challenge = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.finalize().to_vec()
    };

    let response = provider.challenge_response(&challenge)?;

    // XOR password-derived bytes with hardware response
    let mut augmented = password.to_vec();
    for (i, byte) in response.iter().enumerate() {
        if i < augmented.len() {
            augmented[i] ^= byte;
        } else {
            augmented.push(*byte);
        }
    }

    Ok(augmented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_provider() {
        let provider = StubProvider;
        assert!(!provider.is_available());
        assert_eq!(provider.name(), "none");
        assert!(provider.challenge_response(b"test").is_err());
    }

    #[test]
    fn test_yubikey_detect_returns_none() {
        assert!(YubikeyProvider::detect().is_none());
    }

    #[test]
    fn test_get_provider_returns_stub() {
        let provider = get_provider();
        assert!(!provider.is_available());
        assert_eq!(provider.name(), "none");
    }

    #[test]
    fn test_hardware_augmented_key_fails_without_hw() {
        let provider = StubProvider;
        let result = hardware_augmented_key(b"password", &provider);
        assert!(result.is_err());
    }
}
