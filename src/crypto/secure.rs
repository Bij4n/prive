use zeroize::Zeroize;

/// A string that zeroes its memory on drop.
#[derive(Clone)]
#[allow(dead_code)]
pub struct SecureString(Vec<u8>);

#[allow(dead_code)]
impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s.into_bytes())
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
