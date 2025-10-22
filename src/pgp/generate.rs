use pgp::composed::key::{SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::composed::{KeyType, SecretKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{CompressionAlgorithm, KeyVersion};
use rand::rngs::OsRng;
use smallvec::smallvec;

pub fn generate_keypair(
    name: &str,
    email: &str,
    algorithm: &str,
    passphrase: &str,
) -> Result<SignedSecretKey, String> {
    let mut rng = OsRng;

    let uid = if name.is_empty() && email.is_empty() {
        return Err("At least name or email is required".to_string());
    } else if name.is_empty() {
        format!("<{email}>")
    } else if email.is_empty() {
        name.to_string()
    } else {
        format!("{name} <{email}>")
    };
