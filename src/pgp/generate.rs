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

    let (primary_key_type, subkey_type, version) = match algorithm.to_lowercase().as_str() {
        "cv25519" | "curve25519" | "ed25519" => (
            KeyType::EdDSALegacy,
            KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519),
            KeyVersion::V4,
        ),
        "rsa4096" | "rsa" => (
            KeyType::Rsa(4096),
            KeyType::Rsa(4096),
            KeyVersion::V4,
        ),
        other => return Err(format!("Unsupported algorithm: {other}. Use cv25519 or rsa4096")),
    };

    let key_params = SecretKeyParamsBuilder::default()
        .version(version)
        .key_type(primary_key_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(uid.clone())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_256,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .version(version)
                .key_type(subkey_type)
                .can_encrypt(true)
                .build()
