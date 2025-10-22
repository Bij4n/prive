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
