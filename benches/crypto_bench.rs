use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_password_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_generation");

    for length in [8, 16, 32, 64, 128] {
        group.bench_with_input(BenchmarkId::new("random", length), &length, |b, &len| {
            b.iter(|| {
                prive::crypto::password_gen::generate_password(black_box(len), true, true, true)
            });
        });
    }

    for words in [4, 6, 8, 12] {
        group.bench_with_input(BenchmarkId::new("passphrase", words), &words, |b, &w| {
            b.iter(|| prive::crypto::password_gen::generate_passphrase(black_box(w), "-"));
        });
    }

    group.bench_function("pin_6", |b| {
        b.iter(|| prive::crypto::password_gen::generate_pin(black_box(6)));
    });

    group.bench_function("pronounceable_12", |b| {
        b.iter(|| prive::crypto::password_gen::generate_pronounceable(black_box(12)));
    });

    group.finish();
}

fn bench_vault_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_crypto");

    // Bench Argon2 key derivation (the expensive part)
    let salt = [0u8; 32];
    let password = b"benchmark-password-123";

    group.sample_size(10); // Argon2 is slow
    group.bench_function("argon2id_derive_key", |b| {
        b.iter(|| {
            prive::vault::crypto::VaultCrypto::derive_key(black_box(password), black_box(&salt))
        });
    });

    // Bench AES-256-GCM encrypt/decrypt
    group.sample_size(100);
    let small_data = vec![0u8; 1024]; // 1KB
    group.bench_function("encrypt_1kb", |b| {
        b.iter(|| {
            prive::vault::crypto::VaultCrypto::encrypt(black_box(&small_data), black_box(password))
        });
    });

    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    group.sample_size(10);
    group.bench_function("encrypt_1mb", |b| {
        b.iter(|| {
            prive::vault::crypto::VaultCrypto::encrypt(black_box(&large_data), black_box(password))
        });
    });

    group.finish();
}

fn bench_password_entropy(c: &mut Criterion) {
    let passwords = [
        "abc",
        "Password123!",
        "xK9#mP2$vL7@nQ4!wR8%",
        "correct-horse-battery-staple",
    ];

    c.bench_function("password_entropy", |b| {
        b.iter(|| {
            for pw in &passwords {
                black_box(prive::crypto::password_gen::password_entropy(pw));
            }
        });
    });
}

fn bench_totp(c: &mut Criterion) {
    let secret = b"12345678901234567890";

    c.bench_function("totp_generate", |b| {
        b.iter(|| {
            prive::crypto::totp::generate_totp_at(
                black_box(secret),
                black_box(1234567890),
                black_box(30),
                black_box(6),
            )
        });
    });

    c.bench_function("base32_decode", |b| {
        b.iter(|| prive::crypto::totp::decode_base32_secret(black_box("JBSWY3DPEHPK3PXP")));
    });
}

criterion_group!(
    benches,
    bench_password_generation,
    bench_vault_crypto,
    bench_password_entropy,
    bench_totp,
);
criterion_main!(benches);
