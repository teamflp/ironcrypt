//! Reproducible crypto micro-benchmarks (AES-GCM, XChaCha, ECC stream).
//!
//! ```bash
//! cargo bench -p ironcrypt --bench crypto_bench --features cli
//! # HTML report under target/criterion/
//! ```
//!
//! KMS/HSM benches are **not** included here (require live backends). Measure
//! those with `crypto_provider_*` Prometheus histograms against a staging HSM/KMS.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ironcrypt::algorithms::SymmetricAlgorithm;
use ironcrypt::ecc_utils;
use ironcrypt::encrypt_stream;
use ironcrypt::keys::{PrivateKey, PublicKey};
use ironcrypt::{decrypt_stream, Argon2Config, PasswordCriteria};
use std::io::Cursor;
use std::time::Duration;

fn ecc_pair() -> (PrivateKey, PublicKey) {
    let (sk, pk) = ecc_utils::generate_ecc_keys().expect("ecc");
    (PrivateKey::Ecc(sk), PublicKey::Ecc(pk))
}

fn bench_encrypt_decrypt(c: &mut Criterion, name: &str, algo: SymmetricAlgorithm, size: usize) {
    let (sk, pk) = ecc_pair();
    let payload = vec![0xA5u8; size];
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Bytes(size as u64));
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    group.bench_function("encrypt_stream", |b| {
        b.iter(|| {
            let mut src = Cursor::new(payload.clone());
            let mut dst = Cursor::new(Vec::with_capacity(size + 512));
            let mut password = String::new();
            encrypt_stream(
                &mut src,
                &mut dst,
                &mut password,
                vec![(&pk, "v1")],
                None,
                &PasswordCriteria::default(),
                Argon2Config::default(),
                false,
                algo,
            )
            .expect("encrypt");
            black_box(dst.into_inner());
        });
    });

    // Pre-encrypt once for decrypt bench.
    let mut src = Cursor::new(payload.clone());
    let mut enc = Cursor::new(Vec::new());
    let mut password = String::new();
    encrypt_stream(
        &mut src,
        &mut enc,
        &mut password,
        vec![(&pk, "v1")],
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        algo,
    )
    .expect("encrypt setup");
    let ciphertext = enc.into_inner();

    group.bench_function("decrypt_stream", |b| {
        b.iter(|| {
            let mut src = Cursor::new(ciphertext.clone());
            let mut out = Cursor::new(Vec::with_capacity(size));
            decrypt_stream(&mut src, &mut out, &sk, "v1", "", None).expect("decrypt");
            black_box(out.into_inner());
        });
    });

    group.finish();
}

fn benches(c: &mut Criterion) {
    for &size in &[1024usize, 64 * 1024, 1024 * 1024] {
        bench_encrypt_decrypt(
            c,
            &format!("aes256gcm/{size}"),
            SymmetricAlgorithm::Aes256Gcm,
            size,
        );
        bench_encrypt_decrypt(
            c,
            &format!("xchacha20poly1305/{size}"),
            SymmetricAlgorithm::ChaCha20Poly1305,
            size,
        );
    }
}

criterion_group!(crypto, benches);
criterion_main!(crypto);
