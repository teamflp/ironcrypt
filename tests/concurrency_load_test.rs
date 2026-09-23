//! Concurrency / load-shaped tests mirroring `ironcryptd` crypto paths
//! (semaphore-bounded wrap, parallel encrypt/decrypt).

use ironcrypt::algorithms::SymmetricAlgorithm;
use ironcrypt::crypto_provider::{CryptoProvider, LocalKeyProvider};
use ironcrypt::ecc_utils;
use ironcrypt::encrypt_stream;
use ironcrypt::keys::{PrivateKey, PublicKey};
use ironcrypt::limits::DEFAULT_CRYPTO_CONCURRENCY;
use ironcrypt::resilience::CircuitBreaker;
use ironcrypt::{decrypt_stream, Argon2Config, PasswordCriteria};
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

fn ecc_pair() -> (PrivateKey, PublicKey) {
    let (sk, pk) = ecc_utils::generate_ecc_keys().expect("ecc");
    (PrivateKey::Ecc(sk), PublicKey::Ecc(pk))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_local_provider_wrap_unwrap() {
    let (sk, pk) = ecc_pair();
    let provider = Arc::new(LocalKeyProvider::new("v1", pk, sk).expect("local provider"));
    let sem = Arc::new(Semaphore::new(DEFAULT_CRYPTO_CONCURRENCY.max(1)));
    let ok = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..32 {
        let provider = provider.clone();
        let sem = sem.clone();
        let ok = ok.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let mut dek = [0u8; 32];
            dek[0] = i as u8;
            dek[31] = 0xff;
            let wrapped = provider.wrap_key("v1", &dek).await.expect("wrap");
            let plain = provider
                .unwrap_key(&wrapped.key_id, &wrapped.ciphertext)
                .await
                .expect("unwrap");
            assert_eq!(plain.as_slice(), &dek);
            ok.fetch_add(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(ok.load(Ordering::SeqCst), 32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_encrypt_decrypt_streams() {
    let (sk, pk) = ecc_pair();
    let sk = Arc::new(sk);
    let pk = Arc::new(pk);
    let mut handles = Vec::new();

    for n in 0..16 {
        let sk = sk.clone();
        let pk = pk.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let payload = format!("load-test-payload-{n}").into_bytes();
            let mut source = Cursor::new(payload.clone());
            let mut encrypted = Cursor::new(Vec::new());
            let mut password = String::new();
            encrypt_stream(
                &mut source,
                &mut encrypted,
                &mut password,
                vec![(&*pk, "v1")],
                None,
                &PasswordCriteria::default(),
                Argon2Config::default(),
                false,
                SymmetricAlgorithm::Aes256Gcm,
            )
            .expect("encrypt");
            encrypted.set_position(0);
            let mut out = Cursor::new(Vec::new());
            decrypt_stream(&mut encrypted, &mut out, &*sk, "v1", "", None).expect("decrypt");
            assert_eq!(out.into_inner(), payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[test]
fn circuit_breaker_under_burst_failures() {
    let cb = Arc::new(CircuitBreaker::new(5, Duration::from_secs(30)));
    let threads: Vec<_> = (0..20)
        .map(|_| {
            let cb = cb.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    let _ = cb.guard();
                    cb.record_failure();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(cb.is_open(), "threshold should trip under concurrent failures");
}
