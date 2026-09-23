//! Known Answer Tests (KAT) for core primitives used by IronCrypt.
//!
//! Vectors are public standards (NIST / RFC). These do **not** certify FIPS/ANSSI
//! compliance of the IronCrypt binary — they check our wiring of upstream crates.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::SecretKey;
use sha2::Sha256;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// AES-256-GCM empty-message vector (key/IV all-zero).
///
/// Tag is the stable output of the `aes-gcm` crate for these inputs (regression KAT).
#[test]
fn aes256_gcm_all_zero_empty_message() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let tag_expected = hex("530f8afbc74536b9a963b4f1c4cb738b");

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let out = cipher
        .encrypt(nonce, Payload { msg: b"", aad: b"" })
        .unwrap();
    assert_eq!(out, tag_expected);

    let recovered = cipher
        .decrypt(nonce, Payload { msg: &out, aad: b"" })
        .unwrap();
    assert!(recovered.is_empty());
}

/// AES-256-GCM encrypt/decrypt round-trip with fixed key/nonce/AAD (integrity KAT).
#[test]
fn aes256_gcm_fixed_roundtrip_with_aad() {
    let key = hex(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    );
    let iv = hex("0102030405060708090a0b0c");
    let aad = b"ironcrypt-kat-aad";
    let pt = b"known-answer-plaintext";

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: pt,
                aad,
            },
        )
        .unwrap();
    // Ciphertext+tag must be deterministic for fixed inputs.
    let ct2 = cipher
        .encrypt(
            nonce,
            Payload {
                msg: pt,
                aad,
            },
        )
        .unwrap();
    assert_eq!(ct, ct2);
    assert_eq!(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ct,
                    aad,
                },
            )
            .unwrap(),
        pt
    );
    assert!(cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: b"wrong-aad",
            },
        )
        .is_err());
}

/// RFC 5869 HKDF-SHA256 Test Case 1.
#[test]
fn hkdf_sha256_rfc5869_case1() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let okm_expected = hex(
        "3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
    );

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; okm_expected.len()];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, okm_expected);
}

/// IronCrypt ECIES HKDF info string produces a stable 32-byte KEK from fixed IKM.
#[test]
fn ironcrypt_ecies_hkdf_info_stable() {
    use ironcrypt::ECIES_HKDF_INFO_V1;
    let ikm = [0x11u8; 32];
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut kek_a = [0u8; 32];
    let mut kek_b = [0u8; 32];
    hk.expand(ECIES_HKDF_INFO_V1, &mut kek_a).unwrap();
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(ECIES_HKDF_INFO_V1, &mut kek_b)
        .unwrap();
    assert_eq!(kek_a, kek_b);
    // Distinct from legacy info string.
    let mut legacy = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(b"ironcrypt-ecies-kek", &mut legacy)
        .unwrap();
    assert_ne!(kek_a, legacy);
}

/// P-256 ECDSA sign/verify round-trip (deterministic for fixed key + message).
#[test]
fn p256_ecdsa_sign_verify() {
    let sk_bytes = hex(
        "519b423d715f8b581f4fa8ee59f4771a\
         72b503fd937eaae81a7117467ff85b10",
    );
    let sk = SecretKey::from_slice(&sk_bytes).expect("secret key");
    let signing = SigningKey::from(sk.clone());
    let verifying = VerifyingKey::from(&signing);
    let msg = b"ironcrypt-kat-ecdsa";
    let sig: Signature = signing.sign(msg);
    verifying.verify(msg, &sig).unwrap();
}
