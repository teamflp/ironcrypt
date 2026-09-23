//! Regression tests for stream header size limits (DoS hardening).

use ironcrypt::{decrypt_stream, generate_rsa_keys, keys::PrivateKey, MAX_STREAM_HEADER_SIZE};
use byteorder::{BigEndian, WriteBytesExt};
use std::io::Cursor;

#[test]
fn decrypt_stream_rejects_oversized_header_len() {
    let (private_key, _) = generate_rsa_keys(2048).unwrap();
    let mut malicious = Vec::new();
    // Claim a huge header without sending that many bytes — must fail before OOM.
    let claim = (MAX_STREAM_HEADER_SIZE as u64) + 1;
    malicious.write_u64::<BigEndian>(claim).unwrap();

    let mut out = Vec::new();
    let err = decrypt_stream(
        &mut Cursor::new(malicious),
        &mut out,
        &PrivateKey::Rsa(private_key),
        "v1",
        "",
        None,
    );
    assert!(err.is_err(), "oversized header_len must be rejected");
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("MAX_STREAM_HEADER_SIZE") || msg.contains("header length"),
        "unexpected error: {msg}"
    );
}
