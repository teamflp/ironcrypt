#![no_main]

//! Fuzz PEM / PKCS#8 parsers via temp files → `load_any_{public,private}_key`.
//! Must never panic on adversarial input.

use ironcrypt::{load_any_private_key, load_any_public_key};
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // Cap size to keep I/O cheap under libFuzzer.
    if data.len() > 64 * 1024 {
        return;
    }

    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };

    let pub_path = dir.path().join("fuzz_pub.pem");
    let priv_path = dir.path().join("fuzz_priv.pem");

    if std::fs::write(&pub_path, data).is_ok() {
        let _ = load_any_public_key(pub_path.to_str().unwrap_or(""));
    }

    if std::fs::write(&priv_path, data).is_ok() {
        let _ = load_any_private_key(priv_path.to_str().unwrap_or(""), None);
        // Also try treating leading bytes as a passphrase hint (empty / short / binary).
        let pass = if data.is_empty() {
            None
        } else {
            let slice = &data[..data.len().min(64)];
            std::str::from_utf8(slice).ok()
        };
        let _ = load_any_private_key(priv_path.to_str().unwrap_or(""), pass);

        // Encrypted-looking PEM wrapper with garbage body.
        if let Ok(mut f) = std::fs::File::create(&priv_path) {
            let _ = writeln!(f, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
            let _ = f.write_all(data);
            let _ = writeln!(f, "\n-----END ENCRYPTED PRIVATE KEY-----");
            let _ = load_any_private_key(priv_path.to_str().unwrap_or(""), Some("fuzz-pass"));
        }
    }
});
