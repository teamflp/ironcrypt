#![no_main]

use ironcrypt::{decrypt_stream, ecc_utils, keys::PrivateKey};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::sync::OnceLock;

static KEY: OnceLock<PrivateKey> = OnceLock::new();

fn private_key() -> &'static PrivateKey {
    KEY.get_or_init(|| {
        let (sk, _) = ecc_utils::generate_ecc_keys().expect("ecc keygen");
        PrivateKey::Ecc(sk)
    })
}

fuzz_target!(|data: &[u8]| {
    let mut source = Cursor::new(data);
    let mut out = Vec::new();
    let _ = decrypt_stream(&mut source, &mut out, private_key(), "v1", "", None);
});
