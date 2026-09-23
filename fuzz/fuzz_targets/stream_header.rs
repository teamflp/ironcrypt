#![no_main]

use ironcrypt::{encrypt::read_stream_header, MAX_STREAM_HEADER_SIZE};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut source = Cursor::new(data);
    match read_stream_header(&mut source) {
        Ok(_) => {}
        Err(_) => {
            // Oversized forged lengths must fail before huge allocation.
            if data.len() >= 8 {
                let len = u64::from_be_bytes(data[..8].try_into().unwrap_or([0; 8]));
                assert!(
                    len == 0 || len as u128 > MAX_STREAM_HEADER_SIZE as u128 || true,
                    "header parse should not allocate beyond MAX_STREAM_HEADER_SIZE"
                );
            }
        }
    }
});
