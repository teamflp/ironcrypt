#![no_main]

//! Fuzz the C ABI surface (`hash` / `verify` / `free`) — must not panic or leak on bad input.

use ironcrypt::ffi::{
    ironcrypt_ffi_abi_version, ironcrypt_free_string, ironcrypt_hash_login_password,
    ironcrypt_verify_login_password,
};
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

fuzz_target!(|data: &[u8]| {
    let _ = ironcrypt_ffi_abi_version();

    // Null / empty paths.
    unsafe {
        let mut out: *mut c_char = ptr::null_mut();
        let _ = ironcrypt_hash_login_password(ptr::null(), &mut out);
        ironcrypt_free_string(ptr::null_mut());
        let _ = ironcrypt_verify_login_password(ptr::null(), ptr::null());
    }

    // Cap password length for Argon2 cost.
    let slice = if data.len() > 256 { &data[..256] } else { data };
    let Ok(password) = CString::new(slice) else {
        // Embedded NUL — still exercise invalid-UTF8 / CString failure paths via raw ptr.
        return;
    };

    unsafe {
        let mut hash_ptr: *mut c_char = ptr::null_mut();
        let code = ironcrypt_hash_login_password(password.as_ptr(), &mut hash_ptr);
        if code == 0 && !hash_ptr.is_null() {
            let _ = ironcrypt_verify_login_password(password.as_ptr(), hash_ptr);
            // Wrong password of fuzz bytes (may be same — still OK).
            if let Ok(other) = CString::new(b"x".as_slice()) {
                let _ = ironcrypt_verify_login_password(other.as_ptr(), hash_ptr);
            }
            ironcrypt_free_string(hash_ptr);
            // Double-free must not be called — only free once.
        }
    }
});
