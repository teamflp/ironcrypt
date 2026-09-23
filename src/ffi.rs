//! C ABI for IronCrypt (`cdylib`).
//!
//! See [`FFI.md`](../../FFI.md) for ownership, threading, and versioning rules.
//!
//! Error codes are stable negative integers ([`codes`]). Success is `0` unless a
//! function documents a positive boolean result (`1` / `0`).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroize;

use crate::hashing;
use crate::encrypt::Argon2Config;

#[cfg(feature = "rsa-algo")]
use crate::{
    keys::{PrivateKey, PublicKey},
    password, rsa_utils,
};
#[cfg(feature = "rsa-algo")]
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};

/// Stable FFI error / status codes (ABI v1).
pub mod codes {
    pub const SUCCESS: i32 = 0;
    pub const ERROR_NULL_POINTER: i32 = -1;
    pub const ERROR_INVALID_UTF8: i32 = -2;
    pub const ERROR_KEY_GENERATION: i32 = -3;
    pub const ERROR_KEY_ENCODING: i32 = -4;
    pub const ERROR_ENCRYPTION_FAILED: i32 = -5;
    pub const ERROR_DECRYPTION_FAILED: i32 = -6;
    pub const ERROR_VERIFICATION_FAILED: i32 = -7;
    pub const ERROR_KEY_DECODING: i32 = -8;
    pub const ERROR_UNSUPPORTED: i32 = -9;
    pub const ERROR_HASHING_FAILED: i32 = -10;
    pub const ERROR_PANIC: i32 = -98;
    pub const ERROR_UNKNOWN: i32 = -99;
}

use codes::*;

/// ABI major version exported to C callers (`ironcrypt_ffi_abi_version`).
pub const FFI_ABI_VERSION: u32 = 1;

#[cfg(feature = "rsa-algo")]
fn payment_rejects_rsa() -> bool {
    crate::payment::PaymentSecurityProfile::is_enabled()
}

/// Copy a C string into an owned Rust `String` immediately.
fn c_str_to_string(ptr: *const c_char) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(ERROR_NULL_POINTER);
    }
    // SAFETY: caller guarantees a valid NUL-terminated C string (or null, handled above).
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => Err(ERROR_INVALID_UTF8),
    }
}

fn ffi_guard<F>(f: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => ERROR_PANIC,
    }
}

fn write_cstring(out: *mut *mut c_char, value: &str) -> i32 {
    if out.is_null() {
        return ERROR_NULL_POINTER;
    }
    match CString::new(value) {
        Ok(c) => {
            // SAFETY: `out` validated non-null.
            unsafe {
                *out = c.into_raw();
            }
            SUCCESS
        }
        Err(_) => ERROR_INVALID_UTF8,
    }
}

/// Returns the IronCrypt FFI ABI major version (`1`, `2`, …).
#[no_mangle]
pub extern "C" fn ironcrypt_ffi_abi_version() -> u32 {
    FFI_ABI_VERSION
}

/// Frees a C string allocated by IronCrypt, zeroizing contents first.
///
/// # Safety
/// - `s` is null **or** was returned by an IronCrypt FFI allocator and not freed yet.
/// - Do not free the same pointer twice.
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_free_string(s: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if s.is_null() {
            return;
        }
        // SAFETY: caller guarantees this was allocated by this library.
        let cstr = unsafe { CString::from_raw(s) };
        let mut bytes = cstr.into_bytes_with_nul();
        bytes.zeroize();
    }));
}

/// Argon2id login hash (PHC string). Preferred under Payment — no RSA.
///
/// Caller must free `hash_out` with [`ironcrypt_free_string`].
///
/// # Safety
/// All pointers must be valid or null as documented; `hash_out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_hash_login_password(
    password_ptr: *const c_char,
    hash_out: *mut *mut c_char,
) -> i32 {
    ffi_guard(|| {
        let mut password = match c_str_to_string(password_ptr) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let code = match hashing::hash_password_with_config(&password, &Argon2Config::default()) {
            Ok(phc) => write_cstring(hash_out, &phc),
            Err(_) => ERROR_HASHING_FAILED,
        };
        password.zeroize();
        code
    })
}

/// Verify a login password against a PHC hash.
///
/// Returns `1` match, `0` mismatch, or a negative error code.
///
/// # Safety
/// Pointers must be valid NUL-terminated C strings (non-null).
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_verify_login_password(
    password_ptr: *const c_char,
    phc_hash_ptr: *const c_char,
) -> i32 {
    ffi_guard(|| {
        let mut password = match c_str_to_string(password_ptr) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let phc = match c_str_to_string(phc_hash_ptr) {
            Ok(s) => s,
            Err(e) => {
                password.zeroize();
                return e;
            }
        };
        let code = match hashing::verify_password(&password, &phc) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => ERROR_VERIFICATION_FAILED,
        };
        password.zeroize();
        code
    })
}

/// Generate a P-256 ECC key pair (PEM). Safe under Payment.
///
/// Caller frees both PEMs with [`ironcrypt_free_string`].
///
/// # Safety
/// Output pointers must be non-null writable slots.
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_generate_ecc_keys(
    private_key_pem: *mut *mut c_char,
    public_key_pem: *mut *mut c_char,
) -> i32 {
    ffi_guard(|| {
        if private_key_pem.is_null() || public_key_pem.is_null() {
            return ERROR_NULL_POINTER;
        }
        let (sk, pk) = match crate::ecc_utils::generate_ecc_keys() {
            Ok(k) => k,
            Err(_) => return ERROR_KEY_GENERATION,
        };
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let private_pem = match sk.to_pkcs8_pem(LineEnding::LF) {
            Ok(p) => p,
            Err(_) => return ERROR_KEY_ENCODING,
        };
        let public_pem = match pk.to_public_key_pem(LineEnding::LF) {
            Ok(p) => p,
            Err(_) => return ERROR_KEY_ENCODING,
        };
        if write_cstring(private_key_pem, private_pem.as_str()) != SUCCESS {
            return ERROR_KEY_ENCODING;
        }
        if write_cstring(public_key_pem, public_pem.as_str()) != SUCCESS {
            // Best-effort free the first allocation on failure.
            unsafe {
                ironcrypt_free_string(*private_key_pem);
                *private_key_pem = std::ptr::null_mut();
            }
            return ERROR_KEY_ENCODING;
        }
        SUCCESS
    })
}

/// Generates a new RSA key pair of the specified bit size.
///
/// Unavailable / returns [`ERROR_UNSUPPORTED`] under the Payment profile.
#[cfg(feature = "rsa-algo")]
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_generate_rsa_keys(
    bits: u32,
    private_key_pem: *mut *mut c_char,
    public_key_pem: *mut *mut c_char,
) -> i32 {
    ffi_guard(|| {
        if payment_rejects_rsa() {
            return ERROR_UNSUPPORTED;
        }
        if private_key_pem.is_null() || public_key_pem.is_null() {
            return ERROR_NULL_POINTER;
        }

        let (private_key, public_key) = match rsa_utils::generate_rsa_keys(bits) {
            Ok(keys) => keys,
            Err(_) => return ERROR_KEY_GENERATION,
        };

        let private_pem = match private_key.to_pkcs8_pem(LineEnding::LF) {
            Ok(pem) => pem,
            Err(_) => return ERROR_KEY_ENCODING,
        };
        let public_pem = match public_key.to_public_key_pem(LineEnding::LF) {
            Ok(pem) => pem,
            Err(_) => return ERROR_KEY_ENCODING,
        };

        if write_cstring(private_key_pem, private_pem.as_str()) != SUCCESS {
            return ERROR_KEY_ENCODING;
        }
        if write_cstring(public_key_pem, public_pem.as_str()) != SUCCESS {
            unsafe {
                ironcrypt_free_string(*private_key_pem);
                *private_key_pem = std::ptr::null_mut();
            }
            return ERROR_KEY_ENCODING;
        }
        SUCCESS
    })
}

/// Encrypts a password using an RSA public key (legacy). Prefer login hash under Payment.
#[cfg(feature = "rsa-algo")]
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_password_encrypt(
    password_ptr: *const c_char,
    public_key_pem_ptr: *const c_char,
    key_version_ptr: *const c_char,
    encrypted_output: *mut *mut c_char,
) -> i32 {
    ffi_guard(|| {
        if payment_rejects_rsa() {
            return ERROR_UNSUPPORTED;
        }
        if encrypted_output.is_null() {
            return ERROR_NULL_POINTER;
        }

        let mut password = match c_str_to_string(password_ptr) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let public_key_pem = match c_str_to_string(public_key_pem_ptr) {
            Ok(s) => s,
            Err(e) => {
                password.zeroize();
                return e;
            }
        };
        let key_version = match c_str_to_string(key_version_ptr) {
            Ok(s) => s,
            Err(e) => {
                password.zeroize();
                return e;
            }
        };

        let rsa_pub_key = match rsa::RsaPublicKey::from_public_key_pem(&public_key_pem) {
            Ok(key) => key,
            Err(_) => {
                password.zeroize();
                return ERROR_KEY_DECODING;
            }
        };
        let public_key = PublicKey::Rsa(rsa_pub_key);

        let code = match password::encrypt(
            &password,
            &public_key,
            &key_version,
            &Argon2Config::default(),
        ) {
            Ok(json) => write_cstring(encrypted_output, &json),
            Err(_) => ERROR_ENCRYPTION_FAILED,
        };
        password.zeroize();
        code
    })
}

/// Verifies a password against an RSA-encrypted payload (legacy).
#[cfg(feature = "rsa-algo")]
#[no_mangle]
pub unsafe extern "C" fn ironcrypt_password_verify(
    encrypted_json_ptr: *const c_char,
    password_ptr: *const c_char,
    private_key_pem_ptr: *const c_char,
    passphrase_ptr: *const c_char,
) -> i32 {
    ffi_guard(|| {
        if payment_rejects_rsa() {
            return ERROR_UNSUPPORTED;
        }
        let encrypted_json = match c_str_to_string(encrypted_json_ptr) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut password = match c_str_to_string(password_ptr) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let private_key_pem = match c_str_to_string(private_key_pem_ptr) {
            Ok(s) => s,
            Err(e) => return e,
        };

        let passphrase = if passphrase_ptr.is_null() {
            None
        } else {
            match c_str_to_string(passphrase_ptr) {
                Ok(s) => Some(s),
                Err(e) => return e,
            }
        };

        let private_key =
            match rsa_utils::load_private_key_from_str(&private_key_pem, passphrase.as_deref()) {
                Ok(key) => PrivateKey::Rsa(key),
                Err(_) => {
                    if let Some(mut p) = passphrase {
                        p.zeroize();
                    }
                    password.zeroize();
                    return ERROR_KEY_DECODING;
                }
            };
        if let Some(mut p) = passphrase {
            p.zeroize();
        }

        let result = match password::verify(&encrypted_json, &password, &private_key) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(crate::IronCryptError::PasswordVerificationError) => ERROR_VERIFICATION_FAILED,
            Err(crate::IronCryptError::DecryptionError(_)) => ERROR_DECRYPTION_FAILED,
            Err(_) => ERROR_UNKNOWN,
        };
        password.zeroize();
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn abi_version_is_one() {
        assert_eq!(ironcrypt_ffi_abi_version(), 1);
    }

    #[test]
    fn null_password_hash_returns_null_pointer_error() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe { ironcrypt_hash_login_password(ptr::null(), &mut out) };
        assert_eq!(code, ERROR_NULL_POINTER);
        assert!(out.is_null());
    }

    #[test]
    fn login_hash_verify_roundtrip() {
        let password = CString::new("Str0ngP@ssw0rd42!").unwrap();
        let mut hash_ptr: *mut c_char = ptr::null_mut();
        let code = unsafe { ironcrypt_hash_login_password(password.as_ptr(), &mut hash_ptr) };
        assert_eq!(code, SUCCESS);
        assert!(!hash_ptr.is_null());
        let v = unsafe { ironcrypt_verify_login_password(password.as_ptr(), hash_ptr) };
        assert_eq!(v, 1);
        let wrong = CString::new("WrongP@ssw0rd99!").unwrap();
        let v2 = unsafe { ironcrypt_verify_login_password(wrong.as_ptr(), hash_ptr) };
        assert_eq!(v2, 0);
        unsafe { ironcrypt_free_string(hash_ptr) };
    }

    #[test]
    fn free_null_is_safe() {
        unsafe { ironcrypt_free_string(ptr::null_mut()) };
    }

    #[test]
    fn generate_ecc_keys_ok() {
        let mut priv_p: *mut c_char = ptr::null_mut();
        let mut pub_p: *mut c_char = ptr::null_mut();
        let code = unsafe { ironcrypt_generate_ecc_keys(&mut priv_p, &mut pub_p) };
        assert_eq!(code, SUCCESS);
        assert!(!priv_p.is_null() && !pub_p.is_null());
        unsafe {
            ironcrypt_free_string(priv_p);
            ironcrypt_free_string(pub_p);
        }
    }

    #[test]
    fn invalid_utf8_rejected() {
        // Embed a non-UTF8 byte before NUL.
        let bad: [i8; 3] = [0x80u8 as i8, 0x41, 0];
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe { ironcrypt_hash_login_password(bad.as_ptr(), &mut out) };
        assert_eq!(code, ERROR_INVALID_UTF8);
    }
}
