use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::{
    keys::{PrivateKey, PublicKey},
    password,
    rsa_utils,
};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};

// Error codes
const SUCCESS: i32 = 0;
const ERROR_NULL_POINTER: i32 = -1;
const ERROR_INVALID_UTF8: i32 = -2;
const ERROR_KEY_GENERATION: i32 = -3;
const ERROR_KEY_ENCODING: i32 = -4;
const ERROR_ENCRYPTION_FAILED: i32 = -5;
const ERROR_DECRYPTION_FAILED: i32 = -6;
const ERROR_VERIFICATION_FAILED: i32 = -7;
const ERROR_KEY_DECODING: i32 = -8;
const ERROR_UNKNOWN: i32 = -99;

/// Generates a new RSA key pair of the specified bit size.
///
/// The generated keys are returned as PEM-encoded strings. The memory for these strings
/// is allocated by Rust and must be freed by the caller using `ironcrypt_free_string`.
/// On failure, the pointers are not modified.
#[no_mangle]
pub extern "C" fn ironcrypt_generate_rsa_keys(
    bits: u32,
    private_key_pem: *mut *mut c_char,
    public_key_pem: *mut *mut c_char,
) -> i32 {
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

    let private_pem_c = match CString::new(private_pem.as_str()) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_UTF8,
    };
    let public_pem_c = match CString::new(public_pem.as_str()) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_UTF8,
    };

    unsafe {
        *private_key_pem = private_pem_c.into_raw();
        *public_key_pem = public_pem_c.into_raw();
    }
    SUCCESS
}

/// Frees a C string that was allocated by the Rust library.
#[no_mangle]
pub extern "C" fn ironcrypt_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            // Reconstruct the CString from the raw pointer and let it be dropped,
            // which deallocates the memory.
            let _ = CString::from_raw(s);
        }
    }
}

/// Encrypts a password using a public key.
///
/// The encrypted result is returned as a JSON string. The memory for this string
/// is allocated by Rust and must be freed by the caller using `ironcrypt_free_string`.
#[no_mangle]
pub extern "C" fn ironcrypt_password_encrypt(
    password_ptr: *const c_char,
    public_key_pem_ptr: *const c_char,
    key_version_ptr: *const c_char,
    encrypted_output: *mut *mut c_char,
) -> i32 {
    if password_ptr.is_null() || public_key_pem_ptr.is_null() || key_version_ptr.is_null() || encrypted_output.is_null() {
        return ERROR_NULL_POINTER;
    }

    let password = unsafe { CStr::from_ptr(password_ptr) }.to_str();
    let public_key_pem = unsafe { CStr::from_ptr(public_key_pem_ptr) }.to_str();
    let key_version = unsafe { CStr::from_ptr(key_version_ptr) }.to_str();

    if password.is_err() || public_key_pem.is_err() || key_version.is_err() {
        return ERROR_INVALID_UTF8;
    }

    let rsa_pub_key = match rsa::RsaPublicKey::from_public_key_pem(public_key_pem.unwrap()) {
        Ok(key) => key,
        Err(_) => return ERROR_KEY_DECODING,
    };
    let public_key = PublicKey::Rsa(rsa_pub_key);

    match password::encrypt(password.unwrap(), &public_key, key_version.unwrap()) {
        Ok(json) => match CString::new(json) {
            Ok(c_json) => {
                unsafe { *encrypted_output = c_json.into_raw() };
                SUCCESS
            }
            Err(_) => ERROR_INVALID_UTF8,
        },
        Err(_) => ERROR_ENCRYPTION_FAILED,
    }
}

/// Verifies a password against an encrypted payload using a private key.
///
/// Returns:
/// - 1 if the password is valid.
/// - 0 if the password is not valid.
/// - A negative error code on failure.
#[no_mangle]
pub extern "C" fn ironcrypt_password_verify(
    encrypted_json_ptr: *const c_char,
    password_ptr: *const c_char,
    private_key_pem_ptr: *const c_char,
    passphrase_ptr: *const c_char, // can be NULL
) -> i32 {
    if encrypted_json_ptr.is_null() || password_ptr.is_null() || private_key_pem_ptr.is_null() {
        return ERROR_NULL_POINTER;
    }

    let encrypted_json = unsafe { CStr::from_ptr(encrypted_json_ptr) }.to_str();
    let password = unsafe { CStr::from_ptr(password_ptr) }.to_str();
    let private_key_pem = unsafe { CStr::from_ptr(private_key_pem_ptr) }.to_str();
    let passphrase = if passphrase_ptr.is_null() {
        Ok(None)
    } else {
        unsafe { CStr::from_ptr(passphrase_ptr) }.to_str().map(Some)
    };

    if encrypted_json.is_err() || password.is_err() || private_key_pem.is_err() || passphrase.is_err() {
        return ERROR_INVALID_UTF8;
    }

    let private_key = match rsa_utils::load_private_key_from_str(
        private_key_pem.unwrap(),
        passphrase.unwrap(),
    ) {
        Ok(key) => PrivateKey::Rsa(key),
        Err(_) => return ERROR_KEY_DECODING,
    };

    match password::verify(encrypted_json.unwrap(), password.unwrap(), &private_key) {
        Ok(true) => 1,  // Valid password
        Ok(false) => 0, // Invalid password
        Err(crate::IronCryptError::PasswordVerificationError) => ERROR_VERIFICATION_FAILED,
        Err(crate::IronCryptError::DecryptionError(_)) => ERROR_DECRYPTION_FAILED,
        Err(_) => ERROR_UNKNOWN,
    }
}
