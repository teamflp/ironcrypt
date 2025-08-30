use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

use crate::algorithms::SymmetricAlgorithm;
use crate::encrypt::{EncryptedData, RecipientInfo};
use crate::rsa_utils;
use crate::PasswordCriteria;

/// Generates a new RSA key pair of the specified bit size.
///
/// The generated keys are returned as PEM-encoded strings. The memory for these strings
/// is allocated by Rust and must be freed by the caller using `ironcrypt_free_string`.
#[no_mangle]
pub extern "C" fn ironcrypt_generate_rsa_keys(
    bits: u32,
    private_key_pem: *mut *mut c_char,
    public_key_pem: *mut *mut c_char,
) -> i32 {
    if private_key_pem.is_null() || public_key_pem.is_null() {
        return -1;
    }
    let (private_key, public_key) = match rsa_utils::generate_rsa_keys(bits) {
        Ok(keys) => keys,
        Err(_) => return -1,
    };
    let private_pem = match private_key.to_pkcs8_pem(LineEnding::LF) {
        Ok(pem) => pem,
        Err(_) => return -1,
    };
    let public_pem = match public_key.to_public_key_pem(LineEnding::LF) {
        Ok(pem) => pem,
        Err(_) => return -1,
    };
    unsafe {
        *private_key_pem = CString::new(private_pem.as_str()).unwrap().into_raw();
        *public_key_pem = CString::new(public_pem.as_str()).unwrap().into_raw();
    }
    0
}

/// Frees a C string that was allocated by the Rust library.
#[no_mangle]
pub extern "C" fn ironcrypt_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Encrypts a password using a public key according to the IronCrypt password workflow.
#[no_mangle]
pub extern "C" fn ironcrypt_password_encrypt(
    password: *const c_char,
    public_key_pem: *const c_char,
    key_version: *const c_char,
    encrypted_output: *mut *mut c_char,
) -> i32 {
    if password.is_null() || public_key_pem.is_null() || key_version.is_null() || encrypted_output.is_null() {
        return -1;
    }

    let password = unsafe { CStr::from_ptr(password) }.to_str().unwrap_or("");
    let public_key_pem = unsafe { CStr::from_ptr(public_key_pem) }.to_str().unwrap_or("");
    let key_version = unsafe { CStr::from_ptr(key_version) }.to_str().unwrap_or("");

    if password.is_empty() || public_key_pem.is_empty() || key_version.is_empty() {
        return -1;
    }

    let criteria = PasswordCriteria::default();
    if criteria.validate(password).is_err() {
        return -1;
    }

    let rsa_pub_key = match RsaPublicKey::from_public_key_pem(public_key_pem) {
        Ok(key) => key,
        Err(_) => return -1,
    };

    let params = Params::new(65536, 3, 1, None).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => return -1,
    };

    let mut aes_key = [0u8; 32];
    OsRng.fill_bytes(&mut aes_key);

    let padding = Oaep::new::<Sha256>();
    let encrypted_aes_key = match rsa_pub_key.encrypt(&mut OsRng, padding, &aes_key) {
        Ok(key) => key,
        Err(_) => return -1,
    };

    let cipher = match Aes256Gcm::new_from_slice(&aes_key) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = aes_gcm::Nonce::from_slice(&nonce);
    let ciphertext = match cipher.encrypt(nonce_ga, password_hash.as_bytes()) {
        Ok(text) => text,
        Err(_) => return -1,
    };

    let encrypted_data = EncryptedData {
        symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
        recipient_info: RecipientInfo::Rsa {
            key_version: key_version.to_string(),
            encrypted_symmetric_key: base64_standard.encode(&encrypted_aes_key),
        },
        nonce: base64_standard.encode(nonce),
        ciphertext: base64_standard.encode(&ciphertext),
        password_hash: Some(password_hash),
    };

    let json = match serde_json::to_string(&encrypted_data) {
        Ok(j) => j,
        Err(_) => return -1,
    };

    unsafe {
        *encrypted_output = CString::new(json).unwrap().into_raw();
    }

    0
}

#[no_mangle]
pub extern "C" fn ironcrypt_password_verify(
    encrypted_json: *const c_char,
    password: *const c_char,
    private_key_pem: *const c_char,
    passphrase: *const c_char, // can be NULL
) -> i32 {
    // 1. Check for null pointers and convert C strings
    if encrypted_json.is_null() || password.is_null() || private_key_pem.is_null() {
        return -1; // Error
    }
    let encrypted_json = unsafe { CStr::from_ptr(encrypted_json) }.to_str().unwrap_or("");
    let password = unsafe { CStr::from_ptr(password) }.to_str().unwrap_or("");
    let private_key_pem = unsafe { CStr::from_ptr(private_key_pem) }.to_str().unwrap_or("");
    let passphrase = if passphrase.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(passphrase) }.to_str().unwrap_or(""))
    };

    // 2. Deserialize JSON
    let encrypted_data: EncryptedData = match serde_json::from_str(encrypted_json) {
        Ok(data) => data,
        Err(_) => return -1,
    };

    // 3. Load private key
    let private_key = match rsa_utils::load_private_key_from_str(private_key_pem, passphrase) {
        Ok(key) => key,
        Err(_) => return -1,
    };

    // 4. Decrypt AES key
    let encrypted_aes_key_b64 = match encrypted_data.recipient_info {
        RecipientInfo::Rsa {
            encrypted_symmetric_key,
            ..
        } => encrypted_symmetric_key,
        _ => return -1, // Only support RSA for now
    };
    let encrypted_aes_key = match base64_standard.decode(encrypted_aes_key_b64) {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let padding = Oaep::new::<Sha256>();
    let aes_key = match private_key.decrypt(padding, &encrypted_aes_key) {
        Ok(key) => key,
        Err(_) => return -1,
    };

    // 5. Decrypt password hash
    let nonce_vec = match base64_standard.decode(encrypted_data.nonce) {
        Ok(n) => n,
        Err(_) => return -1,
    };
    if nonce_vec.len() != 12 {
        return -1;
    }
    let nonce = aes_gcm::Nonce::from_slice(&nonce_vec);
    let ciphertext = match base64_standard.decode(encrypted_data.ciphertext) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let cipher = match Aes256Gcm::new_from_slice(&aes_key) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let decrypted_hash_bytes = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(h) => h,
        Err(_) => return -1,
    };
    let decrypted_hash = match String::from_utf8(decrypted_hash_bytes) {
        Ok(h) => h,
        Err(_) => return -1,
    };

    // 6. Verify password against hash
    let parsed_hash = match argon2::PasswordHash::new(&decrypted_hash) {
        Ok(h) => h,
        Err(_) => return -1,
    };
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => 1, // Valid
        Err(_) => 0, // Invalid
    }
}
