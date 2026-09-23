use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::io;

use crate::encrypt::Argon2Config;

/// Hashes a stream of data using SHA-256.
pub fn hash_stream<R: io::Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    io::copy(reader, &mut hasher).map(|_| hasher.finalize().to_vec())
}

/// Hashes a byte slice using SHA-256.
pub fn hash_bytes(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

/// Hashes a password with Argon2id (default parameters).
///
/// Prefer [`hash_password_with_config`] when you control Argon2 costs (Payment).
pub fn hash_password(password: &str) -> Result<String, String> {
    hash_password_with_config(password, &Argon2Config::default())
}

/// Hashes a password with explicit Argon2id parameters. Returns a PHC string.
pub fn hash_password_with_config(
    password: &str,
    cfg: &Argon2Config,
) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(cfg.memory_cost, cfg.time_cost, cfg.parallelism, None)
        .map_err(|e| format!("invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Error while hashing password: {e:?}"))
}

/// Verifies a password against an Argon2 PHC hash string (login / auth — not recoverable).
///
/// Rejects PHC parameters above [`crate::limits::MAX_ARGON2_*`] to prevent
/// memory/CPU DoS from attacker-controlled hashes (e.g. FFI).
pub fn verify_password(password: &str, phc_hash: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| format!("invalid PHC hash: {e}"))?;
    let mem = parsed
        .params
        .get("m")
        .and_then(|v| v.decimal().ok())
        .unwrap_or(u32::MAX);
    let time = parsed
        .params
        .get("t")
        .and_then(|v| v.decimal().ok())
        .unwrap_or(u32::MAX);
    let parallel = parsed
        .params
        .get("p")
        .and_then(|v| v.decimal().ok())
        .unwrap_or(u32::MAX);
    use crate::limits::{MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM, MAX_ARGON2_TIME_COST};
    if mem > MAX_ARGON2_MEMORY_KIB || time > MAX_ARGON2_TIME_COST || parallel > MAX_ARGON2_PARALLELISM
    {
        return Err(format!(
            "PHC Argon2 params exceed caps (m={mem} t={time} p={parallel})"
        ));
    }
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(format!("password verify error: {e}")),
    }
}

/// Returns `true` when the stored PHC hash should be rehashed with `cfg` costs.
pub fn password_needs_rehash(phc_hash: &str, cfg: &Argon2Config) -> bool {
    let Ok(parsed) = PasswordHash::new(phc_hash) else {
        return true;
    };
    let mem = parsed
        .params
        .get("m")
        .and_then(|v| v.decimal().ok())
        .unwrap_or(0);
    let time = parsed
        .params
        .get("t")
        .and_then(|v| v.decimal().ok())
        .unwrap_or(0);
    let parallel = parsed
        .params
        .get("p")
        .and_then(|v| v.decimal().ok())
        .unwrap_or(0);
    mem != cfg.memory_cost || time != cfg.time_cost || parallel != cfg.parallelism
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_roundtrip() {
        let h = hash_password_with_config("Str0ngP@ss!", &Argon2Config::default()).unwrap();
        assert!(verify_password("Str0ngP@ss!", &h).unwrap());
        assert!(!verify_password("nope", &h).unwrap());
        assert!(!password_needs_rehash(&h, &Argon2Config::default()));
        assert!(password_needs_rehash(
            &h,
            &Argon2Config {
                memory_cost: 128_000,
                time_cost: 4,
                parallelism: 2,
            }
        ));
    }
}
