//! Memory hygiene helpers for secrets (DEKs, passphrases, hashes).
//!
//! Prefer [`Zeroizing`] for owned buffers so early `?` / `return` still wipe.
//! Use [`ZeroizeOnDrop`] when you only have a borrowed mutable slice.
//!
//! ## `mlock` (best-effort)
//!
//! On Unix, [`try_mlock`] / [`try_munlock`] wrap `libc::mlock` / `munlock`.
//! Enable via Cargo feature `mlock` (pulled in by `payment`) or env
//! `IRONCRYPT_MLOCK=1`. Failure is non-fatal (no CAP_IPC_LOCK, RLIMIT_MEMLOCK,
//! or platform limits). See [`MEMORY.md`](../../MEMORY.md).

use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use zeroize::{Zeroize, Zeroizing};

/// Owned 32-byte data-encryption key that wipes itself on drop.
pub type Dek32 = Zeroizing<[u8; 32]>;

/// Generate a fresh random AES-256 DEK (optionally `mlock`'d).
pub fn new_dek32() -> Dek32 {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    if mlock_enabled() {
        let ok = try_mlock(key.as_mut());
        if !ok {
            tracing::debug!("mlock on DEK failed (non-fatal; check RLIMIT_MEMLOCK / capabilities)");
        }
    }
    key
}

/// Wrap an existing 32-byte key so it is wiped on drop.
pub fn dek32_from(bytes: [u8; 32]) -> Dek32 {
    let mut key = Zeroizing::new(bytes);
    if mlock_enabled() {
        let _ = try_mlock(key.as_mut());
    }
    key
}

/// Wrap a decrypted DEK / secret so it is wiped on drop (including early returns).
pub fn zeroizing_vec(bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(bytes);
    if mlock_enabled() {
        let _ = try_mlock(v.as_mut());
    }
    v
}

/// Guarantees `buf` is zeroized when this guard leaves scope.
pub struct ZeroizeOnDrop<'a, T: Zeroize + ?Sized>(pub &'a mut T);

impl<T: Zeroize + ?Sized> Drop for ZeroizeOnDrop<'_, T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Zeroize a `String` in place and clear it.
pub fn wipe_string(s: &mut String) {
    s.zeroize();
    s.clear();
}

/// Whether DEK/secret buffers should attempt `mlock`.
pub fn mlock_enabled() -> bool {
    if cfg!(feature = "mlock") {
        // Feature on → default enabled unless explicitly disabled.
        match env::var("IRONCRYPT_MLOCK") {
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off") => {
                false
            }
            _ => true,
        }
    } else {
        matches!(
            env::var("IRONCRYPT_MLOCK").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES") | Ok("on") | Ok("ON")
        )
    }
}

/// Best-effort lock of `buf`'s pages into RAM (Unix `mlock`).
///
/// Returns `true` if the call reported success. On non-Unix always `false`.
/// Locks whole pages containing the slice — adjacent data on the same page may
/// also be locked.
pub fn try_mlock(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    #[cfg(unix)]
    {
        // SAFETY: pointer/len refer to the live mutable slice for the duration of the call.
        let rc = unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
        rc == 0
    }
    #[cfg(not(unix))]
    {
        let _ = buf;
        false
    }
}

/// Best-effort unlock previously locked pages.
pub fn try_munlock(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    #[cfg(unix)]
    {
        let rc = unsafe { libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
        rc == 0
    }
    #[cfg(not(unix))]
    {
        let _ = buf;
        false
    }
}

/// Guard that unlocks on drop after a successful [`try_mlock`].
pub struct MlockGuard<'a> {
    buf: &'a mut [u8],
    locked: bool,
}

impl<'a> MlockGuard<'a> {
    /// Attempt to lock `buf`; unlocks automatically on drop if lock succeeded.
    pub fn lock(buf: &'a mut [u8]) -> Self {
        let locked = try_mlock(buf);
        Self { buf, locked }
    }

    pub fn locked(&self) -> bool {
        self.locked
    }
}

impl Drop for MlockGuard<'_> {
    fn drop(&mut self) {
        if self.locked {
            let _ = try_munlock(self.buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dek32_drops_clean() {
        let dek = new_dek32();
        assert_ne!(*dek, [0u8; 32]);
        drop(dek);
    }

    #[test]
    fn zeroize_on_drop_wipes_slice() {
        let mut buf = [1u8, 2, 3, 4];
        {
            let _g = ZeroizeOnDrop(&mut buf);
        }
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn wipe_string_clears() {
        let mut s = String::from("secret-passphrase");
        wipe_string(&mut s);
        assert!(s.is_empty());
    }

    #[test]
    fn mlock_guard_does_not_panic() {
        let mut buf = [0u8; 64];
        let g = MlockGuard::lock(&mut buf);
        // May or may not lock depending on platform limits.
        let _ = g.locked();
        drop(g);
    }
}
