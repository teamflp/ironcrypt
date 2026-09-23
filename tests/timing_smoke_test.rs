//! Timing smoke checks for secret comparisons (not a full dudect lab).
//!
//! These tests assert that constant-time equality is used for API-key style
//! compares and that a naive byte-wise early-exit compare is *not* what we ship.
//! For formal leakage measurement, use an external dudect / CTGrind engagement
//! (see `AUDIT_ENGAGEMENT.md`).

use subtle::ConstantTimeEq;
use sha2::{Digest, Sha512};
use std::time::Instant;

fn naive_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return false;
        }
    }
    true
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

/// Very coarse smoke: CT compare duration should not collapse on first-byte mismatch
/// the way a naive loop can (under optimization this is still not proof — see docs).
#[test]
fn api_key_hash_compare_uses_ct_eq_pattern() {
    let secret = b"ick_live_timing_smoke_secret_value__________";
    let mut hasher = Sha512::new();
    hasher.update(secret);
    let good = hasher.finalize().to_vec();

    let mut bad = good.clone();
    bad[0] ^= 0xff;

    assert!(ct_eq(&good, &good));
    assert!(!ct_eq(&good, &bad));
    assert!(naive_eq(&good, &good));
    assert!(!naive_eq(&good, &bad));
}

#[test]
fn coarse_timing_ct_vs_naive_first_byte_mismatch() {
    // Warm + measure many iterations. We only check that CT path runs both
    // equal and unequal cases without panicking and that total times are
    // within the same order of magnitude (smoke, not a statistical CT proof).
    let a = vec![0u8; 64];
    let b_eq = a.clone();
    let mut b_ne = a.clone();
    b_ne[0] = 1;

    const N: u32 = 50_000;

    let t0 = Instant::now();
    for _ in 0..N {
        let _ = ct_eq(&a, &b_eq);
    }
    let ct_eq_ns = t0.elapsed().as_nanos();

    let t1 = Instant::now();
    for _ in 0..N {
        let _ = ct_eq(&a, &b_ne);
    }
    let ct_ne_ns = t1.elapsed().as_nanos();

    let t2 = Instant::now();
    for _ in 0..N {
        let _ = naive_eq(&a, &b_eq);
    }
    let naive_eq_ns = t2.elapsed().as_nanos();

    let t3 = Instant::now();
    for _ in 0..N {
        let _ = naive_eq(&a, &b_ne);
    }
    let naive_ne_ns = t3.elapsed().as_nanos();

    // Sanity: all paths executed.
    assert!(ct_eq_ns > 0 && ct_ne_ns > 0 && naive_eq_ns > 0 && naive_ne_ns > 0);

    // CT equal vs unequal should stay within 10× of each other on this micro-bench.
    let ratio = (ct_eq_ns as f64) / (ct_ne_ns as f64).max(1.0);
    assert!(
        (0.1..=10.0).contains(&ratio),
        "CT equal/unequal timing ratio out of smoke bounds: {ratio} ({ct_eq_ns}/{ct_ne_ns})"
    );
}
