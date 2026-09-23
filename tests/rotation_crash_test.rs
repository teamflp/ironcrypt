//! Crash / kill-process safety for keyring rotation writes (`atomic_write`).

use ironcrypt::key_lifecycle::{
    atomic_write, keyring_path, load_keyring, save_keyring, KeyState, KeyVersionMeta,
    KeyringManifest,
};
use chrono::Utc;
use std::fs;

#[test]
fn atomic_write_preserves_previous_until_rename_commits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyring.json");
    fs::write(&path, br#"{"key_id":"k","active_version":"v1","versions":[]}"#).unwrap();

    // Simulate a crashed writer: orphan temp left behind, destination intact.
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, b"PARTIAL-CRASH").unwrap();

    let before = fs::read(&path).unwrap();
    assert!(before.windows(2).any(|w| w == b"v1"));

    // A new atomic_write removes same-pid temp then commits the new content.
    atomic_write(
        &path,
        br#"{"key_id":"k","active_version":"v2","versions":[]}"#,
    )
    .unwrap();
    let after = fs::read_to_string(&path).unwrap();
    assert!(after.contains("v2"));
    assert!(!tmp.exists(), "same-pid temp should be consumed");
}

#[test]
fn save_keyring_reload_after_simulated_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let key_dir = dir.path().to_str().unwrap();

    let mut manifest = KeyringManifest::new("payment-dek", "v1", "ecc-p256");
    // Rotate: v1 decrypt-only, v2 active (as a post-rotate daemon would write).
    if let Some(v1) = manifest.versions.iter_mut().find(|v| v.key_version == "v1") {
        v1.state = KeyState::DecryptOnly;
        v1.rotated_at = Some(Utc::now());
    }
    manifest.versions.push(KeyVersionMeta {
        key_version: "v2".into(),
        state: KeyState::Active,
        algorithm: Some("ecc-p256".into()),
        provider: Some("local".into()),
        activated_at: Some(Utc::now()),
        expires_at: None,
        rotated_at: None,
    });
    manifest.active_version = "v2".into();

    save_keyring(key_dir, &manifest).unwrap();

    // Simulate process kill + restart: only the final keyring.json is visible.
    assert!(keyring_path(key_dir).exists());
    let reloaded = load_keyring(key_dir).unwrap().expect("manifest");
    assert_eq!(reloaded.active_version, "v2");
    assert_eq!(
        reloaded.version("v1").map(|v| v.state),
        Some(KeyState::DecryptOnly)
    );
    assert!(reloaded.ensure_can_encrypt("v2").is_ok());
    assert!(reloaded.ensure_can_encrypt("v1").is_err());
}
