//! Property-based tests (`proptest`) for auth / context / AAD stability.

use chrono::{Duration, Utc};
use ironcrypt::auth::{expand_full_permissions, ApiKeyConfig, Permission};
use ironcrypt::context::EncryptionContext;
use ironcrypt::api_key_store::parse_api_keys_json;
use proptest::prelude::*;

proptest! {
    #[test]
    fn context_aad_roundtrip_stable(
        tenant in "[a-zA-Z0-9_-]{1,32}",
        purpose in "[a-zA-Z0-9_-]{1,32}",
        record in "[a-zA-Z0-9_-]{1,32}",
    ) {
        let ctx = EncryptionContext::new(&tenant, &purpose, &record);
        prop_assert!(ctx.validate().is_ok());
        let aad = ctx.to_aad_bytes();
        let aad2 = EncryptionContext::new(&tenant, &purpose, &record).to_aad_bytes();
        prop_assert!(aad.starts_with(b"ironcrypt-ctx-v1|"));
        prop_assert_eq!(aad, aad2);
    }

    #[test]
    fn context_rejects_separators(
        tenant in ".*[|=].{0,8}",
    ) {
        let ctx = EncryptionContext::new(&tenant, "purpose", "record");
        // May also fail length; any Err is fine for separator cases when | or = present.
        if tenant.contains('|') || tenant.contains('=') {
            prop_assert!(ctx.validate().is_err());
        }
    }

    #[test]
    fn api_key_usable_respects_window(
        grace_secs in 1i64..86_400,
        skew_secs in -3_600i64..3_600,
    ) {
        let now = Utc::now();
        let mut key = ApiKeyConfig {
            description: "p".into(),
            key_hash: "ab".into(),
            permissions: vec![Permission::Read],
            allowed_services: None,
            key_id: Some("ick_live_prop".into()),
            created_at: Some(now - Duration::days(1)),
            not_before: Some(now - Duration::seconds(grace_secs)),
            expires_at: Some(now + Duration::seconds(grace_secs)),
            revoked_at: None,
            last_used_at: None,
            owner: None,
            replaces_key_id: None,
        };
        let at = now + Duration::seconds(skew_secs);
        let usable = key.is_usable(at);
        let expected = skew_secs >= -grace_secs && skew_secs < grace_secs;
        prop_assert_eq!(usable, expected);

        key.revoked_at = Some(now);
        prop_assert!(!key.is_usable(at));
    }
}

#[test]
fn parse_api_keys_json_expands_full_property() {
    let json = r#"[{"description":"t","keyHash":"deadbeef","permissions":["full"]}]"#;
    let keys = parse_api_keys_json(json).unwrap();
    assert!(!keys[0].permissions.contains(&Permission::Full));
    let mut clone = keys.clone();
    expand_full_permissions(&mut clone);
    assert_eq!(clone[0].permissions, keys[0].permissions);
}
