# IronCrypt key-encapsulation protocol (ECIES-v1)

**Status:** in-repo formal specification of the **current** Payment path.  
**Decision:** retain ECIES-v1 for Payment; **HPKE** is a planned migration (see §7), not the production default.

This document is the “audit formel du protocole actuel” backlog item. It does **not**
replace an external cryptographic review.

Companion: [`PAYMENT_SECURITY.md`](./PAYMENT_SECURITY.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md),
[`src/ecc_utils.rs`](./src/ecc_utils.rs), [`src/envelope.rs`](./src/envelope.rs).

---

## 1. Role in the hybrid envelope

```
plaintext ──AES-256-GCM(DEK, AAD=EncryptionContext)──► ciphertext
DEK ───────ECIES-v1(recipient P-256)─────────────────► encapsulated_key + ephemeral_pk
         or CryptoProvider.wrap_key (KMS/HSM) ────────► provider ciphertext
```

ECIES-v1 only wraps the **32-byte DEK**. Application data never goes through ECIES directly.

---

## 2. Algorithms (fixed under Payment)

| Step | Algorithm | Notes |
|------|-----------|--------|
| Ephemeral ECDH | NIST P-256 | `p256` crate; one-shot `EphemeralSecret` |
| KDF | HKDF-SHA-256 | salt = none; IKM = raw ECDH shared secret |
| HKDF `info` | UTF-8 fixed string (below) | Domain separation |
| Key wrap | AES-256-GCM | Random 12-byte nonce prefixed to ciphertext |

### HKDF info (canonical)

```
ironcrypt-ecies-v1|usage=kek|alg=aes-256-gcm|curve=p256
```

Exported in code as `ecc_utils::ECIES_HKDF_INFO_V1`. Any change requires a **new**
version string and a migration path.

### Encapsulated blob layout

```
encapsulated_key := nonce (12 bytes) || AES-GCM(ciphertext || tag)
```

- Nonce: CSPRNG (`OsRng`), never reused for another wrap with the same KEK (KEK is
  ephemeral per encapsulation).
- Associated data for the wrap AEAD: **empty** (context binding is on the data AEAD).

### Recipient encoding (stream / JSON)

See `RecipientInfo::Ecc`: base64(ephemeral SPKI PEM) + base64(encapsulated_key) +
`key_version`.

---

## 3. Decapsulation

1. Parse ephemeral public key; ECDH with recipient static secret.
2. HKDF-Expand with `ECIES_HKDF_INFO_V1` → 32-byte KEK (zeroized after use).
3. Split nonce ∥ ciphertext; AES-GCM decrypt → DEK.
4. **Payment:** legacy paths disabled (`allow_legacy_nonce = false`).

### Legacy (migration tools only)

| Artifact | Value | Status |
|----------|-------|--------|
| Old HKDF info | `ironcrypt-ecies-kek` | Decrypt-only if `allow_legacy_nonce` |
| Fixed nonce | ASCII `ironcrypt-iv` (12 bytes) | Same gate |

`ironcrypt migrate` / non-Payment builds may enable legacy; Payment must not.

---

## 4. Security properties (claimed)

| Property | Mechanism |
|----------|-----------|
| Confidentiality of DEK | ECDH + AES-GCM wrap |
| Forward secrecy per ciphertext | Ephemeral ECDH key |
| Domain separation | Versioned HKDF info |
| Binding of application data | AES-GCM AAD = `EncryptionContext` (not ECIES) |
| No fixed-nonce reuse (Payment) | Random nonce; legacy banned |

### Explicit non-claims

- Not HPKE (RFC 9180); not a NIST SP 800-56AR3 “approved” module claim.
- Does not authenticate the recipient identity beyond possession of the private key.
- Does not replace mTLS / API-key auth on `ironcryptd`.

---

## 5. Known Answer / regression coverage

- Stable HKDF info → KEK: `tests/kat_test.rs` (`ironcrypt_ecies_hkdf_info_stable`).
- Random-nonce round-trip + legacy rejection: `ecc_utils` unit tests.
- Envelope version gates: `envelope.rs` + Payment refuse V1/V2.

---

## 6. Threat notes specific to ECIES-v1

| Threat | Mitigation |
|--------|------------|
| Cross-tenant ciphertext swap | `EncryptionContext` AAD on data AEAD |
| Legacy fixed nonce | Disabled under Payment |
| KEK left in memory | `Zeroizing` on KEK / DEK paths |
| Weak recipient key | Payment forces ECC P-256; RSA banned |

---

## 7. HPKE decision & roadmap

**Decision (2026-09):** keep **ECIES-v1** as the Payment default encapsulation.

**Rationale**

- Current format is versioned (stream V4 / JSON envelope), migrated, and covered by KAT.
- Introducing HPKE changes wire format and requires dual-stack decrypt for the fleet.
- Prefer an external crypto review of ECIES-v1 **before** a format break.

**Future HPKE (not scheduled in-tree yet)**

1. Feature `hpke` behind `--features hpke` (RFC 9180, suite HPKE-P256-HKDF-SHA256-AES-128/256-GCM).
2. New `RecipientInfo::Hpke { … }` + envelope bump.
3. Decrypt accepts ECIES-v1 **and** HPKE during migration window.
4. Payment eventually forces HPKE-only once inventory is migrated.

Until then, do **not** claim HPKE interoperability.

---

## 8. Related public APIs (role separation)

| Role | API | Recoverable? |
|------|-----|--------------|
| Login hashing | `hash_login_password` / `verify_login_password` | No |
| Secret encryption | `encrypt_secret` / `encrypt_with_context` / streams | Yes |
| Integrity fingerprint | `fingerprint::FingerprintSigner` | N/A (MAC) |
| Tokenization / PAN vault | **Not provided** — see `api_roles` | — |

Never send CVV/PIN or raw PAN into IronCrypt for “tokenization”.
