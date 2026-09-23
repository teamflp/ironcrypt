# IronCrypt Payment Security Profile

This document describes how IronCrypt is intended to be used as the **payment
security core** for SDCREATIV financial workloads. It is a hardening posture,
not a claim of PCI DSS, FIPS 140, or ANSSI product certification.

**Backlog de suivi (cases à cocher)** : [`PAYMENT_HARDENING_BACKLOG.md`](./PAYMENT_HARDENING_BACKLOG.md).
**Threat model** : [`THREAT_MODEL.md`](./THREAT_MODEL.md).  
**ECIES protocol (formal in-repo)** : [`PROTOCOL.md`](./PROTOCOL.md).  
**FFI ABI** : [`FFI.md`](./FFI.md).  
**Memory hygiene (zeroize / mlock / passphrases)** : [`MEMORY.md`](./MEMORY.md).  
**Deployment** : [`DEPLOY.md`](./DEPLOY.md).  
**Format compatibility** : [`FORMAT_COMPAT.md`](./FORMAT_COMPAT.md).  
**External audits / pentest playbook** : [`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md).  
**Unsafe / FFI inventory** : [`UNSAFE_INVENTORY.md`](./UNSAFE_INVENTORY.md).  
**Internal self-assessment (not a substitute for external audit)** : [`INTERNAL_ADVERSARIAL_REVIEW.md`](./INTERNAL_ADVERSARIAL_REVIEW.md).

## Product split (Payment vs generalist)

Payment is enforced by the Cargo feature `payment` (mutually exclusive with
`rsa-algo`) plus `deny.payment.toml`. A separate `ironcrypt-payment` crate is
**not** required for the locked profile; optional later if packaging demands it.
Build Payment graphs with:

```bash
cargo build -p ironcrypt --no-default-features --features payment-daemon
```

## What IronCrypt protects

- Confidentiality of application secrets and sensitive records at rest (hybrid
  encryption with AES-256-GCM and ECC P-256 encapsulation under the Payment
  profile).
- Integrity of ciphertexts via AEAD (AES-GCM / XChaCha20-Poly1305 outside Payment).
- Optional audit event emission for crypto operations (hash-chained JSONL +
  optional segment signatures).
- HMAC webhook / message signatures (`WebhookSigner`) for outbound callbacks.
- Secret-keyed record fingerprints (`FingerprintSigner`) for integrity without
  recoverability.
- Explicit API roles: hashing vs encryption vs fingerprint; **no** tokenization /
  PAN vault (see `api_roles`, [`PROTOCOL.md`](./PROTOCOL.md)).

## What IronCrypt does **not** protect / must not store

- **Never store CVV or PIN** in IronCrypt envelopes. Cardholder authentication
  data that PCI DSS forbids retaining must not enter this library.
- Network attackers between Payment API and `ironcryptd` when TLS/mTLS is not
  correctly deployed.
- A compromised host that can read process memory before zeroization.
- Supply-chain compromise of dependencies (mitigated separately via CI/SBOM).

## Trust boundaries

| Zone | Trust |
|------|--------|
| Payment API / app | Authenticated client of IronCrypt (mTLS + API key) |
| `ironcryptd` | Crypto service; holds or fronts keys |
| KMS/HSM `CryptoProvider` | Sole holder of private key material in production |
| `SecretStore` (Vault/AWS SM/…) | Opaque secret values — **not** crypto key operations |
| Local PEM keys | Development / migration only |
| Operator / CI | Trusted to configure keys and review dependency bumps |

### What crosses the boundary

- **In**: ciphertext / stream bodies, `EncryptionContext`, API key bearer token,
  optional password header (never logged).
- **Out**: ciphertext, audit JSON (sanitized), Prometheus metrics with
  allowlisted labels only (`command`, `status`).
- **Never out**: DEK plaintext, KEK, raw API secrets, PAN/CVV/PIN, Authorization
  header values.

See also [`THREAT_MODEL.md`](./THREAT_MODEL.md).

## Build & runtime

```bash
# Payment MUST use --no-default-features so rsa-algo is not linked (RUSTSEC-2023-0071).
# Combining `payment` with default/`rsa-algo` is a compile error.
cargo build -p ironcrypt --no-default-features --features payment-daemon
cargo build -p ironcrypt --no-default-features --features payment-aws

# Daemon for payment (TLS + mTLS required)
cargo run -p ironcrypt --no-default-features --features payment-daemon --bin ironcryptd -- \
  --config ironcrypt.toml \
  --api-keys-file keys.json \
  --key-version v1 \
  --tls-cert /path/server.crt \
  --tls-key /path/server.key \
  --tls-client-ca /path/client-ca.crt

# Supply-chain check for Payment graphs (bans crate `rsa`)
cargo deny --config deny.payment.toml check
```

See [`DEPENDENCY_UPDATE.md`](./DEPENDENCY_UPDATE.md) and [`SECURITY.md`](./SECURITY.md).

### Locked policy (`PaymentSecurityProfile`)

When `features = ["payment"]` is enabled (or you call `PaymentSecurityProfile::enforce`):

- `CryptoStandard::Custom` is rejected.
- Asymmetric algorithm must be **ECC** (RSA is not linked in Payment graphs;
  see RUSTSEC-2023-0071).
- Symmetric algorithm must be **AES-256-GCM**.
- Legacy PKCS#11 `hsm` **SecretStore** backend is forbidden.
- ECIES fixed-nonce legacy decrypt is disabled.
- `ironcryptd` requires TLS **and** mTLS (`--tls-client-ca`).
- Plaintext secret HTTP export (`GET /service/.../secret/...`) is not mounted.
- HTTP body size is capped (`DEFAULT_HTTP_BODY_LIMIT`, overridable).
- Encryption requires [`EncryptionContext`](./src/context.rs) (tenant / purpose / record).
- DEK buffers attempt best-effort `mlock` on Unix (`MEMORY.md`); passphrases resolve via
  env / file / fd / stdin / TTY — avoid `--passphrase` on argv.

## `SecretStore` vs `CryptoProvider`

| Trait | Responsibility |
|-------|----------------|
| `SecretStore` | Get/set opaque string secrets (credentials, tokens) |
| `CryptoProvider` | `wrap_key` / `unwrap_key` / encrypt / decrypt **without exporting private keys** |

| Provider | Feature | Notes |
|----------|---------|--------|
| `LocalKeyProvider` | (always) | Dev only — `private_material_exportable() == true` |
| `AwsKmsProvider` | `aws-kms` | IAM role / IRSA; EncryptionContext binds AAD |
| `AzureKeyVaultKeysProvider` | `azure-kms` | DefaultAzureCredential; wrapkey/unwrapkey REST |
| `GcpKmsProvider` | `gcp-kms` | Cloud KMS encrypt/decrypt; `IRONCRYPT_GCP_ACCESS_TOKEN` / ADC |
| `VaultTransitProvider` | `vault` | Transit mount; prefer `VAULT_TOKEN` / AppRole |
| `HsmProvider` | `hsm` | cryptoki PKCS#11; AES-CBC-PAD in-device; PIN via `IRONCRYPT_HSM_PIN` |

`IronCrypt::new` and `ironcryptd` call `build_from_config` when `[crypto_provider]` is set.
DEKs are wrapped via the provider (`RecipientInfo::Provider`); local PEM keys are not required
in that mode. Configure **exactly one** provider (see also `ironcrypt.toml.example`).

```toml
# --- AWS KMS ---
[crypto_provider] 
provider = "aws-kms"

[crypto_provider.aws_kms]
region = "eu-west-1"
default_key_id = "arn:aws:kms:eu-west-1:123456789012:key/…"
```

```toml
# --- Vault Transit ---
[crypto_provider]
provider = "vault-transit"

[crypto_provider.vault_transit]
address = "https://vault.internal:8200"
# token = ""   # empty → VAULT_TOKEN
mount = "transit"
```

```toml
# --- PKCS#11 HSM ---
[crypto_provider]
provider = "hsm"

[crypto_provider.hsm]
module_path = "/usr/lib/softhsm/libsofthsm2.so"
token_label = "ironcrypt"
default_key_label = "payment-aes"
# pin via IRONCRYPT_HSM_PIN (preferred over TOML)
```

```bash
cargo build -p ironcrypt --features "payment,aws-kms"
cargo build -p ironcrypt --features "payment,vault"
cargo build -p ironcrypt --features "payment,hsm,daemon"
```

```rust
use ironcrypt::crypto_provider::build_from_config;
use ironcrypt::config::IronCryptConfig;

# async fn example(config: IronCryptConfig) -> Result<(), ironcrypt::IronCryptError> {
let cp = config.crypto_provider.as_ref().expect("configured");
let provider = build_from_config(cp).await?;
assert!(!provider.private_material_exportable());
let wrapped = provider.wrap_key("", b"0123456789abcdef0123456789abcdef").await?;
let _dek = provider.unwrap_key(&wrapped.key_id, &wrapped.ciphertext).await?;
# Ok(())
# }
```

Payment builds **reject** `provider = "local"` via `PaymentSecurityProfile::validate`.

## Audit & logs

- Events are hash-chained (`prev_event_hash` / `event_hash`) and may be written
  append-only via `append_audit_jsonl`.
- **Signing under Payment** must not use a PEM private key on disk:
  - `audit.signing_mode = "hmac-env"` + `IRONCRYPT_AUDIT_HMAC_KEY`, or
  - `signing_mode = "provider"` + `signing_key_id` (CryptoProvider seals the file digest).
  PEM (`signing_mode = "pem"` / bare `signing_key_path`) is rejected by
  `PaymentSecurityProfile::validate`.
- Secret **names** in daemon logs are masked (`sanitize_secret_name` → `sec:<len>:<hash8>`).
- SIEM export: `export_audit_jsonl_for_siem` / `audit_event_to_siem` — allowlisted
  fields only; raw `error_message` is replaced by `error_category`.
- Retention: set `audit.retention_days`; `ironcryptd` purges old `audit.log*`
  segments at startup (`purge_expired_audit_segments`).

## Migration notes

- Historical ECIES payloads using HKDF info `ironcrypt-ecies-kek` and/or fixed
  nonce `ironcrypt-iv` must be re-encrypted with a dedicated migration tool
  **before** cutting over to `--features payment` in production.
- Prefer `hash_password` / `verify_password` (PHC Argon2id) for login accounts;
  do not require asymmetric decryption of credential hashes for auth.

## Roadmap (remaining)

1. External crypto + FFI audits / pentest ([`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md)).
2. Shrink cargo-vet `exemptions` toward `safe-to-deploy`; drop Miri `continue-on-error` when nightly is stable.
3. HPKE migration after external protocol review.
