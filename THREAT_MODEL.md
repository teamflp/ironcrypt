# IronCrypt threat model

This document describes what IronCrypt protects, what it does not, and the
trust boundaries assumed when it is used as a payment **Security Core**.

Companion docs: [`PAYMENT_SECURITY.md`](./PAYMENT_SECURITY.md),
[`PAYMENT_HARDENING_BACKLOG.md`](./PAYMENT_HARDENING_BACKLOG.md),
[`PROTOCOL.md`](./PROTOCOL.md) (ECIES-v1),
[`SECURITY.md`](./SECURITY.md).

## Scope

**In scope**

- Confidentiality and integrity of application secrets and payment data at rest
  (hybrid envelope encryption: AES-256-GCM / XChaCha20-Poly1305 + ECC or
  CryptoProvider-wrapped DEKs).
- Binding of ciphertext to an application [`EncryptionContext`](./src/context.rs)
  (tenant / purpose / record) via AEAD AAD.
- Authentication of daemon callers via API keys (and mTLS under Payment).
- Isolation of private key material behind a [`CryptoProvider`](./src/crypto_provider/)
  (KMS / Vault Transit / HSM) when configured.
- Operational hardening of `ironcryptd`: body limits, concurrency caps, request
  timeouts, provider timeouts, circuit breaker, TLS 1.2+.

**Out of scope**

- Network perimeter, WAF, DDoS beyond daemon-local rate limits.
- Host compromise (root, debugger, memory dump of a process that holds a DEK
  or passphrase in RAM).
- Correctness of upstream KMS/HSM policy (key deletion, IAM misconfiguration).
- PCI DSS / PSD2 / FIPS certification claims — IronCrypt provides building
  blocks and a Payment profile; compliance is an organizational process.
- Never store CVV/PIN — callers must not send them to IronCrypt.

## Assets

| Asset | Sensitivity | Notes |
|-------|-------------|--------|
| DEK (data-encryption key) | Critical | Short-lived in memory; zeroized after use on critical paths |
| KEK / asymmetric private keys | Critical | Prefer non-exportable CryptoProvider |
| Passphrases / API keys | High | Config / env; not logged |
| Ciphertext + header | Medium | Public; integrity via AEAD |
| EncryptionContext | Medium | Authenticated as AAD; not secret by itself |
| Audit events | Medium | Must not contain secrets or raw Authorization headers |

## Trust boundaries

```
┌──────────────┐     mTLS + API key      ┌─────────────┐
│  App / edge  │ ──────────────────────► │  ironcryptd │
└──────────────┘                         └──────┬──────┘
                                                │ wrap/unwrap DEK
                                                ▼
                                         ┌─────────────┐
                                         │ KMS/HSM/Vault│
                                         └─────────────┘
```

1. **Caller → daemon**: untrusted network input. Authn required. Body size and
   timeouts enforced. Payment profile requires TLS + client certificates.
2. **Daemon → CryptoProvider**: trusted configuration, untrusted availability.
   Timeouts + circuit breaker prevent cascade failures.
3. **Library embedder**: the process is trusted for the duration a DEK is in
   use; IronCrypt zeroizes DEKs/passphrases on critical paths but cannot defeat
   a compromised host.
4. **Keyring / PEM on disk**: trusted storage with OS permissions; Payment
   prefers provider-backed keys over local PEM.

## Adversaries (summary)

| Adversary | Goal | Mitigations |
|-----------|------|-------------|
| External HTTP attacker | DoS, crypto oracle, secret exfil | Auth, rate limit, body limit, timeouts, no plaintext secret HTTP under Payment |
| Confused deputy / cross-tenant | Decrypt another tenant’s data | EncryptionContext AAD + decrypt-time match |
| Ciphertext tampering | Forge / alter payloads | AEAD; reject bit-flip / truncate |
| Compromised API key | Encrypt/decrypt as that principal | Key prefix `ick_live_`, rotation, least privilege permissions |
| Provider outage / hang | Availability loss | Provider timeout + circuit breaker |
| Supply-chain dependency | Vulnerable crypto | `cargo deny`, pinned advisories, Payment builds without `rsa-algo` |

## Security properties claimed

- **Confidentiality**: plaintext unreadable without DEK unwrap capability.
- **Integrity / authenticity**: AEAD tag failure on corrupt or substituted AAD.
- **DEK rewrap**: [`IronCrypt::rewrap_data`](./src/ironcrypt.rs) changes only
  recipient wrapping; payload ciphertext and nonce stay unchanged.
- **Forward secrecy of DEKs**: not claimed across process lifetime; rotate keys
  and rewrap when KEK versions change.

## Explicit non-goals

- Homomorphic / searchable encryption.
- Client-side browser crypto.
- Guaranteeing that callers never log secrets.
- Making `LocalKeyProvider` suitable for production Payment (it is exportable
  and rejected by the Payment profile when selected as sole backend).
