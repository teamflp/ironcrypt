# External audit & pentest engagement playbook

IronCrypt Payment hardening is **not** a certification. Use this playbook to
scope third-party work. Checkboxes here track *engagement readiness*, not
completion of the external audit itself.

## 1. Cryptographic design review

**Inputs:** `PROTOCOL.md`, `PAYMENT_SECURITY.md`, `THREAT_MODEL.md`, `FORMAT_COMPAT.md`,
`src/ecc_utils.rs`, `src/encrypt.rs`, `src/crypto_provider/`, KATs in `tests/kat_test.rs`.

**Ask the lab to cover:**

- [ ] ECIES-v1 / HKDF domain separation vs classic HPKE
- [ ] AEAD nonce uniqueness and AAD binding (`EncryptionContext`)
- [ ] DEK wrap via KMS/HSM (no private key export)
- [ ] Argon2id parameters / DoS caps under Payment
- [ ] Audit HMAC / chain integrity assumptions

**Deliverable:** written findings + severity; map to backlog items.

## 2. `unsafe` / FFI review

**Inputs:** [`UNSAFE_INVENTORY.md`](./UNSAFE_INVENTORY.md), [`FFI.md`](./FFI.md), `src/ffi.rs`.

- [ ] ABI ownership / double-free / use-after-free
- [ ] Panic safety across the C boundary
- [ ] UTF-8 / null pointer handling
- [ ] Interaction with Payment RSA ban

## 3. Pentest — `ironcryptd`

**Scope (staging):** TLS+mTLS daemon, `/write` `/read`, admin `/health` `/ready`,
optional use-secret HMAC. **Out of scope:** live card data, production HSMs.

- [ ] Authn/z: API keys, service allowlists, rate limits
- [ ] TLS/mTLS misconfig, cert reload races
- [ ] Body limits / timeout / circuit breaker behavior
- [ ] Header injection / log scrubbing (`Authorization`, passwords)
- [ ] Admin listener exposure (must be loopback / private net)

## 4. Intrusion / purple-team (IronCrypt + KMS/HSM + gateway)

- [ ] Assume gateway compromise: can attacker unwrap DEKs without KMS identity?
- [ ] Stolen API key blast radius / rotation overlap
- [ ] Vault AppRole secret_id leak scenario
- [ ] Metrics / audit exfiltration value

## 5. Timing / side channels (lab)

In-repo: `tests/timing_smoke_test.rs` (smoke only).

- [ ] dudect or CTGrind on API-key hash compare and Argon2 verify
- [ ] Document platform (CPU, frequency scaling off)

## Contacts / disclosure

Follow [`SECURITY.md`](./SECURITY.md) for vulnerability reporting during the engagement.
