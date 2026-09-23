# Internal adversarial self-assessment (NOT an external audit)

**Status:** AI-assisted / in-house review — **does not** replace the three external
engagements in [`PAYMENT_HARDENING_BACKLOG.md`](./PAYMENT_HARDENING_BACKLOG.md)
(crypto lab, pentest `ironcryptd`, purple-team + KMS/HSM/gateway).

**Date:** 2026-09-23  
**Scope:** crypto/protocol, daemon auth/TLS, FFI/ops — aligned with
[`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md).

Do **not** tick external-audit checkboxes based on this document.

---

## Executive summary

Payment engineering posture is strong. The review found a **Critical** production
gap (CryptoProvider stream path skipped `EncryptionContext`) plus several **High**
authz / deploy issues. Highest-severity items that were fixable in-repo were
patched in the same session; residual risks remain for true external validation.

| Severity | Open (post-fix) | Fixed this session |
|----------|--------------------|--------------------|
| Critical | 0 code paths known | EncryptionContext on provider stream; dual-control honesty |
| High | KMS wrap AAD, HSM CBC-PAD, HMAC oracle, circuit DoS, … | allowedServices fail-closed, Azure AAD reject, FFI Argon2 caps, archive PAX/symlink, metrics Payment bind, compose mlock |
| Medium+ | See backlog below | Audit chain race, Docker default `payment-daemon` |

---

## Fixed this session

1. **`encrypt_stream_with_dek` + daemon `/write`** — require/bind `EncryptionContext`
   (headers `X-IronCrypt-Tenant-Id` / `Purpose` / `Record-Id` under Payment).
2. **JSON decrypt under Payment** — require caller `expected_context` (not only
   “ciphertext has some context”).
3. **`allowedServices`** — missing/`[]` deny; `"*"` for allow-all.
4. **Azure KMS** — reject non-empty AAD instead of silently ignoring.
5. **Audit `seal_chain`** — single lock for prev+next (no fork under concurrency).
6. **Metrics** — Payment refuses non-loopback bind.
7. **Archive unpack** — use `entry.size()` (PAX); refuse symlink components in dest.
8. **`verify_password`** — cap Argon2 params (FFI DoS).
9. **Dual-control** — normalize principal IDs; docs: unsigned / not wired to daemon.
10. **Docker** — default `IRONCRYPT_FEATURES=payment-daemon`; compose `IPC_LOCK` + memlock + tmpfs flags.

---

## Residual High / Medium (not fully closed)

| ID | Severity | Topic | Why still open |
|----|----------|--------|----------------|
| R1 | High | `wrap_key` has no AAD / KMS EncryptionContext on DEK wrap | Trait + all providers need API change + migration |
| R2 | High | HSM AES-CBC-PAD (no integrity) allowed under Payment | Needs AES-GCM/KW mechanism + SoftHSM matrix |
| R3 | High | HMAC use-secret is a signing oracle (`Read` only) | Needs new permission + domain-separated input |
| R4 | High | Global provider circuit DoS by one API key | Needs per-principal quarantine |
| R5 | High | Admin `/tls` unauthenticated (path + errors) | Needs token or Unix socket |
| R6 | Medium | ECIES wrap AAD empty; content stream no AAD | Protocol change / HPKE |
| R7 | Medium | Dual-control approvals unsigned + unused by daemon | Product wiring + signatures |
| R8 | Medium | Streaming HTTP 200 before crypto finishes | Protocol / trailers |
| R9 | Info | HPKE migration deferred | External crypto review first |

---

## What an external lab should still do

Use [`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md). Priority asks:

1. Formal ECIES-v1 vs HPKE (findings R1, R6, R9).
2. Live SoftHSM / cloud HSM CBC malleability (R2).
3. Staging pentest: authz (`allowedServices`), HMAC oracle (R3), circuit DoS (R4), admin/metrics exposure (R5).
4. Purple-team: gateway compromise + shared KMS key without EncryptionContext on wrap.

---

## Honesty clause

This document improves readiness and closes concrete bugs. It is **not**:

- a certification,
- a pentest report,
- evidence for PCI / ISO / customer security questionnaires claiming “independently audited”.

When budget exists, buy the external package; map findings to this file + backlog.
