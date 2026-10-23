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

Payment engineering posture is strong. The in-repo High findings R1–R5 are
closed (DEK-wrap context, HSM AES-GCM, HMAC permission, per-principal
quarantine, authenticated `/tls`). Residual items are medium, or need a lab
outside this repository.

| Severity | Open (post-fix) | Fixed this session |
|----------|--------------------|--------------------|
| Critical | 0 code paths known | EncryptionContext on provider stream; dual-control honesty |
| High | 0 of R1–R5 | DEK wrap AAD, HSM AES-GCM, HMAC permission, per-principal quarantine, admin `/tls` bearer |
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
| R1 | Fixed | `wrap_key` binds `EncryptionContext` (KMS context, Vault/GCP AAD, Azure frame, local ECIES) | Legacy unbound wraps still open outside Payment |
| R2 | Fixed | HSM writes AES-GCM (`ICG1`). Payment rejects AES-CBC-PAD | Live SoftHSM matrix still an external check |
| R3 | Fixed | `POST .../hmac` requires permission `hmac`; input is domain-separated | — |
| R4 | Fixed | One API key quarantines only itself. Global circuit needs two principals | — |
| R5 | Fixed | `GET /tls` requires `Authorization: Bearer` from `IRONCRYPT_ADMIN_TOKEN` | — |
| R6 | Medium | Content-stream ECIES AAD still empty on the local PEM path | Protocol change / HPKE |
| R7 | Medium | Dual-control approvals unsigned + unused by daemon | Product wiring + signatures |
| R8 | Medium | Streaming HTTP 200 before crypto finishes | Protocol / trailers |
| R9 | Info | HPKE migration deferred | External crypto review first |

---

## What an external lab should still do

Use [`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md). Priority asks:

1. Formal ECIES-v1 vs HPKE (findings R6, R9). DEK wrap now binds context (R1).
2. Live SoftHSM confirmation that the token accepts `CKM_AES_GCM` (R2 is AES-GCM in code; CBC is rejected under Payment).
3. Staging pentest: confirm `hmac` is required, one API key cannot open the global circuit, and `/tls` rejects a missing bearer.

---

## Honesty clause

This document improves readiness and closes concrete bugs. It is **not**:

- a certification,
- a pentest report,
- evidence for PCI / ISO / customer security questionnaires claiming “independently audited”.

When budget exists, buy the external package; map findings to this file + backlog.
