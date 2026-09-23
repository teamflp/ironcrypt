# Ciphertext format compatibility

IronCrypt stream / envelope formats are versioned. This policy applies to
Payment and general builds.

## Support window

| Format | Status | Notes |
|--------|--------|-------|
| Stream header V2 + ECIES-v1 (current) | **Supported** | Default for new encrypts |
| Stream header V1 | Decrypt-only | Prefer `ironcrypt migrate` |
| Legacy ECIES fixed-nonce | Decrypt-only outside Payment; **disabled** under `payment` | Offline migrate without Payment feature |
| RSA-OAEP recipients | Available only with `rsa-algo`; **forbidden** under Payment | See RUSTSEC-2023-0071 |

## Guarantees

- **N (current major)** encrypt/decrypt: full support for at least **24 months** after a
  successor format ships.
- **N-1**: decrypt-only for at least **12 months**.
- Breaking wire changes require a new version field and a documented migration path
  (`ironcrypt migrate` or re-encrypt via `rewrap_data` / rotate-key).

## Archive CLI (`encrypt-dir` / `decrypt-dir`)

Not part of the Payment runtime path. Hardened limits:

- No symlink/hardlink entries; no `..` / absolute paths
- `MAX_ARCHIVE_ENTRIES` / `MAX_ARCHIVE_ENTRY_BYTES` / `MAX_ARCHIVE_UNPACKED_BYTES`

See `src/archive_safe.rs` and `src/limits.rs`.
