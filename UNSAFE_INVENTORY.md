# Unsafe / FFI inventory (in-repo)

Living checklist for external `unsafe` / FFI audits. Regenerate by searching
`unsafe` under `src/` after each release.

## Policy

- Prefer safe Rust. `unsafe` requires a `// SAFETY:` comment naming invariants.
- FFI (`src/ffi.rs`) is the primary ABI surface — see [`FFI.md`](./FFI.md).
- Payment builds should avoid RSA FFI paths (`payment` rejects RSA).

## Inventory (2026-09-23)

| Location | Kind | Notes |
|----------|------|-------|
| `src/ffi.rs` | `extern "C"` + `unsafe` blocks | ABI v1; null checks; `catch_unwind`; wipe on free |
| `src/memsec.rs` | `libc::mlock` / `munlock` | Unix only; best-effort; documented in `MEMORY.md` |
| `src/secret_input.rs` | `File::from_raw_fd` | Unix passphrase FD; file forgotten (FD not closed) |
| `src/crypto_provider/hsm.rs` | cryptoki session | Native PKCS#11; logout on Drop path |

## Review prompts for external auditors

1. Are all FFI entry points panic-safe (`catch_unwind`)?
2. Is every returned `*mut c_char` owned exactly once and wiped in `ironcrypt_free_string`?
3. Can `from_raw_fd` be confused with double-close?
4. Does `mlock` failure leave secrets in swappable pages (accepted risk)?
5. HSM: session login/logout pairing under error paths?

## Out of scope here

Dependency crates' own `unsafe` (reviewed via `cargo-vet` / supply-chain policy).
