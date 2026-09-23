# Memory hygiene: zeroize & mlock

Companion to [`PAYMENT_SECURITY.md`](./PAYMENT_SECURITY.md) and
[`src/memsec.rs`](./src/memsec.rs).

## Zeroization (always on)

Sensitive buffers use [`zeroize`](https://docs.rs/zeroize):

| Buffer | Mechanism |
|--------|-----------|
| DEK 32-byte | `memsec::new_dek32` / `Zeroizing<[u8; 32]>` |
| Unwrapped DEK `Vec` | `zeroizing_vec` |
| ECIES KEK | `Zeroizing<[u8; 32]>` in `ecc_utils` |
| Passphrases | `secret_input::resolve_passphrase` → `Zeroizing<String>` |
| FFI strings | wipe before `ironcrypt_free_string` |

**Limitations:** the compiler / OS may still leave copies in registers, core
dumps, or swapped pages that were copied before wipe. Zeroize is necessary but
not sufficient against a compromised host.

## `mlock` (best-effort, Unix)

| Control | Effect |
|---------|--------|
| Cargo feature `mlock` | On by default under `payment` |
| `IRONCRYPT_MLOCK=1` | Enable even without the feature |
| `IRONCRYPT_MLOCK=0` | Disable even when the feature is on |

`new_dek32` / `zeroizing_vec` call `try_mlock` when enabled. Failure is **non-fatal**
(logged at `debug`).

### Why best-effort only

- Requires sufficient `RLIMIT_MEMLOCK` (or `CAP_IPC_LOCK` / equivalent).
- Locks **whole pages**; a 32-byte DEK may pin adjacent allocations.
- Does not lock copies created by crypto libraries or the kernel.
- Not available / no-op on non-Unix targets.

### Operator notes (Payment)

```bash
# Prefer feature via payment profile builds; optional explicit confirm:
export IRONCRYPT_MLOCK=1

# If mlock fails in production logs, raise memlock limit (example systemd):
# LimitMEMLOCK=infinity
```

External review / hardened kernels may still prefer keeping long-lived secrets
only in HSM/KMS (`CryptoProvider`), not in process RAM.

## Passphrase resolution (no argv)

Preference order in [`secret_input`](./src/secret_input.rs):

1. `IRONCRYPT_PASSPHRASE`
2. `IRONCRYPT_PASSPHRASE_FILE`
3. `IRONCRYPT_PASSPHRASE_FD` (file descriptor number)
4. `IRONCRYPT_PASSPHRASE_STDIN=1` (one line from stdin)
5. CLI `--passphrase` (discouraged under Payment)
6. Interactive TTY prompt (`resolve_passphrase_or_prompt`, CLI builds with `rpassword`)
