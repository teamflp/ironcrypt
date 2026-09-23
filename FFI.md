# IronCrypt C FFI (ABI v1)

Stable C ABI exported from the `cdylib` / `staticlib` build of `ironcrypt`.

## Versioning

| Symbol | Meaning |
|--------|---------|
| `ironcrypt_ffi_abi_version()` | Major ABI version (`1`). Bump only on breaking changes. |
| Function names | May gain new `ironcrypt_*` symbols; old symbols stay until a major bump. |

Payment builds (`--features payment`, no `rsa-algo`) expose ECC + login-hash APIs only.
RSA helpers return `ERROR_UNSUPPORTED` (`-9`) when Payment is enabled.

## Ownership

| Allocator | Free with |
|-----------|-----------|
| Any `*mut c_char` returned by IronCrypt | `ironcrypt_free_string` **only** |
| Caller-owned input C strings | Caller |

`ironcrypt_free_string` **zeroizes** the buffer before release. Double-free is undefined.
Passing `NULL` to `ironcrypt_free_string` is safe (no-op).

## Thread safety

All exported functions are safe to call concurrently from multiple threads **as long as**
they do not share the same output pointer being written. The library holds no global
mutable crypto state in the FFI layer.

## Error codes (`ironcrypt::ffi::codes`)

| Code | Name | Meaning |
|------|------|---------|
| `0` | `SUCCESS` | OK (or see function docs for `1`/`0` bools) |
| `-1` | `ERROR_NULL_POINTER` | Required pointer was null |
| `-2` | `ERROR_INVALID_UTF8` | Input was not valid UTF-8 |
| `-3` | `ERROR_KEY_GENERATION` | Key generation failed |
| `-4` | `ERROR_KEY_ENCODING` | PEM encode failed |
| `-5` | `ERROR_ENCRYPTION_FAILED` | Encrypt failed |
| `-6` | `ERROR_DECRYPTION_FAILED` | Decrypt failed |
| `-7` | `ERROR_VERIFICATION_FAILED` | Verify failed |
| `-8` | `ERROR_KEY_DECODING` | PEM / key parse failed |
| `-9` | `ERROR_UNSUPPORTED` | Disabled by profile / feature |
| `-10` | `ERROR_HASHING_FAILED` | Argon2 hash failed |
| `-98` | `ERROR_PANIC` | Panic caught at FFI boundary |
| `-99` | `ERROR_UNKNOWN` | Unclassified error |

## Payment-preferred API

- `ironcrypt_hash_login_password` / `ironcrypt_verify_login_password` — Argon2id PHC
- `ironcrypt_generate_ecc_keys` — P-256 PEM pair
- `ironcrypt_free_string` / `ironcrypt_ffi_abi_version`

## Legacy (requires `rsa-algo`, forbidden under Payment)

- `ironcrypt_generate_rsa_keys`
- `ironcrypt_password_encrypt` / `ironcrypt_password_verify`

## Do not

- Generate RSA private PEMs via FFI in Payment production — use a CryptoProvider (KMS/HSM).
- Log or persist FFI password / private-key buffers.
- Call RSA helpers when `ironcrypt_ffi_abi_version` is used from a Payment-linked binary
  (they return `-9`).
