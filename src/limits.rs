//! Hard limits for attacker-controlled sizes in encrypted formats and HTTP I/O.
//!
//! These caps exist to prevent DoS via oversized allocations (e.g. a forged
//! `header_len`) before cryptographic validation can reject the payload.

/// Maximum encrypted-stream header size (bytes), including JSON metadata.
pub const MAX_STREAM_HEADER_SIZE: usize = 1_048_576; // 1 MiB

/// Maximum number of recipients in a multi-recipient envelope.
pub const MAX_RECIPIENTS: usize = 64;

/// Maximum length of a single key version string.
pub const MAX_KEY_VERSION_LEN: usize = 128;

/// Maximum length of a base64-encoded encapsulated key field.
pub const MAX_ENCAPSULATED_KEY_B64_LEN: usize = 16_384;

/// Maximum length of encrypted metadata (base64) in V4 headers.
pub const MAX_ENCRYPTED_METADATA_B64_LEN: usize = 65_536;

/// Maximum PEM / PKCS document size accepted from untrusted input.
pub const MAX_PEM_BYTES: usize = 65_536;

/// Max files extracted from an `encrypt-dir` / `decrypt-dir` archive.
pub const MAX_ARCHIVE_ENTRIES: u32 = 10_000;

/// Max bytes for a single archive entry when unpacking.
pub const MAX_ARCHIVE_ENTRY_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Max total uncompressed bytes extracted from one archive.
pub const MAX_ARCHIVE_UNPACKED_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Default HTTP body limit for `ironcryptd` (bytes).
pub const DEFAULT_HTTP_BODY_LIMIT: usize = 16 * 1024 * 1024; // 16 MiB

/// Default max concurrent crypto operations in `ironcryptd` (`spawn_blocking` slots).
pub const DEFAULT_CRYPTO_CONCURRENCY: usize = 32;

/// Default HTTP request timeout for `ironcryptd` (seconds).
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 60;

/// Default remote CryptoProvider timeout (seconds).
pub const DEFAULT_PROVIDER_TIMEOUT_SECS: u64 = 15;

/// Consecutive provider failures before the daemon circuit opens.
pub const DEFAULT_CIRCUIT_FAILURE_THRESHOLD: u32 = 5;

/// Circuit cool-down when open (seconds).
pub const DEFAULT_CIRCUIT_COOLDOWN_SECS: u64 = 30;

/// Maximum Argon2 memory cost (KiB) accepted from configuration.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1_048_576; // 1 GiB

/// Maximum Argon2 time cost accepted from configuration.
pub const MAX_ARGON2_TIME_COST: u32 = 32;

/// Maximum Argon2 parallelism accepted from configuration.
pub const MAX_ARGON2_PARALLELISM: u32 = 16;
