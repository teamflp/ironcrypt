# Crypto dependency update procedure (IronCrypt)

This document is the mandatory review checklist when changing cryptographic
dependencies (AES, Argon2, ECC/P-256, RSA, HKDF, rustls/aws-lc, KMS/HSM SDKs).

## Scope

Treat as **crypto-sensitive** any bump of:

- `aes-gcm`, `aes-gcm-stream`, `chacha20poly1305`, `cipher`
- `argon2`, `hkdf`, `sha2`, `p256`, `elliptic-curve`, `rsa` (feature `rsa-algo` only)
- `rustls`, `aws-lc-rs`, `tokio-rustls`, `cryptoki`
- Cloud KMS/Secrets SDKs that perform crypto or TLS (`aws-sdk-kms`, `vaultrs`, …)

## Required steps

1. **Read the changelog / advisory** for the new version (RustSec, GitHub releases).
2. **Run locally**
   - `cargo test --lib --locked`
   - `cargo test --features full --locked` (or targeted feature set)
   - Payment: `cargo test --lib --no-default-features --features payment --locked`
   - `cargo deny check`
   - Payment deny: `cargo deny --config deny.payment.toml check`
   - `cargo audit`
3. **Do not silently expand `ignore` lists** in `deny.toml` / `audit.toml`.
   New ignores need a dated reason and an owner in the PR description.
4. **Payment graphs** must stay free of `rsa` (`rsa-algo` off + `deny.payment.toml` ban).
5. **Open a dedicated PR** titled `deps(crypto): …` with:
   - Why the bump is needed (security fix vs feature)
   - Test evidence (CI / local commands)
   - Any residual risk

## Emergencies

Critical remote-code or key-recovery advisories: patch within the window in
[`SECURITY.md`](./SECURITY.md) (acknowledge ≤72h, aim ≤14 days for critical crypto).

## cargo-vet (optional but recommended)

IronCrypt ships a `supply-chain/` tree for [cargo-vet](https://mozilla.github.io/cargo-vet/).

```bash
cargo install cargo-vet --locked
./scripts/cargo-vet.sh
```

Populate audits before enforcing in CI (already enforced via `cargo vet --locked`).
Prefer `safe-to-deploy` for crates on the Payment dependency graph; reduce
`exemptions` over time with `cargo vet suggest` / `cargo vet certify`.
