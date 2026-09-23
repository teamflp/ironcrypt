# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

Payment / financial deployments should build with `--features payment` (and a
CryptoProvider backend such as `aws-kms`, `vault`, or `hsm`) and follow
[`PAYMENT_SECURITY.md`](./PAYMENT_SECURITY.md).

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue
for exploitable flaws.

- Preferred: open a private security advisory on the GitHub repository, or
  email the maintainers listed in `Cargo.toml` / repository ownership.
- Include: affected version, reproduction steps, impact assessment, and any
  suggested fix.
- We aim to acknowledge reports within **72 hours** and to publish a fix or
  mitigation for critical cryptographic defects within **14 days** when feasible.

## Scope

In scope: cryptographic correctness, key handling, daemon authz, FFI memory
safety, and supply-chain issues in published crates/images.

Out of scope: denial-of-service from unbounded caller-controlled work that is
already documented as requiring gateway rate limits; social engineering;
issues only present in unsupported versions.
