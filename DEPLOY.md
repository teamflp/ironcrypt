# IronCrypt deployment (Payment)

Companion to [`PAYMENT_SECURITY.md`](./PAYMENT_SECURITY.md) and
[`PAYMENT_HARDENING_BACKLOG.md`](./PAYMENT_HARDENING_BACKLOG.md).

## Images

```bash
# Payment daemon (no rsa-algo)
docker build --build-arg IRONCRYPT_FEATURES=payment-daemon -t ironcrypt:payment .

# Runtime hardening (orchestrator)
#   --read-only --cap-drop ALL --security-opt no-new-privileges
#   --tmpfs /tmp:rw,noexec,nosuid,size=64m
#   USER is already non-root (`ironcrypt`) in the image
```

Use [`docker-compose.payment.yml`](./docker-compose.payment.yml) for a Payment-shaped
stack: **no PEM key volume**, CryptoProvider via env, admin health on loopback.

## Config vs secrets

| Artifact | Contents |
|----------|----------|
| `ironcrypt.toml` | Non-secret: algorithms, Argon2, audit paths, provider *names*/regions/URIs |
| Env / K8s Secret / Vault | Tokens, PINs, API key JSON, TLS key paths, `IRONCRYPT_PASSPHRASE_FILE` |

Never put `VAULT_TOKEN`, HSM PIN, or API key hashes in the committed TOML.
Example split: keep [`ironcrypt.toml.example`](./ironcrypt.toml.example) clean; inject
`IRONCRYPT_API_KEYS_JSON`, `VAULT_ROLE_ID` / `VAULT_SECRET_ID`, `IRONCRYPT_HSM_PIN`.

## Identity (no static cloud keys)

| Backend | Preferred auth |
|---------|----------------|
| AWS KMS / Secrets Manager | IAM role / IRSA / instance profile (`AWS_REGION` only in config) |
| Azure Key Vault | Managed Identity / `DefaultAzureCredential` (no client secret in TOML) |
| GCP KMS | Workload Identity / ADC / `IRONCRYPT_GCP_ACCESS_TOKEN` short-lived |
| Vault Transit | AppRole (`VAULT_ROLE_ID`+`VAULT_SECRET_ID`) or K8s auth (`VAULT_K8S_ROLE`) — not long-lived root tokens |
| HSM PKCS#11 | `IRONCRYPT_HSM_PIN` from a sealed secret mount |

## Health

| Endpoint | Listener | Meaning |
|----------|----------|---------|
| `GET /health` | `--admin-port` | Liveness — process accepts connections |
| `GET /ready` | `--admin-port` | Readiness — circuit closed + crypto backend present (no error detail leak) |
| `GET /tls` | `--admin-port` | TLS reload status (ops) |

Bind admin to loopback under Payment (`--admin-host 127.0.0.1`).

## Metrics

- Enable with `IRONCRYPT_METRICS_ENABLED=true`
- Default bind **`127.0.0.1`** (`IRONCRYPT_METRICS_BIND`); scrape via sidecar / localhost proxy
- Series: `command_*`, `crypto_provider_duration_seconds`, `crypto_provider_ops_total`
- Labels allowlisted: `command`, `status`, `provider`, `op` — never tenants/keys/PAN

## Rate limiting

| Mode | Flags | When |
|------|-------|------|
| Memory (default) | `--rate-limit-backend memory` | Single replica / lab |
| Redis | `--features redis-rate-limit` + `--rate-limit-backend redis --redis-url …` | Multi-replica shared quotas |

Still put a gateway / WAF in front for edge DDoS. Redis limiter is fail-closed on broker errors.

## CryptoProvider HA + HSM pool

```toml
[crypto_provider]
provider = "aws-kms"
# …

[[crypto_provider.failover]]
provider = "aws-kms"   # e.g. multi-region replica that can unwrap the same ciphertext
```

Standbys must decrypt primary wraps (shared / multi-region key material). Nested failover lists are rejected.

HSM: `crypto_provider.hsm.max_sessions` (default 4) pools logged-in PKCS#11 sessions for concurrency.

## No private-key mounts (Payment + KMS/HSM)

When `[crypto_provider]` is set, `ironcryptd` does **not** load PEM keys.
Do not mount `/keys` into Payment pods. Local PEMs are for lab / migration only
(`ironcrypt migrate`).

## Archive CLI limits

`encrypt-dir` / `decrypt-dir` refuse symlink roots, path traversal, and extract
bombs (`MAX_ARCHIVE_*` in `limits.rs`). See [`FORMAT_COMPAT.md`](./FORMAT_COMPAT.md).
