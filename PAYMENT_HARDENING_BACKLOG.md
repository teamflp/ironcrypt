# IronCrypt Payment Hardening — backlog de suivi

Suivi du durcissement IronCrypt avant utilisation comme **Security Core**
de la plateforme de paiement SDCREATIV.

- `[x]` = réalisé (dans le dépôt actuel)
- `[ ]` = restant
- Priorités : **P0** bloquant prod financière · **P1** avant pilote · **P2** maturité / certification

Mettre à jour ce fichier à chaque livraison (cocher + date courte en fin de ligne si utile).

Voir aussi : [`PAYMENT_SECURITY.md`](./PAYMENT_SECURITY.md).

> **Backlog de suivi (cases à cocher)** : [`PAYMENT_HARDENING_BACKLOG.md`](./PAYMENT_HARDENING_BACKLOG.md).


---

## Légende des lots

| Lot | Thème | Statut |
|-----|--------|--------|
| **1** | Fondations : profil Payment, bornes, FFI, zeroize, legacy ECIES | Fait |
| **1b** | `CryptoProvider` + AWS KMS + Vault Transit + HSM in-device + wrap DEK | Fait |
| **2** | DoS/ops : sémaphore, streaming HTTP, logs/audit, migrate legacy, ban RSA runtime | Fait |
| **3** | AAD, lifecycle clés, auth password, API keys, fuzz | Fait |
| **4** | CI supply-chain, SECURITY, SBOM, attestations, rsa hors Payment | Fait |
| **5** | Rewrap Provider, daemon resilience, zeroize, AAD tests, threat model | Fait |
| **6** | Enveloppe versionnée, rotation policy, audit riche, multi-tenant | Fait |
| **7** | FFI ABI v1 + Azure/GCP KMS CryptoProviders | Fait |
| **8** | KAT + allowlist, retry provider, cargo-vet/Miri scaffolding | Fait |
| **9** | Fichiers 0600, audit chain/sign segments, webhooks HMAC, rate-limit/identité | Fait |
| **10** | Audit/logs : signing non-PEM, secret-name scrub, SIEM, rétention | Fait |
| **11** | Crypto/protocole : PROTOCOL ECIES-v1, fingerprint, api_roles | Fait |

---

## P0 — Bloquant avant production financière

### HSM / KMS / abstraction crypto

- [x] Remplacer `pkcs11 = 0.2.0` (HSM via `cryptoki`, feature `hsm`)
- [x] Transformer le HSM en vrai backend crypto (`HsmProvider` : encrypt/decrypt in-device)
- [x] Abstraction `CryptoProvider` (`LocalKeyProvider`, `AwsKmsProvider`, `VaultTransitProvider`, `HsmProvider`)
- [x] Séparer `SecretStore` de `CryptoProvider`
- [x] Vrais backends KMS (AWS KMS + Vault Transit ; Azure/GCP Keys encore absents)
- [x] Clé privée HSM/KMS ne quitte pas le dispositif (wrap/unwrap DEK côté provider)
- [x] PIN HSM retiré du modèle « `String` obligatoire dans TOML » (optionnel + `IRONCRYPT_HSM_PIN`)
- [x] Traiter l’advisory RSA `RUSTSEC-2023-0071` — feature `rsa-algo` (default on) ; Payment: `--no-default-features` + `deny.payment.toml` (ban `rsa`, pas d’ignore Marvin)
- [x] Profil verrouillé `Payment` / feature `payment` (`PaymentSecurityProfile`)
- [x] Providers Azure Key Vault Keys / Managed HSM et GCP Cloud KMS (`azure-kms`, `gcp-kms`)

### Format / ECIES / DoS parsing

- [x] Supprimer le mode legacy à nonce fixe du profil Payment (désactivé sous `payment` ; opt-in migrate)
- [x] Outil explicite de migration des anciens ciphertexts (`ironcrypt migrate`)
- [x] Limiter `header_len` avant allocation (`MAX_STREAM_HEADER_SIZE`)
- [x] Limiter tailles contrôlées par l’entrée (recipients, metadata, key_version, clés encapsulées)
- [x] Domaine HKDF ECIES renforcé (`ironcrypt-ecies-v1|usage=kek|…`)
- [x] Format d’enveloppe strictement versionné (`src/envelope.rs` : V4 current, V3 supported, V1/V2 migratable / rejected under Payment)

### Mémoire / zeroization

- [x] Zeroization des KEK ECIES
- [x] Utiliser davantage `Zeroizing<T>` sur tous les chemins (erreurs / retours anticipés) — `memsec` + DEK/KEK/`decrypt`/`encrypt`/`password`/FFI
- [x] Zeroizer toutes les DEK temporaires (pas seulement certains chemins) — `new_dek32` / `zeroizing_vec` / wipe hors-closure stream
- [x] Zeroizer copies de passphrases (CLI, daemon, FFI) — `secret_input::resolve_passphrase` / `Zeroizing` + wipe FFI
- [x] Zeroizer hash Argon2 déchiffré après vérification
- [x] Zeroizer clé API temporaire après génération (raw bytes ; secret String encore côté CLI)

### Password / auth vs secret récupérable

- [x] Séparer complètement hash login et chiffrement de secret (`hash_login_password` / `verify_login_password` vs `encrypt_secret` / `decrypt_secret`) dans l’API Payment
- [x] Ne plus imposer le chiffrement asymétrique du hash Argon2 pour les comptes utilisateurs (Payment : `hash_login_password`)

### Daemon / réseau

- [x] Limite HTTP body (`DefaultBodyLimit` + `DEFAULT_HTTP_BODY_LIMIT` / `--max-body-bytes`)
- [x] `/write` et `/read` en **vrai** streaming (SyncIoBridge + duplex ; body plus accumulé en Vec)
- [x] Limite de concurrence crypto (sémaphore / pool borné sur `spawn_blocking`)
- [x] mTLS sur `ironcryptd` (`--tls-client-ca` ; obligatoire sous `payment`)
- [x] Profil Payment : HTTP non chiffré interdit
- [x] Désactiver endpoints secrets en clair sous Payment (`GET/POST /service/.../secret/...` non montés)
- [x] Aucune donnée sensible dans les labels Prometheus (allowlist `command`/`status` + test)
- [x] Brancher daemon / IronCrypt sur `CryptoProvider` pour wrap DEK réel
- [x] Interdiction RSA runtime Payment (load keys, encrypt/decrypt stream, password, CLI generate/rotate, FFI)

### FFI

- [x] Corriger `c_str_to_str()` (copie immédiate en `String`, plus de `'static` lieur)
- [x] Lifetime / ownership FFI correcte
- [x] Empêcher les panics de traverser la FFI (`catch_unwind` / `ERROR_PANIC`)

### Audit / logs

- [x] Séparer conceptuellement `audit_directory` / rolling vs `log_path` fichier (`AuditConfig::rolling_directory`)
- [x] Corriger bout-en-bout `sign_audit_log()` vs rolling daemon (segments / epochs)
- [x] Ne pas stocker la clé privée de signature d’audit dans un simple fichier PEM (HSM/KMS) — `signing_mode` hmac-env|provider ; PEM interdit sous Payment
- [x] Filtrer `error_message` avant journalisation (providers) — `audit::sanitize_error_message` / `AuditEvent::set_failure`
- [x] Interdire explicitement dans les logs : plaintext, PAN, CVV, PIN, clés, tokens, passphrases, ciphertext volumineux (scrub + doc sur `AuditEvent::log`)

### Standards / config Payment

- [x] Renommer / clarifier `FipsCompatibleProfile` / `AnssiCompatibleProfile` (plus de claim de certification)
- [x] Interdire `CryptoStandard::Custom` dans le profil Payment
- [x] `PaymentCompatible` + `PaymentSecurityProfile` fixe
- [x] Allowlist runtime stricte des suites (au-delà du profil config)
- [x] Doc `PAYMENT_SECURITY.md`

### Fuzz / tests P0

- [x] Ajouter `cargo-fuzz` (`fuzz/`)
- [x] Fuzzer `decrypt_stream()`
- [x] Test DoS `header_len` oversized (`tests/header_limits_test.rs`)

---

## P1 — Nécessaire avant pilote réel

### Crypto / protocole

- [x] Privilégier ECC pour le profil paiement (Payment force ECC)
- [x] Revoir ECIES maison → HPKE **ou** audit formel du protocole actuel — `PROTOCOL.md` (ECIES-v1 formel ; HPKE roadmap, défaut inchangé)
- [x] Format d’enveloppe versionné (doc + refuse versions non migrables)
- [x] Authentifier davantage de contexte avec AAD (`tenant_id`, `purpose`, `record_id`, …)
- [x] API `encrypt_with_context()`
- [x] Identifiants de contexte obligatoires multi-tenant (anti-réutilisation de ciphertext entre marchands) — requis sous `payment`

### Zeroization / secrets process

- [x] Zeroizer DEK / passphrases / hash sur chemins critiques (`rewrap_data`, decrypt, password encrypt, daemon DEK)
- [x] Étudier `mlock` — best-effort Unix (`feature = "mlock"` via `payment` + `IRONCRYPT_MLOCK` ; `MEMORY.md`)

### Password

- [x] `password_needs_rehash()`
- [x] Valider bornes Argon2 (DoS config) — caps Payment + `hash_password_with_config`
- [x] Séparer hash login (`hash_login_password` / `verify_login_password`) vs secrets récupérables (`encrypt_secret` / `decrypt_secret`) ; `encrypt_password` refusé sous Payment

### Daemon / ops

- [x] Timeouts par requête (`TimeoutLayer` / `IRONCRYPT_REQUEST_TIMEOUT_SECS`)
- [x] Timeouts fournisseurs KMS / Secrets / HSM (`IRONCRYPT_PROVIDER_TIMEOUT_SECS` + `with_timeout`)
- [x] Circuit breaker backends distants (`CircuitBreaker` ; retry contrôlé via `RetryPolicy` / `with_retry`)
- [x] Versions TLS minimales et politiques crypto explicites (TLS 1.2+ rustls; Payment refuse RSA)
- [x] Rotation automatique des certificats de service (SIGHUP + mtime poll / `TlsMaterial`)
- [x] Séparer listeners crypto vs administration (`--admin-port` : `/health` `/ready` `/tls`)
- [x] Opérations « use secret » plutôt que « give me the secret » (`POST .../secret/.../hmac`)
- [x] CORS fail-closed par défaut (origines vides) ; désactiver explicitement CORS Payment si besoin produit
- [x] Rate limiting distribué (identité, clé API, IP, endpoint) — `memory` + Redis (`redis-rate-limit`) ; gateway/WAF toujours recommandé
- [x] Rate limiting principal au gateway/WAF + 2ᵉ ligne `ironcryptd` — 2ᵉ ligne : buckets auth+route (+IP), cap 10k

### API keys

- [x] Expiration + révocation (`created_at`, `expires_at`, `revoked_at`)
- [x] Identifiant / prefix (`ick_live_…`)
- [x] `last_used_at`, origine, propriétaire (modèle + touch in-memory à l’auth ; pas de rewrite disque)
- [x] Rotation avec chevauchement (`not_before`, `replaces_key_id`, `ironcrypt rotate-api-key`, reload SIGHUP)
- [x] Remplacer `keys.json` en production — `ApiKeyStore` (`file` | `env`/`IRONCRYPT_API_KEYS_JSON`) ; IAM/Vault sync futur
- [x] `X-Password` refusé sous Payment (`allow_x_password_header`)

### FFI (suite)

- [x] ABI IronCrypt documentée (version, ownership, erreurs, thread safety) — `FFI.md`
- [x] Versionner les fonctions FFI sensibles (`ironcrypt_ffi_abi_version`, ABI v1)
- [x] Éviter génération PEM privés en clair via FFI en prod (HSM/KMS) — doc + Payment refuse RSA FFI
- [x] Zeroizer buffers FFI sensibles avant free (`ironcrypt_free_string`)
- [x] Codes d’erreur FFI structurés (`ffi::codes`)
- [x] Tests FFI (nulls, non-UTF-8, free null, login hash, ECC gen)

### Audit (suite)

- [x] Journaux append-only (`append_audit_jsonl`)
- [x] Chaîne d’intégrité (hash de l’événement précédent)
- [x] Signer segments / epochs (`sign_audit_rolling_directory` / `sign_audit_log`)
- [x] Champs audit riches (`request_id`, `principal_id`, `tenant_id`, durée)
- [x] Masquer noms de secrets sensibles dans les logs (`sanitize_secret_name`)
- [x] Vérifier que `Authorization` / `X-Password` ne sont jamais dans les traces HTTP (TraceLayer span sans ces headers)
- [x] Export SIEM sans secrets (`export_audit_jsonl_for_siem` / `audit_event_to_siem`)
- [x] Politique de rétention logs / audits (`retention_days` + `purge_expired_audit_segments`)

### Lifecycle clés

- [x] États `PENDING` / `ACTIVE` / `DECRYPT_ONLY` / `RETIRED` / `REVOKED` / `DESTROYED` (`KeyState` + `keyring.json`)
- [x] Séparer `key_id` et `key_version` (manifest)
- [x] Stocker algorithme + provider par version
- [x] Dates activation / rotation / expiration (champs manifest)
- [x] Rotations crash-safe (tmp + fsync + rename) — `atomic_write` sur PEM + keyring
- [x] Rewrap DEK sans rechiffrer les données (`IronCrypt::rewrap_data` Provider + local; CLI `rotate-key`)
- [x] Politique automatique de rotation (`RotationPolicy` + `ironcrypt keyring-status` + warn daemon ; scheduler cron hors process)

### Standards / doc

- [x] Vocabulaire FIPS / ANSSI clarifié (`*CompatibleProfile`)
- [x] Allowlist suites crypto maintenue (`src/crypto_allowlist.rs`)
- [x] Known Answer Tests (AES-GCM, HKDF RFC 5869, ECIES info, ECDSA) — `tests/kat_test.rs`
- [x] `THREAT_MODEL.md`
- [x] Frontières de confiance documentées (`PAYMENT_SECURITY.md` + `THREAT_MODEL.md`)
- [x] Documenter ce qu’IronCrypt protège / ne protège pas (`PAYMENT_SECURITY.md`)
- [x] Éviter affirmations réglementaires non qualifiées partout (README/FR encore à purger)
- [x] `PAYMENT_SECURITY.md`
- [x] Ne jamais stocker CVV/PIN (doc Payment)
- [x] Module signature messages / webhooks (HMAC / asym + `key_id`, timestamp, version)
- [x] API fingerprint à clé secrète (`FingerprintSigner`)
- [x] Séparer tokenisation / chiffrement / hashing dans l’API publique (`api_roles` + refus CHD)

### Tests / fuzz / charge

- [x] Fuzzer headers JSON / longueurs binaires (`fuzz/stream_header`)
- [x] Fuzzer PEM / PKCS entrants (`fuzz/pem_pkcs`)
- [x] Fuzzer FFI (`fuzz/ffi`)
- [x] Property-based tests (`proptest` — `tests/property_test.rs`)
- [x] Tests ciphertext tronqué / corrompu / bit-flip / mauvaise version (`tests/aad_corruption_test.rs`, `crypto_negative_test`)
- [x] Tests collisions / substitutions AAD (`tests/aad_corruption_test.rs`)
- [x] Tests concurrence et charge daemon (`tests/concurrency_load_test.rs` — wrap/encrypt parallèle + circuit)
- [x] Tests panne HSM/KMS mid-op (`tests/provider_failure_test.rs`)
- [x] Tests rotations avec kill process (`tests/rotation_crash_test.rs` — `atomic_write` / keyring reload)
- [x] Tests isolation multi-tenant (`tests/multi_tenant_test.rs`)
- [x] Fuzzer `decrypt_stream` (`fuzz/decrypt_stream` + `cargo-fuzz`)
- [x] Ajouter `cargo-fuzz` (crate `fuzz/`)

### CI / supply-chain

- [x] CI profil paiement : aucune advisory critique ignorée pour `rsa` (`deny.payment.toml` + ban crate)
- [x] Fail pipeline si vulnérabilité crypto non acceptée (`cargo audit` / `cargo deny` + Payment deny)
- [x] SBOM (`scripts/sbom.sh` + job CI CycloneDX artifact)
- [x] Signer releases et images Docker (attest-build-provenance sur push image GHCR)
- [x] Provenance / attestations de build (idem)
- [x] Analyse secrets Git en CI (gitleaks)
- [x] SAST Rust (`clippy -D warnings` en job lint)
- [x] Pinner GitHub Actions (SHAs)
- [x] Procédure MAJ deps crypto avec revue obligatoire (`DEPENDENCY_UPDATE.md`)
- [x] Job CI `payment` (clippy + tests `--no-default-features --features payment`)
- [x] `SECURITY.md` + divulgation responsable

### Déploiement

- [x] Image Docker durcie (non-root `ironcrypt` user ; notes RO FS / drop caps au runtime)
- [x] Ne plus monter dossier de clés privées sur instances Payment si KMS/HSM (`docker-compose.payment.yml` + warn daemon)
- [x] Séparer config et secrets (`ironcrypt.toml` non secret ; secrets via env — `DEPLOY.md`)
- [x] Vault AppRole / K8s auth / workload identity (plus de token statique) — AppRole + K8s login ; cloud IAM documenté
- [x] IAM Roles AWS (pas de clés statiques) — doc + config sans access keys
- [x] Managed Identity Azure — doc (`DefaultAzureCredential`)
- [x] Workload Identity GCP — doc / ADC
- [x] Health : liveness vs readiness (`/health` vs `/ready` sur `--admin-port`)
- [x] Readiness vérifie backend crypto sans fuite d’info (circuit + présence backend, pas de détail d’erreur)
- [x] Métriques latence crypto / erreurs (`crypto_provider_*` + command histograms)
- [x] Protéger `/metrics` (bind `127.0.0.1` par défaut — `IRONCRYPT_METRICS_BIND`)
- [x] HA provider crypto (`HaCryptoProvider` + `crypto_provider.failover[]`)
- [x] Session pooling HSM (`max_sessions`, default 4)
- [x] Logout/close HSM via RAII même en erreur (`with_session` login/logout + Drop)
- [x] Éviter `Box::leak` PKCS#11 legacy (cryptoki n’en a plus besoin)
- [x] Permissions locales clés fichier `0600` + anti-symlink + `create_new`
- [x] Ne plus recommander `--passphrase "secret"` en CLI prod
- [x] TTY / stdin / fd pour passphrases (`secret_input` : env → file → fd → stdin → CLI → TTY `rpassword`)
- [x] Repenser / supprimer `X-Password` du profil Payment (`allow_x_password_header` → reject 400)
- [x] Durcir `encrypt-dir` / `decrypt-dir` (path traversal, symlinks — `archive_safe`)
- [x] Limites archives / decompression bombs (`MAX_ARCHIVE_*`)
- [x] Max fichiers + taille totale extraction (`MAX_ARCHIVE_ENTRIES` / `MAX_ARCHIVE_UNPACKED_BYTES`)
- [x] Politique de compatibilité des formats (durée de support) — `FORMAT_COMPAT.md`
- [x] Outil `ironcrypt migrate` séparé du runtime Payment

---

## P2 — Maturité industrielle / certification

- [x] `mlock` / verrouillage mémoire sensible (best-effort ; voir `MEMORY.md` — pas un substitut HSM)
- [x] Dual control / M-of-N pour ops admin critiques (`src/dual_control.rs` — quorum d’approvals)
- [x] `TokenizationProvider` dédié (trait + `RefusingTokenizationProvider` ; pas de vault PAN)
- [x] Benchmarks reproductibles (`benches/crypto_bench.rs` — AES-GCM / ChaCha ; KMS via métriques staging)
- [x] Mesure fuites timing sur ops critiques (smoke `tests/timing_smoke_test.rs` ; dudect = engagement externe)
- [ ] Audit cryptographique externe — playbook [`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md) (exécution hors repo)
- [x] Audit code `unsafe` / FFI — inventaire [`UNSAFE_INVENTORY.md`](./UNSAFE_INVENTORY.md) (+ revue externe)
- [ ] Pentest `ironcryptd` — scope dans `AUDIT_ENGAGEMENT.md` (exécution hors repo)
- [ ] Intrusion test IronCrypt + KMS/HSM + API Gateway — idem
- [x] `SECURITY.md` + divulgation responsable
- [x] Politique correctifs critiques (délai max) — documentée dans `SECURITY.md` (14j critiques)
- [x] Brancher / feature Payment séparée du crate généraliste (`payment` ⊕ ban `rsa-algo` ; crate dédié optionnel plus tard)
- [x] Providers Azure Key Vault Keys + GCP KMS (`azure-kms` / `gcp-kms`)
- [x] `cargo-vet` (imports Mozilla/Google + `exemptions` + `imports.lock` ; CI `cargo vet --locked` enforce)
- [x] Miri script + job CI (`scripts/miri.sh` ; `continue-on-error` jusqu’à stabilisation Miri nightly)

---

## Réalisations livrées (résumé technique)

| Domaine | Artifacts |
|---------|-----------|
| Profil Payment | `src/payment.rs`, feature `payment`, `CryptoStandard::PaymentCompatible` |
| Limits | `src/limits.rs`, checks dans `encrypt.rs`, `tests/header_limits_test.rs` |
| CryptoProvider | `src/crypto_provider/` (`local`, `aws_kms`, `azure_kms`, `gcp_kms`, `vault_transit`, `hsm`) |
| DEK wrap | `RecipientInfo::Provider`, `encrypt_stream_with_dek`, `decrypt_stream_with_dek`, IronCrypt + daemon |
| HSM | `cryptoki` (feature `hsm`), `HsmProvider` ; SecretStore HSM legacy désactivé |
| FFI | `src/ffi.rs` + `FFI.md` (ABI v1, login hash, ECC, zeroize free) |
| ECIES | zeroize KEK, HKDF v1, legacy gated |
| Daemon | body limit, mTLS, TLS obligatoire Payment, secrets HTTP off |
| Doc | `PAYMENT_SECURITY.md`, `ironcrypt.toml.example` |
| Lot 2 ops | sémaphore `DEFAULT_CRYPTO_CONCURRENCY`, streaming `/write`/`/read`, `sanitize_error_message`, `ironcrypt migrate`, ban RSA runtime Payment |
| Lot 3 | `EncryptionContext` / `encrypt_with_context`, login hash API, `key_lifecycle` + `atomic_write`, API keys `ick_live_`, `fuzz/` |
| Lot 4 | `rsa-algo` feature-gate, `deny.payment.toml`, CI pin SHAs + gitleaks + SBOM + attest, `DEPENDENCY_UPDATE.md`, Docker non-root |
| Lot 5 | `rewrap_data`, daemon TimeoutLayer + provider timeout + circuit breaker, TLS 1.2+, `THREAT_MODEL.md`, `tests/aad_corruption_test.rs` |
| Lot 6 | `envelope.rs`, `RotationPolicy` + `keyring-status`, audit `request_id`/`principal_id`/`duration_ms`, TraceLayer safe, multi-tenant test |
| Lot 7 | `FFI.md` + ABI v1 (login/ECC/zeroize free), `azure-kms` + `gcp-kms` CryptoProviders |
| Lot 8 | `crypto_allowlist`, `tests/kat_test.rs`, `RetryPolicy`/`with_retry`, `supply-chain/` + Miri CI |
| Lot 9 | `atomic_write` 0600/anti-symlink, audit hash-chain + sign segments, `WebhookSigner`, rate-limit/identité, `secret_input` |
| Zeroize | `src/memsec.rs`, DEK/`Zeroizing` sur encrypt/decrypt/password/ECIES/daemon/FFI (wipe early-return) |
| Audit logs | `AuditSigningMode` hmac-env/provider, `sanitize_secret_name`, SIEM export, `retention_days` purge |
| Protocol | `PROTOCOL.md` (ECIES-v1 + HPKE roadmap), `FingerprintSigner`, `api_roles` (hash/encrypt/fp ; no tokenization) |
| Secrets process | `mlock` best-effort (`MEMORY.md`), passphrase env/file/fd/stdin/TTY (`secret_input`) |
| Daemon ops | TLS SIGHUP reload, `--admin-port`, use-secret HMAC, X-Password ban Payment, RL route+IP |
| API keys | `not_before` / overlap rotate CLI, `ApiKeyStore` file\|env, catalog reload, in-memory `last_used_at` |
| Tests/fuzz | `pem_pkcs`+`ffi` fuzz, `proptest`, concurrency/load, provider mid-op fail, rotation crash |
| Déploiement | `DEPLOY.md`, payment compose sans PEM, Vault AppRole/K8s, metrics loopback, archive_safe, `FORMAT_COMPAT.md` |
| P2 maturité | `dual_control`, `TokenizationProvider` refuse, `crypto_bench`, timing smoke, `UNSAFE_INVENTORY`, `AUDIT_ENGAGEMENT` |
| HA / Redis / vet | `HaCryptoProvider` + failover, HSM `max_sessions`, Redis rate-limit, cargo-vet enforce |

---

## Prochain lot suggéré (maturité / hors repo)

1. Audits externes (crypto, FFI, pentest) — hors repo ([`AUDIT_ENGAGEMENT.md`](./AUDIT_ENGAGEMENT.md))
2. Réduire `exemptions` cargo-vet (`safe-to-deploy`) et retirer `continue-on-error` Miri quand nightly stable
3. Migration HPKE quand revue externe OK

Quand un item est terminé : cocher `[x]` ici et, si besoin, une ligne dans le journal ci-dessous.

### Journal

| Date | Items |
|------|--------|
| 2026-09-22/23 | Lot 1 + Lot 1b (profil, limits, FFI, providers KMS/Vault/HSM, wrap DEK, doc Payment) |
| 2026-09-23 | Lot 2 (sémaphore crypto, streaming HTTP, sanitize audit, `migrate`, ban RSA runtime Payment) |
| 2026-09-23 | Lot 3 + bases Lot 4 (AAD/context, lifecycle/keyring, login vs secret, API keys, fuzz, SECURITY.md, CI payment, SBOM script) |
| 2026-09-23 | Lot 4 conclu (`rsa-algo`, deny Payment, CI supply-chain complète, Docker non-root, DEPENDENCY_UPDATE) |
| 2026-09-23 | Lot 5 (`rewrap_data`, daemon timeouts/circuit/TLS1.2+, zeroize chemins critiques, AAD/corruption tests, `THREAT_MODEL.md`) |
| 2026-09-23 | Lot 6 (enveloppe versionnée, rotation policy CLI/daemon, audit riche, TraceLayer, multi-tenant, metrics labels) |
| 2026-09-23 | Lot 7 (FFI ABI v1 + login/ECC, Azure/GCP KMS providers, `FFI.md`) |
| 2026-09-23 | Lot 8 (KAT, allowlist, provider retry, cargo-vet/Miri scaffolding) |
| 2026-09-23 | Lot 9 (0600/anti-symlink, audit chain+segments, webhooks HMAC, rate-limit/identité, passphrase env/file) |
| 2026-09-23 | Mémoire/zeroization (`memsec`, DEK Zeroizing all paths, ECIES/FFI wipe) |
| 2026-09-23 | Audit/logs (signing hmac-env/provider, secret-name scrub, SIEM export, retention) |
| 2026-09-23 | Crypto/protocole (`PROTOCOL.md` ECIES-v1, fingerprint, api_roles anti-CHD) |
| 2026-09-23 | Zeroization/secrets process (`mlock` best-effort, passphrase fd/stdin/TTY, `MEMORY.md`) |
| 2026-09-23 | Daemon/ops (TLS reload, admin listener, use-secret HMAC, X-Password Payment ban) |
| 2026-09-23 | API keys (overlap rotate, ApiKeyStore file/env, reload, last_used in-memory) |
| 2026-09-23 | Tests/fuzz/charge (`pem_pkcs`/`ffi` fuzz, proptest, concurrency, provider fail, rotation crash) |
| 2026-09-23 | Déploiement (`DEPLOY.md`, payment compose, Vault AppRole/K8s, metrics bind, archive_safe, FORMAT_COMPAT) |
| 2026-09-23 | P2 maturité (`dual_control` M-of-N, TokenizationProvider refuse, crypto_bench, timing smoke, UNSAFE_INVENTORY, AUDIT_ENGAGEMENT) |
| 2026-09-23 | Restant in-repo (Redis rate-limit, HaCryptoProvider failover, HSM session pool, cargo-vet exemptions + CI enforce) |
| 2026-09-23 | Internal adversarial review (`INTERNAL_ADVERSARIAL_REVIEW.md`) + Critical/High fixes (stream AAD, allowedServices, …) — external audits still open |
