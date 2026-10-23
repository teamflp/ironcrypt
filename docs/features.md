# Pistes d'amélioration — futures versions d'IronCrypt

> Document de travail interne (non suivi par Git). Basé sur l'état du code au
> 2026-08-05 (`algorithms.rs`, `keys.rs`, `ecc_utils.rs`, `standards.rs`,
> features Cargo…).

## 🔑 Cryptographie / algorithmes
- **Curve25519 (Ed25519 / X25519)** — aujourd'hui seul P-256 est supporté pour
  l'ECC. Ed25519/X25519 sont plus rapides, plus simples à implémenter en temps
  constant, et largement recommandés (moins de pièges que P-256).
- **Post-quantique hybride** — ajouter ML-KEM (Kyber) pour l'échange de clé et
  ML-DSA (Dilithium) pour la signature, en mode hybride avec RSA/ECC
  existants. C'est la direction que prennent NIST/ANSSI/BSI ; s'y mettre tôt
  évite une refonte plus tard.
- **Courbes additionnelles** — P-384/P-521 pour les profils "haute sécurité"
  (FIPS niveau supérieur), ce qui compléterait bien `standards.rs`.
- **Signatures Ed25519** en plus d'ECDSA (`signing.rs`), plus rapide et moins
  sujet aux erreurs de nonce.
- **Threshold cryptography / Shamir's Secret Sharing** pour la récupération de
  clés maîtresses (utile pour les scénarios HSM/multi-approbateurs).

## 🗝️ Gestion des clés
- **Rotation automatique programmée** (politique d'expiration, alerte avant
  expiration) plutôt que rotation manuelle uniquement.
- **Intégration KMS native** (AWS KMS, Azure Key Vault *keys* — pas juste
  *secrets*, GCP KMS) pour du "bring your own key" avec enveloppe chiffrée
  côté cloud, en complément des secrets managers déjà supportés.
- **Meilleur support HSM** (`secrets/hsm.rs`) — actuellement basé sur
  `pkcs11`, à étoffer avec plus de tests d'intégration réels (SoftHSM en CI)
  et supporter FIDO2/PIV (YubiKey) pour des cas d'usage plus légers.

## ⚙️ Performance / streaming
- **API de streaming pleinement async** (actuellement AES streaming existe
  via `aes-gcm-stream`, mais vérifier le backpressure/chunking pour très
  gros fichiers).
- **Benchmarks Criterion** publiés dans le repo pour suivre les régressions
  de perf entre versions.
- **Cible WASM** — compiler la lib pour le navigateur/edge, ce qui ouvrirait
  IronCrypt à des cas d'usage front-end (chiffrement côté client avant
  envoi).

## 🛡️ Sécurité / audit
- **Audit de sécurité externe** avant une v1.0 stable — vu que le crate
  touche à du chiffrement de mots de passe et des clés privées, un audit
  tiers (type Trail of Bits / Cure53) rassurerait fortement les
  utilisateurs crates.io.
- **Fuzzing continu** (`cargo-fuzz`) sur les parseurs de format (JSON
  enveloppe, PEM, formats de fichiers chiffrés) — surface d'attaque
  classique.
- **Vecteurs de test officiels** (NIST CAVP, RFC test vectors) pour garantir
  l'interopérabilité des primitives.
- **Vérification formelle des propriétés "constant-time"** (via `dudect` ou
  équivalent) sur les comparaisons de secrets.

## 🌐 Interopérabilité / bindings
- Le PHP SDK et le FFI C ABI existent déjà : ajouter des **bindings Python et
  Node.js** (via `pyo3` / `napi-rs`) élargirait beaucoup l'audience, ces deux
  écosystèmes étant les plus demandeurs de crypto "prête à l'emploi".
- **Bindings mobiles** (Swift/Kotlin via `uniffi-rs`) si un usage mobile est
  envisagé.

## 🖥️ Daemon / API
- **mTLS** pour `ironcryptd` en plus de TLS serveur simple.
- **RBAC plus fin** que le système de permissions actuel (`write`/`read`) —
  scoping par clé, par répertoire, etc.
- **Spec OpenAPI/Swagger** générée automatiquement pour l'API REST.
- **Rate limiting** intégré (protection contre le brute-force sur l'endpoint
  de vérification de mot de passe).
- Envisager un **endpoint gRPC** en parallèle du REST pour les intégrations à
  fort débit.

## 📊 Observabilité
- Le module `metrics.rs` exporte déjà vers Prometheus — ajouter le
  **support OpenTelemetry** (traces distribuées) serait cohérent avec l'usage
  `tracing` déjà en place.
- **Logs d'audit tamper-evident** (chaînage par hash façon "Merkle log") dans
  `audit.rs` pour garantir l'intégrité de l'historique, pas juste sa
  présence.

## ✅ Conformité / standards
- Ajouter d'autres profils dans `standards.rs` : **BSI (Allemagne)**,
  **ISO/IEC 19790**, ou un profil "Suite B" — utile pour des clients dans
  différentes juridictions.
- Exposer une commande CLI `ironcrypt audit-compliance` qui vérifie qu'une
  configuration/clé respecte un standard donné.

---

## 🎯 Priorités (si on doit n'en garder que 3)
1. **Curve25519 (Ed25519/X25519)** — gain immédiat en perf/sécurité, effort
   modéré vu que l'infra ECC existe déjà.
2. **Bindings Python/Node.js** — multiplie l'audience potentielle du crate à
   effort raisonnable (FFI existe déjà comme base).
3. **Audit de sécurité externe + fuzzing** — condition de confiance pour
   qu'un projet de chiffrement de mots de passe/clés soit adopté sérieusement
   en production.
