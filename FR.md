# IronCrypt

- [IronCrypt](#ironcrypt)
  - [Fonctionnalités](#fonctionnalités)
  - [Démarrage rapide](#démarrage-rapide)
  - [Utiliser IronCrypt depuis PHP](#utiliser-ironcrypt-depuis-php)
  - [Utiliser IronCrypt via FFI (ABI C)](#utiliser-ironcrypt-via-ffi-abi-c)
  - [Scénarios d'utilisation](#scénarios-dutilisation)
    - [Chiffrement/Déchiffrement de mot de passe](#chiffrementdéchiffrement-de-mot-de-passe)
    - [Chiffrement/Déchiffrement de fichier](#chiffrementdéchiffrement-de-fichier)
    - [Chiffrement/Déchiffrement de répertoire](#chiffrementdéchiffrement-de-répertoire)
  - [Installation](#installation)
  - [Utilisation](#utilisation)
    - [Interface en ligne de commande (CLI)](#interface-en-ligne-de-commande-cli)
    - [En tant que bibliothèque (Crate)](#en-tant-que-bibliothèque-crate)
  - [Configuration](#configuration)
  - [Sécurité et bonnes pratiques](#sécurité-et-bonnes-pratiques)
  - [Contribution](#contribution)
  - [Licence](#licence)

**IronCrypt** est un outil en ligne de commande (CLI) et une bibliothèque Rust dédiée au chiffrement sécurisé des mots de passe et des données. En combinant l'algorithme de hachage **Argon2**, le chiffrement symétrique **AES-256-GCM** ou **XChaCha20-Poly1305**, et la cryptographie asymétrique moderne comme **RSA** ou la **cryptographie sur les courbes elliptiques (ECC)**, IronCrypt offre une solution robuste et flexible pour garantir la confidentialité des données et la sécurité des mots de passe de votre application.

---

## Fonctionnalités

- **Chiffrement hybride et moderne :** IronCrypt utilise un modèle de chiffrement hybride robuste. Il chiffre les données avec un chiffrement symétrique haute performance (AES-256-GCM ou XChaCha20-Poly1305) et protège la clé symétrique à l'aide d'une cryptographie asymétrique de pointe. Ce "chiffrement d'enveloppe" offre le meilleur des deux mondes : la vitesse des chiffrements symétriques et la gestion sécurisée des clés de la cryptographie à clé publique.
- **Cryptographie asymétrique flexible :** Choisissez entre **RSA** pour une large compatibilité ou la **cryptographie sur les courbes elliptiques (ECC)** pour des performances plus élevées et des tailles de clé plus petites, offrant une sécurité équivalente avec moins de surcoût. Les deux sont entièrement pris en charge pour le chiffrement et les signatures numériques.
- **Chiffrement multi-destinataires :** Prend en charge nativement le chiffrement d'un seul fichier ou répertoire pour plusieurs utilisateurs, même avec différents types de clés (par exemple, certains destinataires utilisant RSA, d'autres ECC). Chaque utilisateur peut déchiffrer les données avec sa propre clé privée unique, sans avoir besoin de partager de secrets.
- **Clés chiffrées par phrase de passe :** Les clés privées peuvent être chiffrées en option avec une phrase de passe fournie par l'utilisateur pour une couche de sécurité supplémentaire, les protégeant même si les fichiers de clés sont exposés.
- **Hachage de mot de passe de pointe :** Pour les mots de passe, IronCrypt utilise Argon2, actuellement considéré comme l'un des algorithmes de hachage les plus sécurisés au monde. Il est spécifiquement conçu pour résister aux attaques par force brute modernes basées sur les GPU, offrant une sécurité bien plus grande que les anciens algorithmes.
- **Gestion avancée des clés :** Le système de gestion de versions de clés intégré (`-v v1`, `-v v2`) et la commande dédiée `rotate-key` vous permettent de mettre à jour vos clés de chiffrement au fil du temps. Cela automatise le processus de migration vers une nouvelle clé sans avoir à déchiffrer et rechiffrer manuellement toutes vos données. IronCrypt peut charger à la fois les clés PKCS#8 modernes et les clés PKCS#1 héritées, garantissant une large compatibilité.
- **Configuration flexible :** Vous pouvez affiner les paramètres de sécurité via le fichier `ironcrypt.toml`, les variables d'environnement ou la structure `IronCryptConfig` dans le code. Cela inclut la taille de la clé RSA et les "coûts" de calcul de l'algorithme Argon2, vous permettant d'équilibrer la sécurité et les performances en fonction de vos besoins.
- **Chiffrement en flux (streaming) :** Pour **AES-256-GCM sans signature**, IronCrypt chiffre et déchiffre par morceaux sans charger tout le fichier en mémoire. **Limites :** (1) **XChaCha20-Poly1305** est one-shot (le plaintext est bufferisé) ; (2) une **signature** dans l’en-tête impose aussi un pré-buffer du contenu pour le hachage. Choisissez AES sans signature pour les très gros fichiers.
- **Chiffrement complet des données :** IronCrypt est conçu pour gérer plus que de simples mots de passe. Il peut chiffrer n'importe quel fichier (images, PDF, documents), des répertoires entiers (en les archivant d'abord), ou toute autre donnée pouvant être représentée comme un flux d'octets.
- **Double usage (CLI et bibliothèque) :** IronCrypt est conçu dès le départ pour être à double usage. Vous pouvez l'utiliser comme un outil en ligne de commande rapide pour des tâches simples, ou l'intégrer comme une bibliothèque (crate) directement dans vos propres applications Rust pour une logique plus complexe.

---

## Démarrage rapide

Exemples copier-coller, alignés sur le comportement actuel du code.

### 1. Préparer le lab local

```sh
git clone https://github.com/teamflp/ironcrypt.git
cd ironcrypt

# Compile CLI + daemon (opt-in : le default crates.io est bibliothèque seule)
cargo build --release --features full

# Copie les fixtures d'exemple (ne jamais committer vos vraies clés)
make bootstrap-lab
# → keys.json, ironcrypt.toml, keys/private_key_v1.pem, keys/public_key_v1.pem
```

### 2. CLI — clés, fichier, mot de passe

```sh
# Générer une paire RSA (ou --key-type ecc)
./target/release/ironcrypt generate -v v1 -d keys -s 2048

# Chiffrer / déchiffrer un fichier (AES enveloppe + clé publique v1)
./target/release/ironcrypt encrypt-file \
  -i rapport.pdf -o rapport.enc -d keys -v v1

./target/release/ironcrypt decrypt-file \
  -i rapport.enc -o rapport.out.pdf -k keys -v v1

# Mot de passe (hash Argon2id chiffré dans un JSON — jamais de hash en clair)
./target/release/ironcrypt encrypt -w 'Str0ngP@ssw0rd42!' -d keys -v v1 > secret.json
./target/release/ironcrypt decrypt -w 'Str0ngP@ssw0rd42!' -k keys -f secret.json
```

### 3. Daemon HTTP (`ironcryptd`)

Permissions API : `read`, `write`, `delete`, `update`, `full`.  
Endpoints : **`POST /write`** (chiffrer) et **`POST /read`** (déchiffrer).

```sh
# 1) Créer une clé API
./target/release/ironcrypt generate-api-key
# → notez la « Clé API secrète » (base64) et le « Hash » (hex SHA-512)

# 2) Remplir keys.json (camelCase) à partir de keys.json.example
# {
#   "description": "lab write/read",
#   "keyHash": "<HASH_HEX>",
#   "permissions": ["write", "read"]
# }

# 3) Démarrer (loopback ; HTTP non-loopback exige TLS ou --allow-insecure-http)
./target/release/ironcryptd \
  --host 127.0.0.1 --port 3000 \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json \
  --config ironcrypt.toml \
  --rate-limit-per-sec 20 --rate-limit-burst 40

# 4) Appels curl
export API_KEY='<CLE_API_SECRETE_BASE64>'

echo 'hello ironcrypt' | curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @- \
  http://127.0.0.1:3000/write > payload.enc

curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @payload.enc \
  http://127.0.0.1:3000/read

# Mot de passe optionnel (Argon2) via en-tête :
#   -H "X-Password: Str0ngP@ssw0rd42!"
```

HTTPS in-process :

```sh
./target/release/ironcryptd \
  --host 0.0.0.0 --port 3443 \
  --tls-cert cert.pem --tls-key key.pem \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json --config ironcrypt.toml
```

### 4. Docker Compose (lab vs prod)

```sh
make bootstrap-lab
make lab    # Vault -dev + token lab (jamais en prod)
# make prod # stack prod sans root token Vault
```

### 5. Bibliothèque Rust (streaming AES)

```rust
use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    decrypt_stream, encrypt_stream, generate_rsa_keys,
    keys::{PrivateKey, PublicKey},
    Argon2Config, PasswordCriteria,
};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_rsa_keys(2048)?;
    let public_key = PublicKey::Rsa(pk);
    let private_key = PrivateKey::Rsa(sk);

    let original = b"message secret en flux";
    let mut src = Cursor::new(original.as_slice());
    let mut enc = Cursor::new(Vec::new());
    let mut password = String::new(); // pas de gate Argon2

    encrypt_stream(
        &mut src,
        &mut enc,
        &mut password,
        [(&public_key, "v1")],
        None, // pas de signature → vrai streaming AES
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    enc.set_position(0);
    let mut out = Cursor::new(Vec::new());
    decrypt_stream(&mut enc, &mut out, &private_key, "v1", "", None)?;
    assert_eq!(out.into_inner(), original);
    Ok(())
}
```

---

## Utiliser IronCrypt depuis PHP

Une appli PHP **ne lie pas** la crate Rust. Elle parle au démon HTTP **`ironcryptd`** via le client [`sdks/php`](sdks/php/) (`IronCryptClient`).

```text
App PHP  --POST /write|/read + Bearer-->  ironcryptd  (détient les clés PEM)
```

### Pourquoi ce modèle ?

- Un seul service crypto partagé (PHP, Python, curl…)
- Clés API avec permissions (`write`, `read`, …)
- Pas besoin d’embarquer les clés privées dans chaque conteneur PHP

### Mise en place

```bash
# 1) Démon (racine du dépôt)
cargo build --release --features full && make bootstrap-lab
./target/release/ironcrypt generate-api-key   # secret (base64) + hash → keys.json
./target/release/ironcryptd \
  --host 127.0.0.1 --port 3000 \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json --config ironcrypt.toml

# 2) SDK PHP
cd sdks/php && composer install
```

`keys.json` en camelCase (`keyHash`), permissions du type `["write", "read"]`.  
Envoyer la clé **secrète** telle quelle : `Authorization: Bearer …` (sans re-encoder).

### Exemple minimal PHP

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

use IronCrypt\Sdk\IronCryptClient;

$client = new IronCryptClient(getenv('IRONCRYPT_URL') ?: 'http://127.0.0.1:3000');
$apiKey = getenv('IRONCRYPT_API_KEY'); // secret base64 de generate-api-key

$ciphertext = $client->encrypt('payload sensible', $apiKey); // POST /write
$plaintext  = $client->decrypt($ciphertext, $apiKey);       // POST /read

// Gate Argon2 optionnel :
// $client->encrypt($data, $apiKey, 'Str0ngP@ssw0rd42!');
```

Stocker le ciphertext en BLOB SQL ou via `base64_encode($ciphertext)`.

Guide complet (Composer path, cURL sans SDK, erreurs `401`/`403`/`429`, alternatives CLI/FFI) : **[`sdks/php/README.md`](sdks/php/README.md)**.  
Client HTTP Python : [`sdks/python`](sdks/python/).

---

## Utiliser IronCrypt via FFI (ABI C)

Pour un usage **in-process** (sans démon HTTP), chargez la bibliothèque dynamique produite par Cargo (`cdylib`) et appelez l’API C de [`ironcrypt.h`](ironcrypt.h).

```text
Python / Java / C# / C / PHP-FFI  --appels natifs-->  libironcrypt (.so / .dylib / .dll)
```

### FFI vs démon

| | **FFI (`libironcrypt`)** | **HTTP (`ironcryptd` + SDKs)** |
| --- | --- | --- |
| Processus | Même processus que l’appli | Service séparé |
| Auth | Vous fournissez les PEM | Clé API Bearer + permissions |
| Idéal pour | Apps natives, JVM/.NET, faible latence | PHP/web, microservices multi-langages |
| Portée API C actuelle | Workflow **mot de passe** (Argon2 + enveloppe RSA) | Fichiers/flux via `/write` `/read`, secrets… |

### Compiler la bibliothèque

```bash
cargo build --release
# Linux :  target/release/libironcrypt.so
# macOS :  target/release/libironcrypt.dylib
# Windows : target/release/ironcrypt.dll
```

### Surface API

| Fonction | Succès | Rôle |
| --- | --- | --- |
| `ironcrypt_generate_rsa_keys` | `0` | Alloue les chaînes PEM privée/publique |
| `ironcrypt_password_encrypt` | `0` | Mot de passe → JSON scellé |
| `ironcrypt_password_verify` | `1` / `0` / `-1` | Valide / invalide / erreur |
| `ironcrypt_free_string` | — | **Obligatoire** pour chaque chaîne allouée par Rust |

### Idée minimale (Python ctypes)

```python
import ctypes
lib = ctypes.CDLL("target/release/libironcrypt.dylib")  # .so sous Linux

lib.ironcrypt_generate_rsa_keys.restype = ctypes.c_int32
# … argtypes, encrypt/verify, puis :
# lib.ironcrypt_free_string(ptr)
```

Exemple C : [`examples/c_api_usage.c`](examples/c_api_usage.c).  
Exemples complets (ctypes, JNA, P/Invoke, PHP `FFI`, compilation, dépannage) : **[`FFI_EXAMPLES.md`](FFI_EXAMPLES.md)**.

---

## Scénarios d'utilisation

### Chiffrement/Déchiffrement de mot de passe
![workflow-password.png](images/workflow-password.png)

Ce processus combine un hachage **Argon2** et un chiffrement d'enveloppe (AES + asymétrique) pour protéger le secret au repos.

---

### **1. Processus de chiffrement (par exemple, lors de l'inscription d'un utilisateur)**

L'objectif ici n'est pas de chiffrer le mot de passe lui-même, mais de chiffrer une **empreinte unique** (un "hash") de ce mot de passe. Le mot de passe en clair n'est jamais stocké.

1.  **Hachage du mot de passe** :
    *   Le mot de passe fourni par l'utilisateur (par exemple, `"MonMotDePasse123"`) est d'abord passé dans l'algorithme de hachage **Argon2**.
    *   Argon2 le transforme en une empreinte numérique unique et non réversible (le "hash"). Cet algorithme est conçu pour être lent et gourmand en mémoire, ce qui le rend extrêmement résistant aux attaques par force brute modernes.

2.  **Création de l'enveloppe de chiffrement** :
    *   Une nouvelle clé de chiffrement symétrique **AES-256** est générée aléatoirement. Cette clé est à usage unique et ne sera utilisée que pour cette opération.
    *   Le hash Argon2 (créé à l'étape 1) est ensuite chiffré à l'aide de cette clé AES.

3.  **Sécurisation de la clé AES (le "sceau" de l'enveloppe)** :
    *   Pour pouvoir vérifier le mot de passe plus tard, la clé AES doit être sauvegardée. La stocker en clair serait une faille de sécurité.
    *   Par conséquent, la clé AES est elle-même chiffrée, mais cette fois avec votre **clé publique RSA**. Seul le détenteur de la clé privée RSA correspondante pourra déchiffrer cette clé AES.

4.  **Stockage des données sécurisées** :
    *   Le résultat final est un objet JSON structuré qui contient toutes les informations nécessaires à la vérification future :
        *   Le **hash Argon2 chiffré** (ciphertext AES) — le hash **n’est jamais dupliqué en clair** dans le JSON.
        *   La **clé AES chiffrée** par RSA/ECC (enveloppe).
        *   Les paramètres techniques publics (nonce, version de clé, algorithme).
    *   C'est cet objet JSON qui est stocké en toute sécurité dans votre base de données.

---

### **2. Processus de vérification (par exemple, lors de la connexion d'un utilisateur)**

L'objectif ici est de vérifier si le mot de passe fourni par l'utilisateur correspond à celui qui est stocké, **sans jamais avoir à le voir en clair**.

1.  **Récupération des données** :
    *   L'utilisateur se connecte en fournissant son mot de passe (par exemple, `"MonMotDePasse123"`).
    *   Vous récupérez l'objet JSON correspondant à cet utilisateur dans votre base de données.

2.  **Ouverture de l'enveloppe** :
    *   À l'aide de votre **clé privée RSA**, vous déchiffrez la clé AES contenue dans le JSON.
    *   Une fois la clé AES en clair obtenue, vous l'utilisez pour déchiffrer le hash Argon2 d'origine.

3.  **Hachage en temps réel et comparaison** :
    *   Le mot de passe que vient de fournir l'utilisateur pour se connecter est haché à son tour, en utilisant exactement les mêmes paramètres (le "sel") que ceux stockés dans le JSON.
    *   Les deux hashes — celui qui vient d'être généré et celui déchiffré de la base de données — sont comparés.

4.  **Résultat de la vérification** :
    *   **Si les deux hashes sont identiques**, cela prouve que le mot de passe fourni est correct. L'accès est autorisé.
    *   **S'ils sont différents**, le mot de passe est incorrect. L'accès est refusé.

Ce scénario garantit que même si votre base de données était compromise, les mots de passe des utilisateurs resteraient inutilisables par un attaquant, car le mot de passe d'origine n'y est jamais stocké.

### Chiffrement/Déchiffrement de fichier

![img.png](images/img-1.png)

Ce processus utilise également le chiffrement d'enveloppe (AES + RSA) pour garantir à la fois les performances et la sécurité.

#### **1. Processus de chiffrement**

1.  **Ouverture des flux de fichiers** : IronCrypt ouvre le fichier d'entrée en lecture et le fichier de sortie en écriture. En mode **AES-256-GCM sans signature**, le contenu est traité par morceaux (streaming). Avec **XChaCha20** ou une **signature**, un buffer mémoire du contenu est requis (voir la section Fonctionnalités).
2.  **Création de l'en-tête de l'enveloppe** :
    *   Une nouvelle clé **AES-256** à usage unique est générée aléatoirement.
    *   Cette clé AES est chiffrée avec une ou plusieurs **clés publiques RSA** (une pour chaque destinataire).
    *   Un en-tête JSON est créé contenant une liste de destinataires, où chaque entrée contient la clé AES chiffrée pour cet utilisateur et la version de sa clé.
3.  **Chiffrement en flux** :
    *   L'en-tête JSON est écrit au début du fichier de sortie.
    *   IronCrypt lit ensuite le fichier d'entrée par petits morceaux, chiffre chaque morceau avec la clé AES et écrit immédiatement le morceau chiffré dans le fichier de sortie.
4.  **Finalisation** : Une fois que le fichier entier a été traité, une balise d'authentification est ajoutée à la fin du fichier de sortie pour garantir son intégrité.

#### **2. Processus de déchiffrement**

1.  **Lecture de l'en-tête** : IronCrypt lit l'en-tête JSON au début du fichier chiffré.
2.  **Ouverture de l'enveloppe** :
    *   Votre **clé privée RSA** est utilisée pour trouver votre entrée dans la liste des destinataires et déchiffrer la clé AES.
3.  **Déchiffrement en flux** :
    *   Avec la clé AES, IronCrypt lit le reste du fichier chiffré par morceaux, déchiffre chaque morceau et écrit les données en clair dans le fichier de sortie.
4.  **Vérification et enregistrement** : Après avoir traité tous les morceaux, il vérifie la balise d'authentification. Si elle est valide, le fichier d'origine est entièrement restauré.

### Chiffrement/Déchiffrement de répertoire

![img.png](images/workflow-directory.png)

Le chiffrement d'un répertoire entier est basé sur le scénario de chiffrement de fichier, avec une étape de préparation supplémentaire.

#### **1. Processus de chiffrement**

1.  **Archivage et compression** :
    *   Le répertoire cible est d'abord lu, et tous ses fichiers et sous-répertoires sont compressés dans une seule archive `.tar.gz`, qui est écrite dans un fichier temporaire sur le disque.
2.  **Chiffrement de l'archive** :
    *   Cette archive temporaire `.tar.gz` est ensuite chiffrée en utilisant le processus de **chiffrement de fichier en flux** décrit ci-dessus.
3.  **Stockage** : Le JSON résultant est enregistré dans un seul fichier chiffré.

#### **2. Processus de déchiffrement**

1.  **Déchiffrement de l'archive** :
    *   Le processus de **déchiffrement de fichier** est utilisé pour récupérer l'archive `.tar.gz` en clair.
2.  **Décompression et extraction** :
    *   L'archive `.tar.gz` est ensuite décompressée, et son contenu est extrait dans le répertoire de destination, recréant ainsi la structure et les fichiers d'origine.

---

## Installation

### Prérequis

- **Rust** ≥ **1.88** (MSRV pour le build bibliothèque par défaut — voir `rust-version` dans `Cargo.toml`)
- Dernière version **stable** recommandée pour CLI / `full` / cloud
- **Cargo** (le gestionnaire de paquets de Rust)

#### Notes MSRV

| Jeu de features | rustc minimal (approx.) | Notes |
|-----------------|-------------------------|--------|
| default (bibliothèque) | **1.88** | Garanti / testé en CI (`time` etc. dans le lockfile) |
| `cli` / `daemon` / `full` (sans bump AWS) | 1.88 | Même baseline |
| `aws` / SDK AWS actuel dans le lockfile | **1.94.1+** | Déclaré par `aws-config` / crates Smithy |

Le job CI **MSRV 1.88** exécute `cargo check/test --lib` à chaque push.

### Compiler et exécuter depuis les sources

Il y a trois façons principales d'exécuter l'outil en ligne de commande `ironcrypt`.

#### 1. Utiliser `cargo run` (Recommandé pour le développement)
Cette commande compile et exécute le programme en une seule étape. Utilisez `--` pour séparer les arguments de `cargo` de ceux de votre programme.
```sh
# Cloner le dépôt
git clone https://github.com/teamflp/ironcrypt.git
cd ironcrypt

# Exécuter la commande --help (feature CLI requise)
cargo run --features cli -- --help
```

#### 2. Compiler et exécuter l'exécutable directement
Vous pouvez compiler l'exécutable puis l'exécuter depuis son chemin dans le répertoire `target`.
```sh
# Compiler le CLI (+ daemon) — les defaults sont bibliothèque seule
cargo build --release --features full

# L'exécuter depuis son chemin
./target/release/ironcrypt --help
```

#### 3. Installer le binaire (Recommandé pour l'utilisation)
Ceci installera la commande `ironcrypt` sur votre système, la rendant disponible depuis n'importe quel répertoire. C'est la meilleure option pour une utilisation régulière.
```sh
# Depuis la racine du répertoire du projet, exécutez :
cargo install --path . --features full
# Ou depuis crates.io (une fois publié) :
# cargo install ironcrypt --features full

# Maintenant, vous pouvez utiliser la commande de n'importe où
ironcrypt --help
```

#### 4. Compiler un binaire statique pour Linux (MUSL)
Compilez des binaires statiques portables (aucune glibc requise), utiles pour les conteneurs minimaux et Alpine.

Prérequis (choisissez votre SE) :

- Debian/Ubuntu :
```sh
sudo apt-get update && sudo apt-get install -y musl-tools lld
rustup target add x86_64-unknown-linux-musl
```

- macOS (Homebrew) :
```sh
brew install FiloSottile/musl-cross/musl-cross
rustup target add x86_64-unknown-linux-musl
```

Compiler les binaires de production :
```sh
cargo build --locked --release --target x86_64-unknown-linux-musl
# Binaires :
#   target/x86_64-unknown-linux-musl/release/ironcrypt
#   target/x86_64-unknown-linux-musl/release/ironcryptd
```

Note : Le fichier .cargo/config.toml du dépôt est déjà configuré pour MUSL (musl-gcc + lld). Si vous voyez "musl-gcc not found", installez musl-tools (Linux) ou musl-cross (macOS) comme ci-dessus.

#### 5. Compiler et exécuter avec Docker
Un Dockerfile multi-étapes compile des binaires statiques et fournit une image d'exécution minimale.

Compiler l'image :
```sh
docker build -t ironcrypt:latest .
```

Exécuter le CLI à l'intérieur du conteneur :
```sh
docker run --rm ironcrypt:latest --help
```

Exécuter le démon (expose le port 3000, monte le répertoire des clés de l'hôte) :
```sh
# Générez ou placez vos clés dans ./keys d'abord
# Note : le démon se lie actuellement à 127.0.0.1 à l'intérieur du conteneur.
# Il sera accessible depuis l'intérieur du conteneur. Pour l'atteindre depuis l'hôte,
# liez le serveur à 0.0.0.0 dans le code ou utilisez une configuration réseau alternative.
docker run --rm -p 3000:3000 -v "$PWD/keys:/keys" ironcrypt:latest \
  ironcryptd -v v1 -d /keys -p 3000
```

#### 6. Utiliser le Makefile (Docker Compose)
Le Makefile fournit des raccourcis lab / prod.

Prérequis : Docker et Docker Compose v2 (`docker compose`).

```sh
make help
make bootstrap-lab   # copie *.example → fichiers locaux (sans écraser)
make lab             # alias: make dev — stack lab (Vault -dev)
make prod            # stack prod (pas de root token Vault)
make stop
make logs
make test
make coverage
```

Notes :
```sh
make lab ENV_FILE=.env.local
make prod PROD_ENV_FILE=.env.prod
```
La cible par défaut est `all -> lab`.

### Compilations optimisées avec les "Feature Flags"

IronCrypt est **library-first** sur crates.io : le jeu de features par défaut est vide (API crypto seule). Les binaires et backends cloud sont en opt-in — ça garde l’arbre de dépendances des consommateurs léger.

**Fonctionnalités disponibles :**

*   *(default)* : bibliothèque seule — API mots de passe / stream / RSA-ECC.
*   `cli` : Compile l'outil en ligne de commande `ironcrypt`.
*   `daemon` : Compile le démon `ironcryptd` et active la sous-commande `daemon` dans le CLI.
*   `interactive` : Active les indicateurs de progression dans le CLI (nécessite `cli`).
*   `aws` / `azure` / `vault` : backends secrets (`aws` nécessite actuellement rustc ≥ 1.94.1).
*   `gcp` : Google Secret Manager (**optionnel**, tire `tonic` — hors méta `cloud` / `full`).
*   `hsm` : backend PKCS#11.
*   `cloud` : `aws` + `azure` + `vault` (sans `gcp`).
*   `full` : `cli` + `daemon` + `cloud` + `interactive` (méta « tout inclus »).

**En dépendance bibliothèque :**

```toml
# Léger (recommandé pour les apps)
ironcrypt = "0.1"

# Avec backends optionnels
ironcrypt = { version = "0.1", features = ["vault"] }
```

**Compilations locales avec `cargo` :**

```sh
# Bibliothèque seule (identique au default crates.io)
cargo build --release

# Binaire CLI minimal
cargo build --release --features cli

# CLI avec AWS et indicateurs interactifs
cargo build --release --features "cli,interactive,aws"

# Démon avec fournisseurs cloud
cargo build --release --features "daemon,cloud"

# Tout sauf gcp/hsm
cargo build --release --features full
```

**Compilations Docker personnalisées :**

Vous pouvez passer les fonctionnalités à la compilation Docker en utilisant l'argument de construction `IRONCRYPT_FEATURES`.

```sh
# Compiler une image Docker minimale avec uniquement l'outil CLI
docker build --build-arg IRONCRYPT_FEATURES="cli" -t ironcrypt:cli .

# Compiler une image Docker avec le démon et le support Azure
docker build --build-arg IRONCRYPT_FEATURES="daemon,azure" -t ironcrypt:daemon-azure .
```

---

## Utilisation

### Interface en ligne de commande (CLI)

Voici un tableau récapitulatif de toutes les commandes disponibles :

| Commande | Alias | Description | Options de clé |
| :--- | :--- | :--- | :--- |
| `generate` | | Génère une nouvelle paire de clés RSA. | `-v, --version <VERSION>` <br> `-d, --directory <DIR>` <br> `-s, --key-size <SIZE>` <br> `[--passphrase <PASSPHRASE>]` |
| `encrypt` | | Hache et chiffre un mot de passe. | `-w, --password <PASSWORD>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>` |
| `decrypt` | | Vérifie un mot de passe chiffré. | `-w, --password <PASSWORD>` <br> `-k, --private-key-directory <DIR>` <br> `-f, --file <FILE>` <br> `[--passphrase <PASSPHRASE>]` |
| `encrypt-file`| `encfile`, `efile`, `ef` | Chiffre un fichier binaire. | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>...` <br> `[-w, --password <PASSWORD>]` |
| `decrypt-file`| `decfile`, `dfile`, `df` | Déchiffre un fichier binaire. | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` <br> `[--passphrase <PASSPHRASE>]` |
| `encrypt-dir` | `encdir` | Chiffre un répertoire entier. | `-i, --input-dir <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>...` <br> `[-w, --password <PASSWORD>]` |
| `decrypt-dir` | `decdir` | Déchiffre un répertoire entier. | `-i, --input-file <INPUT>` <br> `-o, --output-dir <OUTPUT>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` <br> `[--passphrase <PASSPHRASE>]` |
| `rotate-key` | `rk` | Fait pivoter les clés de chiffrement pour les données chiffrées. | `--old-version <OLD_V>` <br> `--new-version <NEW_V>` <br> `-k, --key-directory <DIR>` <br> `[--file <FILE> | --directory <DIR>]` <br> `[--passphrase <PASSPHRASE>]` |
| `sign` | | Crée une signature détachée pour un fichier. | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-k, --key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[--passphrase <PASSPHRASE>]` |
| `verify` | | Vérifie une signature détachée pour un fichier. | `-i, --input-file <INPUT>` <br> `-s, --signature-file <SIG>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>` |

Une liste complète des commandes et de leurs arguments peut être consultée en exécutant `ironcrypt --help`. Pour obtenir de l'aide sur une commande spécifique, exécutez `ironcrypt <commande> --help`.

#### `generate`
Génère une nouvelle paire de clés RSA (privée et publique).

**Utilisation :**
```sh
ironcrypt generate --version <VERSION> [--directory <DIR>] [--key-size <SIZE>] [--passphrase <PASSPHRASE>]
```

**Exemple :**
```sh
# Générer une nouvelle clé v2 avec une taille de 4096 bits dans le répertoire "my_keys"
ironcrypt generate -v v2 -d my_keys -s 4096

# Générer une nouvelle clé v3 protégée par une phrase de passe
ironcrypt generate -v v3 -d my_keys --passphrase "une-phrase-tres-secrete"
```

#### `encrypt`
Hache et chiffre un mot de passe.

**Utilisation :**
```sh
ironcrypt encrypt --password <PASSWORD> --public-key-directory <DIR> --key-version <VERSION>
```

**Exemple :**
```sh
# Chiffrer un mot de passe en utilisant la clé publique v1
ironcrypt encrypt -w "Mon$MotDePasseF0rt" -d keys -v v1
```

#### `decrypt`
Déchiffre et vérifie un mot de passe.

**Utilisation :**
```sh
ironcrypt decrypt --password <PASSWORD> --private-key-directory <DIR> --file <FILE> [--passphrase <PASSPHRASE>]
```

**Exemple :**
```sh
# Vérifier un mot de passe en utilisant la clé privée v1 et les données chiffrées d'un fichier
ironcrypt decrypt -w "Mon$MotDePasseF0rt" -k keys -f encrypted_data.json

# Vérifier en utilisant une clé protégée par une phrase de passe
ironcrypt decrypt -w "Mon$MotDePasseF0rt" -k my_keys -f encrypted_data_v3.json --passphrase "une-phrase-tres-secrete"
```

#### `encrypt-file`
Chiffre un seul fichier.

**Utilisation :**
```sh
ironcrypt encrypt-file -i <INPUT> -o <OUTPUT> -d <KEY_DIR> -v <VERSION>... [-w <PASSWORD>]
```

**Exemple :**
```sh
# Chiffrer un fichier pour un seul utilisateur (v1)
ironcrypt encrypt-file -i mon_document.pdf -o mon_document.enc -d keys -v v1

# Chiffrer un fichier pour plusieurs utilisateurs (v1 et v2)
ironcrypt encrypt-file -i mon_document.pdf -o mon_document.multirecipient.enc -d keys -v v1 -v v2
```

#### `decrypt-file`
Déchiffre un seul fichier.

**Utilisation :**
```sh
ironcrypt decrypt-file -i <INPUT> -o <OUTPUT> -k <KEY_DIR> -v <VERSION> [-w <PASSWORD>] [--passphrase <PASSPHRASE>]
```

**Exemple :**
```sh
# Déchiffrer un fichier avec la clé privée v1
ironcrypt decrypt-file -i mon_document.enc -o mon_document.pdf -k keys -v v1

# Déchiffrer un fichier en utilisant une clé protégée par une phrase de passe
ironcrypt decrypt-file -i mon_secret.enc -o mon_secret.zip -k my_keys -v v3 -w "CoucheDeS3curiteSupplementaire" --passphrase "une-phrase-tres-secrete"
```

#### `encrypt-dir`
Chiffre un répertoire entier en l'archivant d'abord dans un `.tar.gz`.

**Utilisation :**
```sh
ironcrypt encrypt-dir -i <INPUT_DIR> -o <OUTPUT_FILE> -d <KEY_DIR> -v <VERSION>... [-w <PASSWORD>]
```

**Exemple :**
```sh
# Chiffrer le répertoire "mon_projet" pour plusieurs utilisateurs
ironcrypt encrypt-dir -i ./mon_projet -o mon_projet.enc -d keys -v v1 -v v2
```

#### `decrypt-dir`
Déchiffre et extrait un répertoire.

**Utilisation :**
```sh
ironcrypt decrypt-dir -i <INPUT_FILE> -o <OUTPUT_DIR> -k <KEY_DIR> -v <VERSION> [-w <PASSWORD>] [--passphrase <PASSPHRASE>]
```

**Exemple :**
```sh
# Déchiffrer le fichier "mon_projet.enc" dans le répertoire "projet_dechiffre"
ironcrypt decrypt-dir -i mon_projet.enc -o ./projet_dechiffre -k keys -v v1
```

#### `rotate-key`
Fait pivoter les clés de chiffrement pour un fichier ou un répertoire de fichiers.

**Utilisation :**
```sh
ironcrypt rotate-key --old-version <OLD_V> --new-version <NEW_V> --key-directory <DIR> [--file <FILE> | --directory <DIR>] [--passphrase <PASSPHRASE>]
```

**Exemple :**
```sh
# Faire pivoter les clés de v1 à v2 pour un seul fichier
ironcrypt rotate-key --old-version v1 --new-version v2 -k keys --file mon_document.enc
```

#### `sign`
Crée une signature détachée pour un fichier. Ceci peut être utilisé pour prouver l'authenticité et l'intégrité du fichier.

**Utilisation :**
```sh
ironcrypt sign --input-file <INPUT> --output-file <OUTPUT> --key-directory <DIR> --key-version <VERSION> [--passphrase <PASSPHRASE>]
```

**Exemple :**
```sh
# Signer un document avec une clé privée v1
ironcrypt sign -i mon_document.pdf -o mon_document.sig -k keys -v v1

# Signer un fichier avec une clé ECC protégée par phrase de passe
ironcrypt sign -i archive.zip -o archive.sig -k ecc_keys -v v1_ecc --passphrase "ma-phrase-secrete"
```

#### `verify`
Vérifie une signature détachée par rapport à un fichier. Ceci confirme que le fichier n'a pas été altéré depuis qu'il a été signé par le détenteur de la clé privée correspondante.

**Utilisation :**
```sh
ironcrypt verify --input-file <INPUT> --signature-file <SIGNATURE> --public-key-directory <DIR> --key-version <VERSION>
```

**Exemple :**
```sh
# Vérifier la signature pour mon_document.pdf en utilisant la clé publique v1
ironcrypt verify -i mon_document.pdf -s mon_document.sig -d keys -v v1
```

### En tant que bibliothèque (Crate)

Vous pouvez également utiliser `ironcrypt` comme bibliothèque dans vos projets Rust. Ajoutez-le à votre `Cargo.toml` :
```toml
[dependencies]
ironcrypt = "0.1.2" # Remplacez par la version souhaitée de crates.io
```

Des copies exécutables sont dans [`examples/`](examples/) (`cargo run --example password`, `cargo run --example stream_aes`).

#### Chiffrer et vérifier un mot de passe
```rust
use ironcrypt::{IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
use std::collections::HashMap;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Utiliser un répertoire temporaire pour les clés afin de garder les tests isolés.
    let temp_dir = tempfile::tempdir()?;
    let key_dir = temp_dir.path().to_str().unwrap();

    // 2. Configurer IronCrypt pour utiliser le répertoire temporaire.
    let mut config = IronCryptConfig::default();
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);

    // 3. Initialiser IronCrypt.
    let crypt = IronCrypt::new(config, DataType::Generic).await?;

    // 4. Chiffrer un mot de passe.
    let password = "MonMotDePasseSecurise123!";
    let encrypted_json = crypt.encrypt_password(password)?;
    println!("Mot de passe chiffré : {}", encrypted_json);

    // 5. Vérifier le mot de passe.
    let is_valid = crypt.verify_password(&encrypted_json, password)?;
    assert!(is_valid);
    println!("Vérification du mot de passe réussie !");

    Ok(())
}
```

#### Chiffrer et déchiffrer un fichier (en flux)
```rust
use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    decrypt_stream, encrypt_stream, generate_rsa_keys,
    keys::{PrivateKey, PublicKey},
    Argon2Config, PasswordCriteria,
};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_rsa_keys(2048)?;
    let public_key = PublicKey::Rsa(pk);
    let private_key = PrivateKey::Rsa(sk);

    let original_data = "Ceci est un message secret qui sera chiffré en flux.";
    let mut source = Cursor::new(original_data.as_bytes());
    let mut encrypted_dest = Cursor::new(Vec::new());
    let mut password = String::new();

    encrypt_stream(
        &mut source,
        &mut encrypted_dest,
        &mut password,
        [(&public_key, "v1")],
        None, // signature absente → streaming AES réel
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    encrypted_dest.set_position(0);
    let mut decrypted_dest = Cursor::new(Vec::new());
    decrypt_stream(
        &mut encrypted_dest,
        &mut decrypted_dest,
        &private_key,
        "v1",
        "",
        None,
    )?;

    assert_eq!(original_data, String::from_utf8(decrypted_dest.into_inner())?);
    Ok(())
}
```

### Démon de chiffrement transparent

Pour une intégration transparente avec des applications écrites dans n'importe quel langage, IronCrypt fournit un démon qui expose une API HTTP simple et performante pour le chiffrement et le déchiffrement. Cela vous permet d'exécuter IronCrypt comme un service d'arrière-plan et de faire communiquer vos autres applications avec lui localement, sans avoir besoin d'intégrer directement la bibliothèque Rust.

#### Configuration du démon

Le démon `ironcryptd` lit un TOML **plat** (champs au premier niveau), voir `ironcrypt.toml.example`.

**Exemple minimal `ironcrypt.toml` :**
```toml
standard = "Nist"
buffer_size = 8192
rsa_key_size = 2048
argon2_memory_cost = 65536
argon2_time_cost = 3
argon2_parallelism = 1

[password_criteria]
min_length = 12
```

#### Démarrage du démon

```sh
ironcryptd \
  --config ironcrypt.toml \
  --key-directory keys \
  --key-version v1 \
  --api-keys-file keys.json \
  --host 127.0.0.1 \
  --port 3000
```

#### Authentification du démon

**1. Générer une clé API**

```sh
ironcrypt generate-api-key
```

Vous obtenez :
* **Clé API secrète** (base64) — à envoyer dans `Authorization: Bearer …`
* **Hash** (hex SHA-512) — à mettre dans `keys.json` sous `keyHash`

**2. Fichier `keys.json` (camelCase)**

```json
[
  {
    "description": "Service backup (écriture seule)",
    "keyHash": "HASH_HEX_DE_GENERATE_API_KEY",
    "permissions": ["write"]
  },
  {
    "description": "Service lecture/écriture",
    "keyHash": "AUTRE_HASH_HEX",
    "permissions": ["write", "read"]
  },
  {
    "description": "Accès secrets AWS uniquement",
    "keyHash": "ENCORE_UN_HASH",
    "permissions": ["read", "write"],
    "allowedServices": ["aws"]
  }
]
```

Permissions valides : `write`, `read`, `delete`, `update`, `full`.

**3. Requêtes authentifiées**

```sh
export API_KEY='CLE_API_SECRETE_BASE64'

# Chiffrer → POST /write
echo "mes données secrètes" | curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @- \
  http://127.0.0.1:3000/write > encrypted.bin

# Déchiffrer → POST /read
curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @encrypted.bin \
  http://127.0.0.1:3000/read

# Avec mot de passe Argon2 optionnel
echo "secret" | curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --header "X-Password: Str0ngP@ssw0rd42!" \
  --data-binary @- \
  http://127.0.0.1:3000/write > encrypted_with_pass.bin
```

Erreurs typiques : `401` (clé absente/invalide), `403` (permission), `429` (rate limit), `400` (crypto / mauvais mot de passe).

#### Points de terminaison de l'API

| Méthode | Chemin | Permission | Rôle |
| --- | --- | --- | --- |
| `POST` | `/write` | `write` | Chiffre le corps de la requête |
| `POST` | `/read` | `read` | Déchiffre le corps de la requête |
| `GET` | `/service/:name/secret/:key` | `read` | Lit un secret cloud |
| `POST` | `/service/:name/secret/:key` | `write` | Écrit un secret cloud |

CORS : désactivé par défaut ; whitelist via `--cors-origins https://app.example.com`.

### Haute disponibilité

Le démon `ironcryptd` est conçu pour être sans état, ce qui signifie qu'il ne stocke aucune donnée de session ou spécifique à une requête entre les requêtes. Cette architecture le rend horizontalement scalable et hautement disponible. Vous pouvez exécuter plusieurs instances du démon derrière un répartiteur de charge pour distribuer le trafic et assurer la continuité du service même si l'une des instances tombe en panne.

**Exigences clés pour une configuration à haute disponibilité :**

1.  **Configuration partagée :** Toutes les instances `ironcryptd` doivent être démarrées avec la même configuration. La meilleure façon d'y parvenir est d'utiliser un fichier de configuration centralisé `ironcrypt.toml` pour toutes les instances.
2.  **Stockage de clés partagé :** Toutes les instances doivent avoir accès au même ensemble de clés de chiffrement. Cela peut être réalisé en :
    *   Plaçant le répertoire des clés sur un système de fichiers réseau partagé (par exemple, NFS, GlusterFS).
    *   Utilisant un outil de gestion de configuration (par exemple, Ansible, Puppet) pour déployer les mêmes fichiers de clés sur chaque nœud.
3.  **Journalisation centralisée :** Pour surveiller et auditer le cluster, les journaux de toutes les instances (journaux standard et d'audit) doivent être transférés vers un système de journalisation centralisé (par exemple, la suite ELK, Splunk, Graylog).

**Exemple : Répartition de charge avec Nginx**

Voici un exemple de configuration Nginx qui montre comment répartir la charge du trafic entre deux instances `ironcryptd` s'exécutant sur `localhost` aux ports 3000 et 3001.

```nginx
# /etc/nginx/nginx.conf

http {
    # Définir un groupe de serveurs en amont
    upstream ironcryptd_cluster {
        # Utiliser un algorithme de répartition de charge, par exemple, round-robin (par défaut) ou least_conn
        # least_conn;

        server 127.0.0.1:3000;
        server 127.0.0.1:3001;
    }

    server {
        listen 80;

        location / {
            # Transférer les requêtes au cluster en amont
            proxy_pass http://ironcryptd_cluster;

            # Définir les en-têtes pour transmettre les informations du client au démon
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

Avec cette configuration, Nginx écoutera sur le port 80 et distribuera les requêtes entrantes (`/write`, `/read`, …) entre les deux instances du démon, offrant à la fois une répartition de charge et une redondance.

---

## Exemples d'intégration avec une base de données

Voici quelques exemples d'utilisation de `ironcrypt` avec des frameworks web populaires et une base de données PostgreSQL. Ces exemples utilisent la crate `sqlx` pour l'interaction avec la base de données.

### Exemple avec Actix-web

Cet exemple montre comment créer un service web simple avec `actix-web` qui peut enregistrer et connecter des utilisateurs.

**Dépendances :**
```toml
[dependencies]
ironcrypt = "0.1.2"
actix-web = "4"
sqlx = { version = "0.7", features = ["runtime-async-std-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

**Code :**
```rust,ignore
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use ironcrypt::{IronCrypt, IronCryptConfig, DataType};
use serde::Deserialize;

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

async fn register(user: web::Json<User>, pool: web::Data<PgPool>, crypt: web::Data<IronCrypt>) -> impl Responder {
    let encrypted_password = match crypt.encrypt_password(&user.password) {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let result = sqlx::query("INSERT INTO users (username, password) VALUES ($1, $2)")
        .bind(&user.username)
        .bind(&encrypted_password)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("Utilisateur créé"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn login(user: web::Json<User>, pool: web::Data<PgPool>, crypt: web::Data<IronCrypt>) -> impl Responder {
    let result: Result<(String,), sqlx::Error> = sqlx::query_as("SELECT password FROM users WHERE username = $1")
        .bind(&user.username)
        .fetch_one(pool.get_ref())
        .await;

    let stored_password = match result {
        Ok((p,)) => p,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    match crypt.verify_password(&stored_password, &user.password) {
        Ok(true) => HttpResponse::Ok().body("Connexion réussie"),
        Ok(false) => HttpResponse::Unauthorized().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_url = "postgres://user:password@localhost/database";
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Échec de la création du pool.");

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(config, DataType::Generic).await.expect("Échec de l'initialisation d'IronCrypt");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )"
    )
    .execute(&pool)
    .await
    .expect("Échec de la création de la table.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(crypt.clone()))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Exemple avec Rocket

Cet exemple montre comment obtenir la même fonctionnalité en utilisant le framework `rocket`.

**Dépendances :**
```toml
[dependencies]
ironcrypt = "0.1.2"
rocket = { version = "0.5.0", features = ["json"] }
sqlx = { version = "0.7", features = ["runtime-tokio-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
```

**Code :**
```rust,ignore
#[macro_use] extern crate rocket;

use rocket::serde::json::Json;
use rocket::State;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use ironcrypt::{IronCrypt, IronCryptConfig, DataType};
use serde::Deserialize;

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

#[post("/register", data = "<user>")]
async fn register(user: Json<User>, pool: &State<PgPool>, crypt: &State<IronCrypt>) -> Result<String, rocket::response::status::Custom<String>> {
    let encrypted_password = crypt.encrypt_password(&user.password).map_err(|e| rocket::response::status::Custom(rocket::http::Status::InternalServerError, e.to_string()))?;

    sqlx::query("INSERT INTO users (username, password) VALUES ($1, $2)")
        .bind(&user.username)
        .bind(&encrypted_password)
        .execute(&**pool)
        .await
        .map_err(|e| rocket::response::status::Custom(rocket::http::Status::InternalServerError, e.to_string()))?;

    Ok("Utilisateur créé".to_string())
}

#[post("/login", data = "<user>")]
async fn login(user: Json<User>, pool: &State<PgPool>, crypt: &State<IronCrypt>) -> Result<String, rocket::response::status::Custom<String>> {
    let result: (String,) = sqlx::query_as("SELECT password FROM users WHERE username = $1")
        .bind(&user.username)
        .fetch_one(&**pool)
        .await
        .map_err(|_| rocket::response::status::Custom(rocket::http::Status::Unauthorized, "Utilisateur non trouvé".to_string()))?;

    let stored_password = result.0;

    if crypt.verify_password(&stored_password, &user.password).unwrap_or(false) {
        Ok("Connexion réussie".to_string())
    } else {
        Err(rocket::response::status::Custom(rocket::http::Status::Unauthorized, "Identifiants invalides".to_string()))
    }
}

#[launch]
async fn rocket() -> _ {
    let database_url = "postgres://user:password@localhost/database";
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Échec de la création du pool.");

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(config, DataType::Generic).await.expect("Échec de l'initialisation d'IronCrypt");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )"
    )
    .execute(&pool)
    .await
    .expect("Échec de la création de la table.");

    rocket::build()
        .manage(pool)
        .manage(crypt)
        .mount("/", routes![register, login])
}
```

---

## Configuration

IronCrypt peut être configuré de trois manières, par ordre de priorité :

1.  **Fichier `ironcrypt.toml` :** Créez ce fichier dans le répertoire où vous exécutez la commande.
2.  **Variables d'environnement :** Définissez des variables comme `IRONCRYPT_KEY_DIRECTORY`.
3.  **Arguments de ligne de commande :** Les indicateurs comme `--key-directory` remplacent toutes les autres méthodes.

Pour l'utilisation en bibliothèque, vous pouvez construire une structure `IronCryptConfig` et la passer à `IronCrypt::new`.

### Configuration de l'algorithme cryptographique

Personnalisez les algorithmes via `ironcrypt.toml` (champs plats, voir `ironcrypt.toml.example`).

```toml
# Normes : "Nist" | "Fips140_2" | "Anssi" | "Custom"
standard = "Nist"
rsa_key_size = 2048
buffer_size = 8192
argon2_memory_cost = 65536
argon2_time_cost = 3
argon2_parallelism = 1

[password_criteria]
min_length = 12
```

Mode personnalisé :

```toml
standard = "Custom"
symmetric_algorithm = "ChaCha20Poly1305"  # ou "Aes256Gcm"
asymmetric_algorithm = "Ecc"              # ou "Rsa"
rsa_key_size = 4096                       # ignoré si Ecc
```

`Anssi` force AES-256-GCM + RSA 3072. Pour ECC, utilisez `standard = "Custom"` avec `asymmetric_algorithm = "Ecc"`.

### Configuration de la gestion des secrets

Pour utiliser IronCrypt avec un système de gestion des secrets comme HashiCorp Vault, AWS Secrets Manager ou Azure Key Vault, vous devez activer le "feature flag" correspondant lors de la compilation et le configurer dans votre fichier `ironcrypt.toml`.

Tout d'abord, spécifiez le fournisseur que vous souhaitez utiliser :

```toml
[secrets]
provider = "vault" # ou "aws", "azure"
```

Ensuite, fournissez la configuration spécifique à votre fournisseur choisi.

#### HashiCorp Vault (fonctionnalité `vault`)

```toml
[secrets.vault]
address = "http://127.0.0.1:8200" # Adresse de votre serveur Vault
token = "VOTRE_JETON_VAULT"        # Jeton Vault avec accès au moteur de secrets
mount = "secret"                  # Chemin de montage du moteur de secrets KVv2 (optionnel, par défaut "secret")
```

### Configuration CryptoProvider (wrap / unwrap DEK)

Distinct de `[secrets]` : un `CryptoProvider` enveloppe les clés de données sans exporter
le matériel privé. Activez `aws-kms`, `vault` ou `hsm`, puis configurez **un seul**
provider dans le TOML (`ironcrypt.toml.example`, `PAYMENT_SECURITY.md`).

```toml
[crypto_provider]
provider = "aws-kms"   # ou "vault-transit" | "hsm"

[crypto_provider.aws_kms]
region = "eu-west-1"
default_key_id = "arn:aws:kms:eu-west-1:123456789012:key/…"
```

```toml
[crypto_provider]
provider = "vault-transit"

[crypto_provider.vault_transit]
address = "https://vault.internal:8200"
# token via VAULT_TOKEN de préférence
mount = "transit"
```

```toml
[crypto_provider]
provider = "hsm"

[crypto_provider.hsm]
module_path = "/usr/lib/softhsm/libsofthsm2.so"
token_label = "ironcrypt"
default_key_label = "payment-aes"
# pin via IRONCRYPT_HSM_PIN
```

---

## Sécurité et bonnes pratiques

- **Protégez vos clés privées :** N'exposez jamais vos clés privées. Stockez-les dans un endroit sécurisé et non public. Si possible, chiffrez-les avec une phrase de passe forte et unique en utilisant l'option `--passphrase` lors de la génération.
- **Utilisez des mots de passe forts :** Lorsque vous utilisez la fonction de mot de passe pour le chiffrement de fichiers/répertoires, assurez-vous que le mot de passe est fort.
- **Faites pivoter les clés régulièrement :** Utilisez la commande `rotate-key` pour mettre à jour périodiquement vos clés de chiffrement.
- **Sauvegardez vos clés :** Conservez des sauvegardes sécurisées de vos clés. Si vous perdez une clé privée, vous ne pourrez pas déchiffrer vos données.

---

## Contribution

Les contributions sont les bienvenues ! Si vous souhaitez contribuer, veuillez suivre ces étapes :

1.  **Fork** le dépôt sur GitHub.
2.  **Créez** une nouvelle branche pour votre fonctionnalité ou votre correction de bogue.
3.  **Commitez** vos modifications et poussez-les sur votre fork.
4.  **Soumettez** une pull request avec une description claire de vos modifications.

---

## Licence

*IronCrypt est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.*
