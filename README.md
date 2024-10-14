# IronCrypt

**IronCrypt** est une librairie de cryptage de mots de passe en Rust, conçue pour offrir un niveau de sécurité élevé grâce à une combinaison d'algorithmes de hachage et de chiffrement. Utilisant **Argon2** pour le hachage sécurisé et le chiffrement **RSA** pour une deuxième couche de protection, IronCrypt est idéal pour les applications nécessitant une sécurité accrue, comme les systèmes de gestion des utilisateurs ou les applications financières.Fonctionnalités

## Fonctionnalités

- **Vérification de la robustesse des mots de passe** : Vérifiez si un mot de passe répond à des critères de sécurité (longueur, présence de caractères spéciaux, majuscules, etc.).
- **Hachage et chiffrement des mots de passe** : Hachez les mots de passe avec Argon2, puis chiffrez-les avec RSA pour un stockage sécurisé.
- **Déchiffrement et vérification des mots de passe** : Déchiffrez un hash chiffré et vérifiez si le mot de passe fourni correspond au hash.
- **Gestion des clés RSA** : Génération de paires de clés RSA, et sauvegarde/chargement de clés à partir de fichiers PEM.

## Prérequis

- Rust &gt;= 1.56
- Bibliothèques Rust supplémentaires :
  - `argon2`
  - `rsa`
  - `base64`
  - `sha2`
  - `rand`
  - `serde` pour la sérialisation des critères de mot de passe
  - `clap` pour la gestion de la ligne de commande
  - `thiserror` pour une gestion idiomatique des erreurs
  - `indicatif` pour les spinners et les barres de progression en CLI

Assurez-vous que votre fichier `Cargo.toml` inclut les dépendances nécessaires :

```toml
[dependencies]
serde = { version = "1.0.210", features = ["derive"] }
argon2 = "0.5.3"
base64 = "0.22.1"
rsa = { version = "0.9.6", features = ["pem"] }
serde_json = "1.0"
sha2 = "0.10.6"
rand = "0.8.5"
rand_chacha = "0.3.1"
rand_core = "0.6.4"
clap = { version = "4.5.20", features = ["derive"] }
thiserror = "1.0.64"
indicatif = "0.17.2"
```

## Installation

Ajoutez `IronCrypt` à votre projet en utilisant `cargo` :

```bash
cargo add ironcrypt
```

Ou, ajoutez manuellement cette ligne dans votre fichier `Cargo.toml` :

```toml
[dependencies]
ironcrypt = "0.1.0"
```

## Utilisation : Génération de paire de clés RSA

### **Utilisation par défaut (sans options)**

Si vous exécutez la commande `generate` sans spécifier d'options, les clés seront générées avec les paramètres par défaut :

- **Chemin de la clé privée** : `private_key.pem`
- **Chemin de la clé publique** : `public_key.pem`
- **Taille de la clé** : `2048` bits

**Commande :**

```bash
cargo run -- generate
```

**Exemple de sortie :**

```bash
Génération des clés RSA en cours...
Génération des clés RSA terminée.
Les clés RSA ont été générées et sauvegardées avec succès.
Clé privée : private_key.pem
Clé publique : public_key.pem
```

Cela générera une paire de clés RSA dans les fichiers suivants par défaut :

- Clé privée : `private_key.pem`
- Clé publique : `public_key.pem`

### Utilisation avec options

Vous pouvez spécifier les chemins de sortie pour la clé privée et la clé publique en utilisant les options `-p` (pour la clé privée) et `-k` (pour la clé publique) et `-s` pour la taille de la clé en bits (par defaut 2048). Cette commande vous permet de renommer vous clés et de choisir la taille de la paire de clés.

- `-- generate` : Générer des clés RSA.
- `-p` : Chemin de sauvegarde pour la clé privée (par défaut `private_key.pem`).
- `-k` : Chemin de sauvegarde pour la clé publique (par défaut `public_key.pem`).
- `-s` : Taille de la clé en bits (par défaut `2048`).

1. Spécifier le chemin de la clé privée avec `-p`.

Voici comment procéder avec Cargo :

```bash
cargo run -- generate -p path/to/ma_cle_privee.pem
```

**Exemple de sortie :**

```bash
Génération des clés RSA en cours...
Génération des clés RSA terminée.
Les clés RSA ont été générées et sauvegardées avec succès.
Clé privée : chemin/vers/ma_cle_privee.pem
Clé publique : public_key.pem
```

#### **2. Spécifier le chemin de la clé publique avec** `-k`

**Commande :**

```bash
cargo run -- generate -k chemin/vers/ma_cle_publique.pem
```

**Exemple de sortie :**

```bash
Génération des clés RSA en cours...
Génération des clés RSA terminée.
Les clés RSA ont été générées et sauvegardées avec succès.
Clé privée : private_key.pem
Clé publique : chemin/vers/ma_cle_publique.pem
```

#### **3. Spécifier la taille de la clé avec** `-s` sans chemin

**Commande :**

```bash
cargo run -- generate -s 4096
```

**Exemple de sortie :**

```bash
Génération des clés RSA en cours...
Génération des clés RSA terminée.
Les clés RSA ont été générées et sauvegardées avec succès.
Clé privée : private_key.pem
Clé publique : public_key.pem
```

*Remarque : La génération d'une clé de 4096 bits peut prendre plus de temps que pour une clé de 2048 bits.*

#### **4. Combiner plusieurs options**

Vous pouvez combiner les options pour personnaliser à la fois les chemins et la taille de la clé.

**Commande :**

```bash
cargo run -- generate -p ma_cle_privee.pem -k ma_cle_publique.pem -s 3072
```

**Exemple de sortie :**

```bash
Génération des clés RSA en cours...
Génération des clés RSA terminée.
Les clés RSA ont été générées et sauvegardées avec succès.
Clé privée : ma_cle_privee.pem
Clé publique : ma_cle_publique.pem
```

### **Affichage de l'aide et des options disponibles**

Pour voir toutes les options disponibles pour la commande `generate`, vous pouvez utiliser l'option `--help`.

**Commande :**\
ru

```bash
cargo run -- generate --help
```

**Exemple de sortie :**

```vbnet
Génère une paire de clés RSA

Usage: ironcrypt-cli generate [OPTIONS]

Options:
  -p, --private-key-path <PRIVATE_KEY_PATH>
          Chemin de sauvegarde pour la clé privée [default: private_key.pem]
  -k, --public-key-path <PUBLIC_KEY_PATH>
          Chemin de sauvegarde pour la clé publique [default: public_key.pem]
  -s, --key-size <KEY_SIZE>
          Taille de la clé (en bits) [default: 2048]
  -h, --help
          Print help
```

### **Conseils**

- **Ordre des options** : L'ordre des options n'a pas d'importance. Vous pouvez écrire les options dans l'ordre qui vous convient.

- **Valeurs par défaut** : Si vous n'indiquez pas une option, sa valeur par défaut sera utilisée.

- **Combinaison des options courtes** : Vous pouvez combiner les options courtes si elles n'attendent pas de valeur. Par exemple, si vous aviez des options comme `-v` pour verbose et `-f` pour force, vous pourriez écrire `-vf`. Cependant, dans ce cas, chaque option attend une valeur, donc elles doivent être séparées.

La commande `generate` vous permet de générer des paires de clés RSA avec des paramètres personnalisés selon vos besoins. Utilisez les options `-p`, `-k` et `-s` pour spécifier respectivement le chemin de la clé privée, le chemin de la clé publique et la taille de la clé en bits.

N'hésitez pas à utiliser l'option `--help` pour obtenir des informations détaillées sur les commandes et options disponibles.

**4. Fonctionnalités futures**

L'outil `ironcrypt` est conçu pour être extensible. De futures versions pourraient inclure des fonctionnalités supplémentaires pour le hachage sécurisé des mots de passe, le chiffrement de données sensibles, etc.

### Remarques

- Assurez-vous que le dossier dans lequel vous générez vos clés a les permissions suffisantes pour écrire les fichiers.
- Les fichiers PEM générés peuvent être utilisés dans des projets nécessitant des clés RSA pour le chiffrement ou la signature numérique.

**3. Hacher et chiffrer un mot de passe**

Pour hacher et chiffrer un mot de passe, vous pouvez utiliser la sous-commande `encrypt`. :

```bash
cargo run -- encrypt -w "VotreMotDeP@sse1" -k public_key.pem
```

- `encrypt` : Sous-commande pour hacher et chiffrer un mot de passe.
- `-w` : Le mot de passe à hacher et chiffrer.
- `-k` : Chemin vers la clé publique pour le chiffrement (par défaut `public_key.pem`).

Résultat : Mot de passe haché et chiffré

```bash
 {
   "ciphertext":"P2A4hrhIg9E9o+sChKPK3zrwo/49Cutpb0FoxmZSfzs6YmG0wkiToEVy9vKBaxMcYzM7sAWso2977vzgrIReTZfHPMBnsi2yVR6xh7RUIeoNJvx346Ya8ws/GI+HjxTVOXZh2odHPFS7mHUpWASOb7U=",
   "encrypted_symmetric_key":"j/MMqYqHNEh8+Go1HsjlLWfQlg9/94meH6sNpPcYQt1ZEwA5BoGVaJ1hcOt0A6Sv54dwlG4Yr8WrHUkPR04raw0jFhSNkk7iO5fZJwuA8gvYRLhnAxyW0X/vRJzwUaee4TuDt9r4Zr3DppAl12lW03SkOkuwFokrz8AGg6G1LqnUz0CwgbfmOauM2+O70VDA4cTCb6mH7LmslplS6pUuY5U3M8inWag6Z907Q6yV4HNYdHxAuYHfLK/XxOiHCsH8H8EfWbVt7BU31PC8o2L+MkfTyf6f5t4wvQtAx2BWvMt7zE9JWYVs1aTxsJC4urO4oeer/XddZLym7t6xsNTNoQ==",
   "nonce":"W7q6TjwB4x0ysavW"
}
```

### **Explication des champs :**

1. `encrypted_symmetric_key` :

   - Il s'agit de la **clé symétrique** utilisée pour chiffrer le hash du mot de passe, **elle-même chiffrée** avec la **clé publique RSA**.
   - Cette clé est encodée en **base64**.
   - Seule la **clé privée RSA** correspondante peut déchiffrer cette clé symétrique.

2. `nonce` :

   - C'est le **nonce** (nombre aléatoire) utilisé lors du chiffrement avec AES-GCM.
   - Il assure que chaque chiffrement est unique, même si le même message est chiffré plusieurs fois.
   - Encodé en **base64**.

3. `ciphertext` :

   - Il s'agit du **hash du mot de passe chiffré** avec AES-256-GCM en utilisant la clé symétrique générée.
   - Encodé en **base64**.

## **Utilisation de la commande** `decrypt` **:**

### **1. Utiliser les données chiffrées sous forme de chaîne :**

```bash
cargo run -- decrypt -w "VotreMotDeP@sse1" -k private_key.pem -d '{"ciphertext":"...","encrypted_symmetric_key":"...","nonce":"..."}'
```

---

Remplacez `...` par les valeurs réelles des données chiffrées.

### **2. Utiliser un fichier contenant les données chiffrées :**

- Enregistrez les données chiffrées dans un fichier, par exemple `encrypted_data.json`.

- Exécutez la commande :

  ```bash
  cargo run -- decrypt -w "VotreMotDeP@sse1" -k private_key.pem -f encrypted_data.json
  ```

### 1. Importation des Fonctions

Pour utiliser les principales fonctionnalités de la bibliothèque, importez-les dans votre code :

```rust
use ironcrypt::{
    is_password_strong, PasswordCriteria, hash_and_encrypt_password_with_criteria,
    decrypt_and_verify_password, generate_rsa_keys, save_keys_to_files, load_rsa_keys,
};
```

### 2. Définir des Critères de Mot de Passe

Créez une configuration pour les mots de passe en utilisant la structure `PasswordCriteria` :

```rust
let criteria = PasswordCriteria {
    min_length: 12,
    max_length: Some(128),
    require_uppercase: true,
    require_numbers: true,
    require_special_chars: true,
    disallowed_patterns: vec!["password".to_string(), "1234".to_string()],
    digits: Some(0),
    lowercase: Some(0),
    special_chars: Some(0),
    uppercase: Some(0),
};
```

### 3. Générer des Clés RSA et les Sauvegarder

Générez une paire de clés RSA (privée et publique) :

```rust
use ironcrypt::IronCryptError;

let (private_key, public_key) = generate_rsa_keys(2048)
    .expect("Erreur lors de la génération des clés RSA");
save_keys_to_files(&private_key, &public_key, "private_key.pem", "public_key.pem")
    .expect("Erreur lors de la sauvegarde des clés");
```

**Remarque :** `generate_rsa_keys` prend maintenant un argument pour la taille de la clé (en bits) et retourne un `Result`, il faut donc gérer les erreurs.

### 4. Hacher et Chiffrer un Mot de Passe

Hachez et chiffrez un mot de passe en utilisant les critères définis et la clé publique :

```rust
let password = "StrongP@ssw0rd";
let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria)
    .expect("Erreur lors du hachage et du chiffrement du mot de passe");
```

### 5. Déchiffrer et Vérifier un Mot de Passe

Déchiffrez le hash et vérifiez si un mot de passe correspond :

```rust
let result = decrypt_and_verify_password(&encrypted_hash, password, &private_key);
match result {
    Ok(_) => println!("Le mot de passe est valide."),
    Err(e) => println!("Erreur lors de la vérification du mot de passe : {:?}", e),
}
```

### 6. Charger les Clés RSA depuis des Fichiers

Si vous avez déjà sauvegardé vos clés RSA, vous pouvez les recharger facilement :

```rust
let (private_key, public_key) = load_rsa_keys("private_key.pem", "public_key.pem")
    .expect("Erreur lors du chargement des clés RSA");
```

## Exemples Complets

Voici un exemple complet de la bibliothèque en action :

```rust
use ironcrypt::{
    is_password_strong, PasswordCriteria, hash_and_encrypt_password_with_criteria,
    decrypt_and_verify_password, generate_rsa_keys, save_keys_to_files, load_rsa_keys, IronCryptError,
};

fn main() -> Result<(), IronCryptError> {
    // Définir les critères de mot de passe
    let criteria = PasswordCriteria {
        min_length: 8,
        max_length: Some(128),
        require_uppercase: true,
        require_numbers: true,
        require_special_chars: true,
        disallowed_patterns: vec!["password".to_string(), "1234".to_string()],
        digits: Some(1),
        lowercase: Some(1),
        special_chars: Some(1),
        uppercase: Some(1),
    };

    // Générer les clés RSA et les sauvegarder dans des fichiers
    let (private_key, public_key) = generate_rsa_keys(2048)?;
    save_keys_to_files(&private_key, &public_key, "private_key.pem", "public_key.pem")?;

    // Hachage et chiffrement du mot de passe
    let password = "StrongP@ssw0rd";
    let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria)?;

    // Déchiffrement et vérification du mot de passe
    match decrypt_and_verify_password(&encrypted_hash, password, &private_key) {
        Ok(_) => println!("Le mot de passe est valide."),
        Err(e) => println!("Erreur lors de la vérification du mot de passe : {:?}", e),
    }

    Ok(())
}

// Résultat : Le mot de passe haché est : $argon2id$v=19$m=19456,t=2,p=1$2hF8WmxsmuCDaytOywqdlg$D9wxeTvYO4xbi4DZW9fU2mbpwMF6X4xVgnQpK0+nOQo
```

### Exemple de Vérification de Mot de Passe

```rust
use ironcrypt::{hash_password, is_password_strong, PasswordCriteria};

fn main() {
    // Définition des critères de robustesse du mot de passe.
    let criteria = PasswordCriteria {
        min_length: 8,
        max_length: Some(20),
        require_uppercase: true,
        require_numbers: true,
        require_special_chars: true,
        disallowed_patterns: vec!["password".to_string(), "1234".to_string()],
        special_chars: Some(1),
        uppercase: Some(1),
        lowercase: Some(1),
        digits: Some(1),
    };

    // Le mot de passe à hacher.
    let password = "StrongP@ssw0rd";

    // Vérification si le mot de passe est robuste selon les critères définis.
    match is_password_strong(password, &criteria) {
        Ok(_) => {
            // Si le mot de passe est valide, on peut le hacher.
            match hash_password(password) {
                Ok(hashed_password) => {
                    println!("Le mot de passe haché est : {}", hashed_password);
                }
                Err(e) => {
                    println!("Erreur lors du hachage du mot de passe : {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Le mot de passe ne respecte pas les critères de robustesse : {}", e);
        }
    }
}
```

**Résultat :**

```bash
Le mot de passe haché est : $argon2id$v=19$m=19456,t=2,p=1$...
```

La librairie **IronCrypt** présente plusieurs points forts qui en font un outil puissant pour la gestion sécurisée des mots de passe et des données sensibles dans vos applications. Voici les principaux avantages et caractéristiques de cette librairie :

---

## **Sécurité avancée**

### **a. Utilisation d'algorithmes cryptographiques modernes**

- **Hachage avec argon2** : IronCrypt utilise l'algorithme de hachage **Argon2**, considéré comme l'un des plus sécurisés et performants pour le stockage des mots de passe. Il est résistant aux attaques par force brute et par dictionnaire, offrant une protection robuste contre les tentatives de compromission.

- **Chiffrement symétrique avec AES-256-GCM** : Pour le chiffrement des données, IronCrypt utilise l'algorithme **AES-256-GCM**, qui offre à la fois confidentialité et intégrité des données grâce à son mode d'opération authentifié.

- **Chiffrement asymétrique avec RSA** : La librairie implémente le chiffrement asymétrique **RSA** pour sécuriser l'échange et le stockage des clés symétriques. Cela permet une gestion sécurisée des clés dans des environnements distribués.

### **b. Chiffrement hybride**

- **Combinaison des chiffrements symétrique et asymétrique** : En adoptant une approche de chiffrement hybride, IronCrypt bénéficie des avantages des deux méthodes. Le chiffrement symétrique offre des performances élevées pour le traitement de grandes quantités de données, tandis que le chiffrement asymétrique garantit une distribution sécurisée des clés.

## **2. Gestion sécurisée des mots de passe**

### **a. Vérification de la robustesse des mots de passe**

- **Critères personnalisables** : La librairie permet de définir des critères de robustesse pour les mots de passe, tels que la longueur minimale, la présence de majuscules, de chiffres, de caractères spéciaux, etc.

- **Fonction de validation intégrée** : Avant le hachage et le chiffrement, IronCrypt vérifie que le mot de passe respecte les critères définis, renforçant ainsi la sécurité dès la création du mot de passe.

### **b. Stockage sécurisé des mots de passe**

- **Hachage et chiffrement** : Les mots de passe sont d'abord hachés avec Argon2, puis le hash est chiffré avec AES-256-GCM. La clé symétrique utilisée est elle-même chiffrée avec RSA, assurant une protection multi-niveaux.

- **Protection contre les fuites** : En chiffrant le hash du mot de passe, la librairie réduit le risque que des attaquants puissent exploiter des hash compromis pour tenter de récupérer les mots de passe en clair.

## **3. Intégrité et confidentialité des données**

### **a. Authentification intégrée**

- **Mode GCM (Galois/Counter Mode)** : L'utilisation d'AES en mode GCM assure non seulement le chiffrement des données, mais aussi leur intégrité. Toute modification non autorisée des données chiffrées est détectée lors du déchiffrement.

### **b. Gestion sécurisée des clés**

- **Clé Privée RSA Protégée** : La clé privée utilisée pour déchiffrer la clé symétrique est maintenue en sécurité, garantissant que seules les parties autorisées peuvent accéder aux données sensibles.

## **4. Facilité d'intégration et d'utilisation**

### **a. API simples et efficaces**

- **Fonctions Claires** : IronCrypt fournit des fonctions bien définies pour le hachage, le chiffrement, le déchiffrement et la vérification des mots de passe, facilitant leur intégration dans vos applications.

- **Gestion des erreurs** : La librairie offre une gestion des erreurs exhaustive, avec des messages explicites qui aident au débogage tout en évitant de divulguer des informations sensibles.

### **b. Compatibilité avec les standards**

- **Utilisation de Formats Reconnaissables** : Les clés et les données sont manipulées en utilisant des formats standard tels que PEM pour les clés RSA et JSON pour les données sérialisées, facilitant l'interopérabilité avec d'autres systèmes et outils.

## **5. Performance et scalabilité**

### **a. Optimisation des opérations cryptographiques**

- **Chiffrement Symétrique pour les Données** : L'utilisation d'AES pour le chiffrement des données assure des performances élevées, ce qui est crucial pour les applications à grande échelle.

- **Chiffrement Asymétrique Limité aux Clés** : En limitant l'utilisation du chiffrement RSA au chiffrement des clés symétriques, IronCrypt minimise l'impact sur les performances tout en maintenant un haut niveau de sécurité.

## **6. Bonnes pratiques de sécurité intégrées**

### **a. Salage des hashs**

- **Génération de Sels Aléatoires** : Pour chaque mot de passe haché, un sel unique est généré, renforçant la résistance aux attaques pré-calculées comme les tables rainbow.

### **b. Mise à jour et maintenance facilitées**

- **Utilisation de Crates Rust Modernes** : En s'appuyant sur des crates Rust maintenues et sécurisées, IronCrypt bénéficie des mises à jour de sécurité et des améliorations de la communauté.

---

## **Conclusion**

La librairie **IronCrypt** se distingue par son approche robuste et sécurisée de la gestion des mots de passe et du chiffrement des données. En combinant des algorithmes cryptographiques modernes avec des pratiques de sécurité éprouvées, elle offre une solution complète pour protéger les informations sensibles dans vos applications.

Que vous développiez une application nécessitant une gestion sécurisée des mots de passe, ou que vous ayez besoin de chiffrer des données confidentielles, IronCrypt fournit les outils nécessaires pour répondre à ces exigences de manière efficace et sécurisée.

## Sécurité et bonnes pratiques

- **Stockage des Clés** : Gardez la clé privée en sécurité et ne la partagez jamais publiquement. La clé publique peut être partagée pour chiffrer des données.
- **Mot de passe robuste** : Encouragez les utilisateurs à choisir des mots de passe longs et complexes pour renforcer la sécurité.
- **Critères personnalisés** : Adaptez `PasswordCriteria` selon les besoins spécifiques de votre application pour renforcer les exigences de mot de passe.
- **Gestion des erreurs** : Assurez-vous de gérer les erreurs retournées par les fonctions, notamment celles qui retournent un `Result`.
- **Utilisation de sources d'aléa sécurisées** : Assurez-vous que toutes les fonctions générant des nombres aléatoires utilisent des sources cryptographiquement sécurisées, comme `OsRng`.

## Licence

`IronCrypt` est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une *issue* ou à soumettre une *pull request* pour proposer des améliorations ou des correctifs.