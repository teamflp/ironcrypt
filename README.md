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
cargo run — generate
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

- `—- generate` : Générer des clés RSA.
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

**Commande :**
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

Pour hacher et chiffrer un mot de passe, vous pouvez utiliser la sous-commande `encrypt` :

```bash
cargo run -- encrypt -w "VotreMotDePasse" -k public_key.pem
```

- `encrypt` : Sous-commande pour hacher et chiffrer un mot de passe.
- `-w` : Le mot de passe à hacher et chiffrer.
- `-k` : Chemin vers la clé publique pour le chiffrement (par défaut `public_key.pem`).

**4. Utilisation des alias**

`ironcrypt` supporte des alias pour simplifier les commandes. Par exemple, vous pouvez utiliser `g` pour `generate` et `e`pour `encrypt`.

Exemple :

```bash
cargo run -- g
cargo run -- e -w "VotreMotDePasse"
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
        special_chars: 1,
        uppercase: 1,
        lowercase: 1,
        digits: 1,
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

## Sécurité et Bonnes Pratiques

- **Stockage des Clés** : Gardez la clé privée en sécurité et ne la partagez jamais publiquement. La clé publique peut être partagée pour chiffrer des données.
- **Mot de passe Robuste** : Encouragez les utilisateurs à choisir des mots de passe longs et complexes pour renforcer la sécurité.
- **Critères Personnalisés** : Adaptez `PasswordCriteria` selon les besoins spécifiques de votre application pour renforcer les exigences de mot de passe.
- **Gestion des Erreurs** : Assurez-vous de gérer les erreurs retournées par les fonctions, notamment celles qui retournent un `Result`.
- **Utilisation de Sources d'Aléa Sécurisées** : Assurez-vous que toutes les fonctions générant des nombres aléatoires utilisent des sources cryptographiquement sécurisées, comme `OsRng`.

## Licence

`IronCrypt` est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une *issue* ou à soumettre une *pull request* pour proposer des améliorations ou des correctifs.