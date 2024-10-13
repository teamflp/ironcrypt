# IronCrypt

**IronCrypt** est une librairie de cryptage de mots de passe en Rust, conçue pour offrir un niveau de sécurité élevé grâce à une combinaison d'algorithmes de hachage et de chiffrement. Utilisant **Argon2** pour le hachage sécurisé et le chiffrement **RSA** pour une deuxième couche de protection, IronCrypt est idéal pour les applications nécessitant une sécurité accrue, comme les systèmes de gestion des utilisateurs ou les applications financières.

## Fonctionnalités

- **Vérification de la robustesse des mots de passe** : Vérifiez si un mot de passe répond à des critères de sécurité (longueur, présence de caractères spéciaux, majuscules, etc.).
- **Hachage et chiffrement des mots de passe** : Hachez les mots de passe avec Argon2, puis chiffrez-les avec RSA pour un stockage sécurisé.
- **Déchiffrement et vérification des mots de passe** : Déchiffrez un hash chiffré et vérifiez si le mot de passe fourni correspond au hash.
- **Gestion des clés RSA** : Génération de paires de clés RSA, et sauvegarde/chargement de clés à partir de fichiers PEM.

## Prérequis

- Rust =&gt; 1.56
- Bibliothèques Rust supplémentaires :
  - `argon2`
  - `rsa`
  - `base64`
  - `sha2`
  - `rand`
  - `serde` pour la sérialisation des critères de mot de passe

Assurez-vous que votre fichier `Cargo.toml` inclut les dépendances nécessaires :

```toml
[dependencies]
argon2 = "0.3"
rsa = "0.9"
base64 = "0.13"
sha2 = "0.10"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
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

## Utilisation

### Avant toute utilisation générer une paire de clés RSA

**1. Générer des clés RSA**

L'outil `ironcrypt` permet de générer une paire de clés RSA (privée et publique). Vous pouvez utiliser l'outil via Cargo ou directement en appelant le binaire.

#### Commande via Cargo

Pour générer des clés RSA, utilisez la commande suivante :

```bash
cargo run -- g
```

Cela générera une paire de clés RSA dans les fichiers suivants par défaut :

- Clé privée : `private_key.pem`
- Clé publique : `public_key.pem`

2. Personnaliser le chemin des clés

Vous pouvez spécifier les chemins de sortie pour la clé privée et la clé publique en utilisant des arguments avec les options `-p` (pour la clé privée) et `-k` (pour la clé publique). Cette commande vous permet de renommer vous clés. 

Voici comment procéder avec Cargo :

```bash
cargo run -- g -p my_private_key.pem -k my_public_key.pem
```

**3. Utilisation des alias**

`ironcrypt` supporte des alias pour simplifier les commandes. Par exemple, au lieu d'utiliser la commande complète pour la génération de clés, vous pouvez utiliser :

```bash
ironcrypt
```

**4. Fonctionnalités futures**

L'outil `ironcrypt` est conçu pour être extensible. De futures versions pourraient inclure des fonctionnalités supplémentaires pour le hachage sécurisé des mots de passe, le chiffrement de données sensibles, etc.

### Remarques

- Assurez-vous que le dossier dans lequel vous générez vos clés a les permissions suffisantes pour écrire les fichiers.
- Les fichiers PEM générés peuvent être utilisés dans des projets nécessitant des clés RSA pour le chiffrement ou la signature numérique.

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
    digits: 0,
    lowercase: 0,
    special_chars: 0,
    uppercase: 0,
};
```

### 3. Générer des Clés RSA et les Sauvegarder

Générez une paire de clés RSA (privée et publique) :

```rust
let (private_key, public_key) = generate_rsa_keys();
save_keys_to_files(&private_key, &public_key, "private_key.pem", "public_key.pem").unwrap();
```

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
    decrypt_and_verify_password, generate_rsa_keys, save_keys_to_files, load_rsa_keys,
};

fn main() {
    // Définir les critères de mot de passe
    let criteria = PasswordCriteria::default();

    // Générer les clés RSA et les sauvegarder dans des fichiers
    let (private_key, public_key) = generate_rsa_keys();
    save_keys_to_files(&private_key, &public_key, "private_key.pem", "public_key.pem")
        .expect("Erreur lors de la sauvegarde des clés");

    // Hachage et chiffrement du mot de passe
    let password = "StrongP@ssw0rd";
    let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria)
        .expect("Erreur lors du hachage et du chiffrement");

    // Déchiffrement et vérification du mot de passe
    match decrypt_and_verify_password(&encrypted_hash, password, &private_key) {
        Ok(_) => println!("Le mot de passe est valide."),
        Err(e) => println!("Erreur lors de la vérification du mot de passe : {:?}", e),
    }
}

use ironcrypt::{hash_password, is_password_strong, PasswordCriteria};

fn main() {
  // Définition des critères de robustesse du mot de passe.
  let criteria = PasswordCriteria {
    min_length: 8,
    require_uppercase: true,
    require_numbers: true,
    require_special_chars: true,
    max_length: Some(20),
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

// Résultat : Le mot de passe haché est : $argon2id$v=19$m=19456,t=2,p=1$2hF8WmxsmuCDaytOywqdlg$D9wxeTvYO4xbi4DZW9fU2mbpwMF6X4xVgnQpK0+nOQo
```

## Sécurité et Bonnes Pratiques

- **Stockage des Clés** : Gardez la clé privée en sécurité et ne la partagez jamais publiquement. La clé publique peut être partagée pour chiffrer des données.
- **Mot de passe Robuste** : Encouragez les utilisateurs à choisir des mots de passe longs et complexes pour renforcer la sécurité.
- **Critères Personnalisés** : Adaptez `PasswordCriteria` selon les besoins spécifiques de votre application pour renforcer les exigences de mot de passe.

## Licence

`IronCrypt` est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une *issue* ou à soumettre une *pull request* pour proposer des améliorations ou des correctifs.