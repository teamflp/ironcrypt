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
```

## Sécurité et Bonnes Pratiques

- **Stockage des Clés** : Gardez la clé privée en sécurité et ne la partagez jamais publiquement. La clé publique peut être partagée pour chiffrer des données.
- **Mot de passe Robuste** : Encouragez les utilisateurs à choisir des mots de passe longs et complexes pour renforcer la sécurité.
- **Critères Personnalisés** : Adaptez `PasswordCriteria` selon les besoins spécifiques de votre application pour renforcer les exigences de mot de passe.

## Licence

`IronCrypt` est distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une *issue* ou à soumettre une *pull request* pour proposer des améliorations ou des correctifs.