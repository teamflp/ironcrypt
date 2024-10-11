# IronCrypt

## Introduction

**IronCrypt** est une librairie de cryptage de mots de passe en Rust, conçue pour offrir un niveau de sécurité élevé grâce à une combinaison d'algorithmes de hachage et de chiffrement. Utilisant **Argon2** pour le hachage sécurisé et le chiffrement **RSA** pour une deuxième couche de protection, IronCrypt est idéal pour les applications nécessitant une sécurité accrue, comme les systèmes de gestion des utilisateurs ou les applications financières.

## Fonctionnalités

- **Hachage sécurisé** des mots de passe avec l'algorithme **Argon2**.
- **Chiffrement RSA** pour protéger les mots de passe hachés.
- **Déchiffrement** et **vérification** sécurisés pour valider les mots de passe.
- Configuration flexible pour ajuster la robustesse du hachage et du chiffrement.

## Installation

Pour utiliser **IronCrypt** dans votre projet Rust, ajoutez les dépendances suivantes à votre fichier `Cargo.toml` :

```
[dependencies]
argon2 = "0.3"
rand = "0.8"
rsa = "0.9"
base64 = "0.21"
```

## Utilisation

### Génération des Clés RSA

Avant de pouvoir chiffrer les mots de passe, vous devez générer une paire de clés RSA (publique et privée) :

```rust
use rsa::{RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Erreur lors de la génération de la clé privée");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}
```

Une fois les clés générées, vous pouvez les sauvegarder dans des fichiers PEM pour les réutiliser ultérieurement :

```rust
use rsa::pkcs1::ToRsaPrivateKey;

let (private_key, public_key) = generate_rsa_keys();
let private_pem = private_key.to_pkcs1_pem().expect("Erreur de conversion de la clé privée");
std::fs::write("private_key.pem", private_pem).expect("Erreur de sauvegarde de la clé privée");

let public_pem = public_key.to_pkcs1_pem().expect("Erreur de conversion de la clé publique");
std::fs::write("public_key.pem", public_pem).expect("Erreur de sauvegarde de la clé publique");
```

### Chargement des Clés RSA

Pour utiliser les clés générées dans l'application :

```rust
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::FromRsaPrivateKey, pkcs1::FromRsaPublicKey};

fn load_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let private_pem = std::fs::read_to_string("private_key.pem").expect("Erreur de lecture de la clé privée");
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem).expect("Erreur de chargement de la clé privée");

    let public_pem = std::fs::read_to_string("public_key.pem").expect("Erreur de lecture de la clé publique");
    let public_key = RsaPublicKey::from_pkcs1_pem(&public_pem).expect("Erreur de chargement de la clé publique");

    (private_key, public_key)
}
```

### Hachage et Chiffrement des Mots de Passe

Utilisez la fonction suivante pour hacher et chiffrer un mot de passe :

```rust
use argon2::{self, Config};
use rand::Rng;
use rsa::{PublicKey, PaddingScheme};
use base64::encode;

pub fn hash_and_encrypt_password(password: &str, public_key: &RsaPublicKey) -> Result<String, String> {
    // Génère un sel aléatoire de 16 octets
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);

    // Configure Argon2 pour un hachage sécurisé
    let config = Config::default();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config)
        .map_err(|e| format!("Erreur lors du hachage du mot de passe: {:?}", e))?;

    // Chiffrement du hash avec la clé publique
    let encrypted_hash = public_key
        .encrypt(&mut rand::thread_rng(), PaddingScheme::new_pkcs1v15_encrypt(), hash.as_bytes())
        .map_err(|e| format!("Erreur lors du chiffrement du hash: {:?}", e))?;

    Ok(encode(encrypted_hash))
}
```

### Vérification des Mots de Passe

Pour vérifier un mot de passe fourni par l'utilisateur, déchiffrez le hash et comparez-le :

```rust
use rsa::{PaddingScheme, RsaPrivateKey};
use base64::decode;
use argon2::verify_encoded;

pub fn decrypt_and_verify_password(
    encrypted_hash: &str,
    password: &str,
    private_key: &RsaPrivateKey,
) -> Result<bool, String> {
    let encrypted_hash = decode(encrypted_hash)
        .map_err(|e| format!("Erreur lors du décodage du hash chiffré: {:?}", e))?;

    let decrypted_hash = private_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &encrypted_hash)
        .map_err(|e| format!("Erreur lors du déchiffrement du hash: {:?}", e))?;

    let decrypted_hash_str = String::from_utf8(decrypted_hash)
        .map_err(|e| format!("Erreur lors de la conversion du hash déchiffré: {:?}", e))?;

    verify_encoded(&decrypted_hash_str, password.as_bytes())
        .map_err(|e| format!("Erreur lors de la vérification du mot de passe: {:?}", e))
}
```

### Exemple Complet

Voici un exemple complet montrant l'utilisation de **IronCrypt** :

```rust
use ironcrypt::{generate_rsa_keys, hash_and_encrypt_password, decrypt_and_verify_password, load_rsa_keys};

fn main() {
    let password = "motdepasse_securise";
    let (private_key, public_key) = generate_rsa_keys();

    match hash_and_encrypt_password(password, &public_key) {
        Ok(encrypted_hash) => {
            println!("Mot de passe hashé et chiffré : {}", encrypted_hash);

            match decrypt_and_verify_password(&encrypted_hash, password, &private_key) {
                Ok(true) => println!("Mot de passe vérifié avec succès après déchiffrement."),
                Ok(false) => println!("Échec de la vérification du mot de passe."),
                Err(e) => println!("Erreur: {}", e),
            }
        }
        Err(e) => println!("Erreur de hashage et chiffrement: {}", e),
    }
}
```

## Sécurité

- **Chiffrement RSA** : Utilisez une taille de clé d'au moins 2048 bits pour garantir une sécurité optimale. Pour des besoins encore plus élevés, envisagez 4096 bits.
- **Stockage des clés** : La clé privée doit être stockée dans un endroit sécurisé, tel qu'un fichier protégé ou un gestionnaire de secrets, pour éviter tout accès non autorisé.
- **Sel pour le hachage** : Chaque mot de passe est haché avec un sel unique pour prévenir les attaques par rainbow table.

## Meilleures Pratiques

- **Ne partagez jamais votre clé privée** : La clé privée doit rester confidentielle. Seule la clé publique peut être partagée pour le chiffrement.
- **Mettez à jour régulièrement** : Assurez-vous de maintenir à jour les dépendances de la librairie pour bénéficier des dernières améliorations de sécurité.
- **Audit de sécurité** : Effectuez régulièrement des audits de sécurité de votre implémentation pour identifier et corriger les éventuelles vulnérabilités.

## Contribuer

Les contributions à **IronCrypt** sont les bienvenues ! Si vous souhaitez ajouter de nouvelles fonctionnalités ou améliorer la documentation, n'hésitez pas à soumettre une pull request.

— 

# QUELQUES FONCTIONNALITES A IMPLEMENTER

Pour renforcer davantage la sécurité de la librairie **IronCrypt**, plusieurs fonctionnalités et améliorations peuvent être ajoutées. Voici quelques suggestions qui couvrent différentes dimensions de la sécurité :

### 1. **Utilisation de HMAC pour l'Intégrité des Données**

- **Description** : Implémenter un mécanisme d'authentification de message basé sur un code de hachage (HMAC) pour garantir l'intégrité des données.
- **Avantage** : Cela permet de vérifier que les données chiffrées n'ont pas été altérées pendant leur stockage ou leur transfert.
- **Comment l'implémenter** :
  - Ajouter un HMAC au hash avant le chiffrement.
  - Lors de la vérification, déchiffrer et comparer le HMAC pour s'assurer que le contenu n'a pas été modifié.

### 2. **Rotation des Clés RSA**

- **Description** : Implémenter un mécanisme de rotation des clés RSA à intervalles réguliers.
- **Avantage** : Cela réduit les risques en cas de compromission d'une clé, limitant l'impact sur les données chiffrées avant la rotation.
- **Comment l'implémenter** :
  - Ajouter un système de gestion des versions pour les clés.
  - Associer chaque hash chiffré à une version de clé spécifique et utiliser la clé appropriée pour le déchiffrement.

### 3. **Double Hashing (Pepper)**

- **Description** : En plus du sel (salt) unique pour chaque mot de passe, ajouter un **pepper**, qui est une valeur secrète partagée utilisée pour hacher les mots de passe.
- **Avantage** : Même si un attaquant obtient les hashs et les sels, le pepper, qui est stocké séparément et non dans la base de données, ajoute une couche supplémentaire de protection.
- **Comment l'implémenter** :
  - Ajouter une valeur secrète (pepper) globale à chaque hash avant le hachage avec Argon2.
  - Stocker le pepper dans un fichier de configuration sécurisé ou un service de gestion de secrets.

### 4. **Support pour les Algorithmes de Hachage Adaptatifs**

- **Description** : Permettre à l'utilisateur de choisir entre différents algorithmes de hachage, comme **bcrypt**, **scrypt**, et **Argon2**, avec des paramètres de configuration pour ajuster la complexité.
- **Avantage** : Donne la flexibilité de choisir l'algorithme le mieux adapté aux besoins de sécurité de l'application.
- **Comment l'implémenter** :
  - Créer une interface ou une énumération pour sélectionner l'algorithme.
  - Ajouter des configurations pour ajuster la difficulté de chaque algorithme.

### 5. **Validation des Mots de Passe Forts**

- **Description** : Intégrer un vérificateur de robustesse des mots de passe pour s'assurer que les utilisateurs choisissent des mots de passe forts.
- **Avantage** : Empêche les utilisateurs d'utiliser des mots de passe faibles qui peuvent être facilement devinés.
- **Comment l'implémenter** :
  - Ajouter une fonction qui vérifie les critères de robustesse (longueur minimale, complexité, etc.).
  - Refuser les mots de passe ne respectant pas ces critères avant de procéder au hachage.

### 6. **Chiffrement Symétrique pour les Mots de Passe Temporairement Utilisés**

- **Description** : Pour les cas où il est nécessaire de stocker un mot de passe en clair pour une courte période (comme pour un mot de passe temporaire), utiliser un chiffrement symétrique comme **AES**.
- **Avantage** : Les mots de passe ne sont jamais stockés en clair, même temporairement.
- **Comment l'implémenter** :
  - Utiliser une clé de chiffrement symétrique pour chiffrer les mots de passe avant de les stocker temporairement.
  - Détruire la clé après que le mot de passe ait été utilisé.

### 7. **Limiter le Nombre de Tentatives de Décryptage**

- **Description** : Implémenter une protection contre les attaques par force brute en limitant le nombre de tentatives de décryptage ou de vérification de mot de passe.
- **Avantage** : Empêche les tentatives répétées de décryptage, ce qui rend les attaques de type brute force beaucoup plus difficiles.
- **Comment l'implémenter** :
  - Ajouter un compteur pour chaque tentative de vérification échouée.
  - Imposer un délai ou bloquer la vérification après un certain nombre de tentatives.

### 8. **Stockage Sécurisé des Sels et des Clés**

- **Description** : Utiliser un **gestionnaire de secrets** ou une solution de chiffrement matérielle comme un **HSM (Hardware Security Module)** pour stocker les sels et les clés.
- **Avantage** : Les sels et les clés sont stockés de manière sécurisée, même en cas de compromission du serveur.
- **Comment l'implémenter** :
  - Utiliser des services comme AWS KMS, HashiCorp Vault, ou Azure Key Vault pour gérer et récupérer les clés de chiffrement.

### 9. **Signature des Hashs avec une Clé Privée**

- **Description** : Signer le hash généré avec une clé privée pour s'assurer de son authenticité.
- **Avantage** : Permet de vérifier que le hash a été généré par une source de confiance et n'a pas été altéré.
- **Comment l'implémenter** :
  - Utiliser un algorithme de signature numérique, comme **ECDSA**, pour signer les hash avant chiffrement.
  - Vérifier la signature lors de la décryption pour s'assurer que le hash est authentique.

### 10. **Audit et Journalisation des Opérations de Chiffrement/Décryptage**

- **Description** : Ajouter un système de journalisation pour suivre les opérations de chiffrement et de déchiffrement.
- **Avantage** : Permet de détecter et d'enquêter sur les tentatives suspectes ou les accès non autorisés.
- **Comment l'implémenter** :
  - Ajouter une fonction de journalisation pour chaque tentative de vérification de mot de passe.
  - Stocker les journaux dans un emplacement sécurisé pour analyse ultérieure.

### Résumé

Ces fonctionnalités permettent de renforcer considérablement la sécurité de **IronCrypt**. En combinant un hachage sécurisé, un chiffrement asymétrique, des mécanismes de gestion des clés, et des pratiques de sécurité avancées, tu pourras créer une librairie extrêmement robuste pour le stockage des mots de passe. N'hésite pas à adapter ces suggestions en fonction des besoins spécifiques de ton projet et du niveau de sécurité requis.

H1 STRUCTURE DE IRONCRYPT

ironcrypt/\
├── Cargo.toml\
├── src/\
│   ├── [lib.rs](http://lib.rs)\
│   ├── [criteria.rs](http://criteria.rs)\
│   ├── [encryption.rs](http://encryption.rs)\
│   ├── [hashing.rs](http://hashing.rs)\
│   └── rsa_utils.rs\
├── examples/\
│   ├── example_basic.rs\
│   └── example_with_criteria.rs\
├── tests/\
│   ├── integration_test.rs\
│   └── criteria_test.rs\
├── [README.md](http://README.md)\
├── LICENSE\
└── .gitignore 

`src/` :

- Contient le code source de la librairie.

- `lib.rs` :

  - Point d'entrée de la librairie. Ce fichier expose les modules principaux et leurs fonctions.

  - Exemple de contenu :

    ```rust
    pub mod criteria;
    pub mod encryption;
    pub mod hashing;
    pub mod rsa_utils;
    
    pub use criteria::{PasswordCriteria, is_password_strong};
    pub use encryption::{hash_and_encrypt_password_with_criteria, decrypt_and_verify_password};
    pub use rsa_utils::{generate_rsa_keys, load_rsa_keys};
    ```

`criteria.rs` :

- Contient la structure `PasswordCriteria` et la fonction `is_password_strong`.

- Gère la vérification de la robustesse des mots de passe.

- Exemple de contenu :

  ```rust
  pub struct PasswordCriteria {
      pub min_length: usize,
      pub require_uppercase: bool,
      pub require_numbers: bool,
      pub require_special_chars: bool,
  }
  
  impl PasswordCriteria {
      pub fn default() -> Self {
          Self {
              min_length: 8,
              require_uppercase: true,
              require_numbers: true,
              require_special_chars: true,
          }
      }
  }
  
  pub fn is_password_strong(password: &str, criteria: &PasswordCriteria) -> Result<(), String> {
      // Implémentation de la vérification...
  }
  ```

`encryption.rs` :

- Contient les fonctions de hachage, de chiffrement, et de vérification.

- Exemple de contenu :

  ```rust
  use argon2::{self, Config};
  use rsa::{RsaPublicKey, RsaPrivateKey, PaddingScheme};
  use base64::{encode, decode};
  use rand::Rng;
  
  pub fn hash_and_encrypt_password_with_criteria(
      password: &str,
      public_key: &RsaPublicKey,
      criteria: &PasswordCriteria,
  ) -> Result<String, String> {
      // Vérifie les critères de robustesse et hache le mot de passe.
  }
  
  pub fn decrypt_and_verify_password(
      encrypted_hash: &str,
      password: &str,
      private_key: &RsaPrivateKey,
  ) -> Result<bool, String> {
      // Implémentation de la vérification...
  }
  ```

`hashing.rs` :

- Contient les fonctions spécifiques au hachage des mots de passe avec Argon2.

- Exemple de contenu :

  ```rust
  use argon2::{self, Config};
  use rand::Rng;
  
  pub fn hash_password(password: &str) -> Result<String, String> {
      // Implémentation de la fonction de hachage...
  }
  ```

`rsa_utils.rs` :

- Gère la génération et le chargement des clés RSA.

- Exemple de contenu :

  ```rust
  use rsa::{RsaPrivateKey, RsaPublicKey};
  use rand::rngs::OsRng;
  
  pub fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
      // Implémentation de la génération de clés...
  }
  
  pub fn load_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
      // Chargement des clés depuis les fichiers...
  }
  ```


- `examples/` :
  - Contient des exemples de code pour illustrer l'utilisation de la librairie.

  - `example_basic.rs` :

    - Un exemple simple qui montre comment hacher et vérifier un mot de passe.

  - `example_with_criteria.rs` :

    - Montre comment utiliser des critères personnalisés pour la vérification des mots de passe avant le hachage.
- `tests/` :
  - Contient les tests pour la librairie.

  - `integration_test.rs` :

    - Tests d'intégration pour vérifier le bon fonctionnement de la librairie dans son ensemble.

  - `criteria_test.rs` :

    - Tests unitaires pour vérifier le fonctionnement de la vérification des critères de robustesse des mots de passe.
- `README.md` :
  - Documentation détaillée sur la librairie, ses fonctionnalités, comment l'utiliser, et des exemples de code.
  - Contient une description du projet, des instructions pour l'installation et l'utilisation, et un guide pour les contributeurs.
- `LICENSE` :
  - Le fichier de licence pour votre projet, tel que MIT, Apache 2.0, etc.
- `.gitignore` :
  - Spécifie les fichiers à ignorer par Git, comme `target/`, `.env`, et `*.pem` pour les clés sensibles.

  ```gitignore
  target/
  *.pem
  Cargo.lock
  .env
  ```