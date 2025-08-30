# Guide de la Cryptographie avec IronCrypt

Ce document détaille l'ensemble des commandes (APIs) disponibles dans l'outil `ironcrypt` pour effectuer des opérations cryptographiques.

## 1. Gestion des Clés Cryptographiques

Ce sont les commandes fondamentales pour créer et gérer le matériel cryptographique qui sécurise vos données.

---

### `generate`

*   **Domaine** : Mise en place de l'infrastructure de sécurité.
*   **Définition** : Crée une paire de clés asymétriques (RSA ou ECC). La clé publique sert à chiffrer et la clé privée à déchiffrer. La clé privée peut être protégée par une phrase de passe.
*   **Utilisation** :
    *   `--version <VERSION>`: Version de la clé (ex: "v1").
    *   `--directory <DIRECTORY>`: Répertoire de sauvegarde des clés (défaut: "keys").
    *   `--key-size <KEY_SIZE>`: Taille de la clé RSA en bits (défaut: 2048).
    *   `--passphrase <PASSPHRASE>`: Phrase de passe optionnelle pour la clé privée.
    *   `--key-type <KEY_TYPE>`: Type de clé (`rsa` ou `ecc`, défaut: `rsa`).
*   **Exemple de code** :
    ```sh
    # Générer une nouvelle paire de clés RSA de 4096 bits, version "v2"
    ironcrypt generate --version v2 --key-size 4096 --passphrase "mon_mot_de_passe_secret"
    ```

---

### `rotate-key` (alias: `rk`)

*   **Domaine** : Maintenance de la sécurité et conformité.
*   **Définition** : Remplace une clé de chiffrement existante par une nouvelle sur un fichier déjà chiffré. Elle déchiffre avec l'ancienne clé et rechiffre avec la nouvelle de manière atomique.
*   **Utilisation** :
    *   `--old-version <OLD_VERSION>`: L'ancienne version de la clé.
    *   `--new-version <NEW_VERSION>`: La nouvelle version de la clé.
    *   `--file <FILE>`: Le fichier à traiter.
    *   `--passphrase <PASSPHRASE>`: La phrase de passe des clés privées.
*   **Exemple de code** :
    ```sh
    # Remplacer la clé v1 par la clé v2 pour le fichier "rapport.enc"
    ironcrypt rotate-key --old-version v1 --new-version v2 --file rapport.enc --passphrase "phrase_secrete_des_cles"
    ```

## 2. Chiffrement & Déchiffrement de Données

Commandes pour protéger et accéder à vos données au quotidien.

---

### `encrypt-file` (alias: `encfile`, `efile`, `ef`)

*   **Domaine** : Protection de fichiers sensibles.
*   **Définition** : Chiffre un fichier unique. Peut utiliser plusieurs clés publiques pour autoriser plusieurs destinataires.
*   **Utilisation** :
    *   `--input-file <INPUT_FILE>`: Fichier source.
    *   `--output-file <OUTPUT_FILE>`: Fichier chiffré de destination.
    *   `--key-versions <KEY_VERSIONS...>`: Une ou plusieurs versions de clés publiques.
    *   `--password <PASSWORD>`: Mot de passe optionnel pour une sécurité additionnelle.
*   **Exemple de code** :
    ```sh
    # Chiffrer un rapport pour deux destinataires (v1 et v3)
    ironcrypt encrypt-file --input-file rapport.pdf --output-file rapport.enc --key-versions v1 v3
    ```

---

### `decrypt-file` (alias: `decfile`, `dfile`, `df`)

*   **Domaine** : Accès aux données sécurisées.
*   **Définition** : Opération inverse de `encrypt-file`. Utilise une clé privée pour déchiffrer un fichier.
*   **Utilisation** :
    *   `--input-file <INPUT_FILE>`: Fichier chiffré.
    *   `--output-file <OUTPUT_FILE>`: Fichier déchiffré de destination.
    *   `--key-version <KEY_VERSION>`: Version de la clé privée à utiliser.
    *   `--passphrase <PASSPHRASE>`: Phrase de passe de la clé privée.
*   **Exemple de code** :
    ```sh
    # Déchiffrer le fichier avec la clé privée v1
    ironcrypt decrypt-file --input-file rapport.enc --output-file rapport_dechiffre.pdf --key-version v1 --passphrase "ma_phrase_secrete"
    ```

---

### `encrypt-dir` (alias: `encdir`)

*   **Domaine** : Sauvegardes et archivage sécurisés.
*   **Définition** : Compresse un répertoire entier dans une archive `.tar.gz` puis chiffre cette archive. Idéal pour les sauvegardes.
*   **Utilisation** :
    *   `--input-dir <INPUT_DIR>`: Répertoire source.
    *   `--output-file <OUTPUT_FILE>`: Fichier chiffré de destination.
    *   `--key-versions <KEY_VERSIONS...>`: Clés publiques des destinataires.
*   **Exemple de code** :
    ```sh
    # Archiver et chiffrer le dossier "Photos_Vacances"
    ironcrypt encrypt-dir --input-dir ./Photos_Vacances --output-file vacances.enc --key-versions v1
    ```

---

### `decrypt-dir` (alias: `decdir`)

*   **Domaine** : Restauration de sauvegardes.
*   **Définition** : Déchiffre une archive créée par `encrypt-dir` et en extrait le contenu.
*   **Utilisation** :
    *   `--input-file <INPUT_FILE>`: Archive chiffrée.
    *   `--output-dir <OUTPUT_DIR>`: Répertoire de destination pour la restauration.
    *   `--key-version <KEY_VERSION>`: Version de la clé privée.
*   **Exemple de code** :
    ```sh
    # Restaurer l'archive dans un nouveau dossier "Vacances_Restaurees"
    ironcrypt decrypt-dir --input-file vacances.enc --output-dir ./Vacances_Restaurees --key-version v1
    ```

## 3. Cas d'Usage Spécifiques et Avancés

---

### `encrypt-pii` & `encrypt-bio`

*   **Domaine** : Conformité réglementaire (RGPD, HIPAA).
*   **Définition** : Commandes spécialisées pour chiffrer des données très sensibles (informations personnelles, biométrie) en utilisant potentiellement des configurations de sécurité renforcées.
*   **Utilisation** :
    *   `--input-file <INPUT_FILE>`: Fichier source.
    *   `--output-file <OUTPUT_FILE>`: Fichier chiffré de destination.
*   **Exemple de code** :
    ```sh
    # Chiffrer un fichier de données clients en utilisant la configuration PII
    ironcrypt encrypt-pii --input-file clients.csv --output-file clients.csv.enc
    ```

---

### `encrypt` & `decrypt` (pour mots de passe)

*   **Domaine** : Stockage de secrets et authentification.
*   **Définition** : Gère le hachage et le chiffrement de chaînes de caractères courtes (mots de passe, clés d'API). `encrypt` crée un hash chiffré. `decrypt` vérifie si un mot de passe en clair correspond au hash stocké.
*   **Utilisation (`encrypt`)** :
    *   `--password <PASSWORD>`: Le mot de passe à hacher et chiffrer.
*   **Utilisation (`decrypt`)** :
    *   `--password <PASSWORD>`: Le mot de passe à vérifier.
    *   `--data <DATA>`: Le hash chiffré à comparer.
*   **Exemple de code** :
    ```sh
    # 1. Chiffrer un mot de passe pour le stocker
    ENCRYPTED=$(ironcrypt encrypt --password "MotDePasse123!")

    # 2. Plus tard, vérifier si un mot de passe fourni est correct
    ironcrypt decrypt --password "MotDePasse123!" --data "$ENCRYPTED"
    # Output: Password correct.
    ```

---

### `daemon`

*   **Domaine** : Chiffrement transparent et automatisé.
*   **Définition** : Lance `ironcrypt` en tant que service d'arrière-plan (démon) pour des opérations de chiffrement/déchiffrement à la volée, typiquement via une API réseau pour d'autres applications.
*   **Utilisation** :
    *   `--port <PORT>`: Port d'écoute (défaut: 3000).
    *   `--key-directory <KEY_DIRECTORY>`: Répertoire des clés.
    *   `--key-version <KEY_VERSION>`: Version de la clé à utiliser.
*   **Exemple de code** :
    ```sh
    # Démarrer le démon pour qu'il écoute sur le port 3000 avec la clé v1
    ironcrypt daemon --port 3000 --key-directory ./keys --key-version v1
    ```

## 4. Fonctionnalités Avancées

Cette section décrit les fonctionnalités avancées pour la conformité et la sécurité.

---

### Journal d'Audit Structuré

*   **Domaine** : Traçabilité, sécurité et conformité.
*   **Définition** : `ironcrypt` enregistre désormais chaque opération de chiffrement et de déchiffrement dans un journal d'audit structuré au format JSON. Cela fournit une piste d'audit complète, essentielle pour les environnements réglementés.
*   **Informations enregistrées** :
    *   `operation`: Type d'opération (`encrypt` ou `decrypt`).
    *   `outcome`: Résultat (`success` ou `failure`).
    *   `key_version(s)`: La ou les versions de clé utilisées.
    *   `algorithm`: L'algorithme symétrique utilisé.
    *   `signature_verification`: Résultat de la vérification de la signature (si applicable).
*   **Utilisation** : Le journal est automatiquement généré lorsque des opérations de chiffrement/déchiffrement sont effectuées, en particulier lors de l'utilisation du démon `ironcryptd`. Les logs peuvent être collectés et analysés par des systèmes de gestion de logs (SIEM).

---

### Standard de Sécurité ANSSI

*   **Domaine** : Conformité et interopérabilité.
*   **Définition** : Ajout d'un nouveau standard de sécurité nommé `Anssi`, basé sur les recommandations de l'Agence Nationale de la Sécurité des Systèmes d'Information. L'utilisation de ce standard garantit que les paramètres cryptographiques sont conformes aux recommandations de sécurité françaises et européennes.
*   **Configuration du standard `Anssi`** :
    *   Algorithme Symétrique : `AES-256-GCM`
    *   Algorithme Asymétrique : `RSA`
    *   Taille de clé RSA : `3072` bits
*   **Utilisation** : Ce standard peut être utilisé lors de l'initialisation de la bibliothèque `ironcrypt` pour s'assurer que les configurations par défaut respectent un haut niveau de sécurité reconnu.
