use argon2::password_hash::rand_core::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;

/// Génère une paire de clés RSA (privée et publique).
///
/// Cette fonction crée une clé privée RSA de 2048 bits ainsi que la clé publique correspondante.
/// Les clés sont générées en utilisant un générateur de nombres aléatoires sécurisé (`OsRng`),
/// garantissant un niveau élevé de sécurité pour les opérations de chiffrement et de signature numérique.
///
/// # Retour
///
/// Renvoie un tuple `(RsaPrivateKey, RsaPublicKey)` contenant :
/// - `RsaPrivateKey` : La clé privée RSA, utilisée pour déchiffrer des données ou signer numériquement.
/// - `RsaPublicKey` : La clé publique RSA, utilisée pour chiffrer des données ou vérifier des signatures numériques.
///
/// # Exemple
///
/// ```rust
/// use crate::ironcrypt::generate_rsa_keys;
///
/// let (private_key, public_key) = generate_rsa_keys();
/// println!("Clé privée générée avec succès.");
/// println!("Clé publique générée avec succès.");
/// ```
///
/// Dans cet exemple, une paire de clés RSA est générée, et les messages de confirmation sont affichés
/// pour indiquer que les clés ont été créées avec succès.
///
/// # Remarques
///
/// - La taille de la clé est fixée à 2048 bits, ce qui est un bon compromis entre sécurité et performance
///   pour la plupart des applications. Vous pouvez ajuster cette taille en modifiant le second paramètre
///   de `RsaPrivateKey::new` si une sécurité accrue est nécessaire.
/// - Assurez-vous de sauvegarder la clé privée dans un emplacement sécurisé, car sa perte entraînera l'impossibilité
///   de déchiffrer les données ou de valider les signatures associées.
/// - La clé publique peut être partagée en toute sécurité avec les autres parties, car elle ne permet pas
///   de déchiffrer les données chiffrées avec elle.
///
/// # Panics
///
/// Cette fonction provoquera un `panic` si la génération de la clé privée échoue. Cela peut survenir
/// en cas de problème interne avec le générateur de nombres aléatoires ou de ressources système insuffisantes.
pub fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).expect("Erreur lors de la génération de la clé privée");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}


/// Charge les clés RSA à partir de fichiers PEM.
///
/// Cette fonction lit les clés RSA (privée et publique) à partir de fichiers PEM spécifiés
/// et les charge sous forme de `RsaPrivateKey` et `RsaPublicKey`.
/// Elle utilise le format PKCS#1 pour décoder les clés à partir des chaînes de caractères
/// lues dans les fichiers.
///
/// # Arguments
///
/// * `private_key_path` - Le chemin vers le fichier contenant la clé privée au format PEM.
/// * `public_key_path` - Le chemin vers le fichier contenant la clé publique au format PEM.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok((RsaPrivateKey, RsaPublicKey))` : La clé privée et la clé publique chargées avec succès.
/// - `Err(String)` : Un message d'erreur décrivant la raison de l'échec si la lecture ou le chargement des clés échoue.
///
/// # Exemple
///
/// ```rust
/// use crate::ironcrypt::load_rsa_keys;
///
/// let private_key_path = "private_key.pem";
/// let public_key_path = "public_key.pem";
/// match load_rsa_keys(private_key_path, public_key_path) {
///     Ok((private_key, public_key)) => {
///         println!("Clés RSA chargées avec succès.");
///     }
///     Err(e) => {
///         println!("Erreur lors du chargement des clés RSA : {}", e);
///     }
/// }
/// ```
///
/// Dans cet exemple, les clés RSA sont chargées à partir des fichiers "private_key.pem" et "public_key.pem",
/// et un message de confirmation est affiché en cas de succès. En cas d'échec, le message d'erreur est affiché.
///
/// # Remarques
///
/// - Assurez-vous que les fichiers contenant les clés sont accessibles en lecture et qu'ils contiennent
///   des clés au format PEM valide pour éviter les erreurs de lecture ou de parsing.
/// - Cette fonction renverra une `Err` si les fichiers sont introuvables ou si les données ne peuvent pas
///   être interprétées comme des clés RSA au format PKCS#1.
///
/// # Erreurs
///
/// La fonction peut renvoyer une `Err` si :
/// - La lecture des fichiers de clés échoue (par exemple, si le fichier n'existe pas ou les permissions sont insuffisantes).
/// - Le format des clés dans les fichiers PEM est invalide ou ne peut pas être interprété.
pub fn load_rsa_keys(
    private_key_path: &str,
    public_key_path: &str,
) -> Result<(RsaPrivateKey, RsaPublicKey), String> {
    let private_pem = std::fs::read_to_string(private_key_path)
        .map_err(|e| format!("Erreur de lecture de la clé privée: {:?}", e))?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem)
        .map_err(|e| format!("Erreur lors du chargement de la clé privée: {:?}", e))?;

    let public_pem = std::fs::read_to_string(public_key_path)
        .map_err(|e| format!("Erreur de lecture de la clé publique: {:?}", e))?;
    let public_key = RsaPublicKey::from_pkcs1_pem(&public_pem)
        .map_err(|e| format!("Erreur lors du chargement de la clé publique: {:?}", e))?;

    Ok((private_key, public_key))
}


/// Sauvegarde les clés RSA générées dans des fichiers.
///
/// Cette fonction prend une clé privée et une clé publique RSA, les convertit en format PEM,
/// puis les enregistre dans les fichiers spécifiés. Cela permet de stocker les clés dans un format
/// lisible et standardisé pour une utilisation ultérieure, comme le chargement ou le partage
/// sécurisé de la clé publique.
///
/// # Arguments
///
/// * `private_key` - Une référence à la clé privée RSA (`RsaPrivateKey`) à sauvegarder.
/// * `public_key` - Une référence à la clé publique RSA (`RsaPublicKey`) à sauvegarder.
/// * `priv_path` - Le chemin du fichier où la clé privée sera sauvegardée (ex. : "private_key.pem").
/// * `pub_path` - Le chemin du fichier où la clé publique sera sauvegardée (ex. : "public_key.pem").
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(())` : Si les clés ont été converties et écrites avec succès dans les fichiers.
/// - `Err(String)` : Un message d'erreur décrivant la raison de l'échec si la conversion ou l'écriture échoue.
///
/// # Exemple
///
/// ```rust
/// use crate::ironcrypt::save_keys_to_files;
/// use rsa::{RsaPrivateKey, RsaPublicKey};
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Erreur de génération de la clé privée");
/// let public_key = RsaPublicKey::from(&private_key);
///
/// let priv_path = "private_key.pem";
/// let pub_path = "public_key.pem";
///
/// match save_keys_to_files(&private_key, &public_key, priv_path, pub_path) {
///     Ok(_) => println!("Clés RSA sauvegardées avec succès."),
///     Err(e) => println!("Erreur lors de la sauvegarde des clés RSA : {}", e),
/// }
/// ```
///
/// Dans cet exemple, les clés privées et publiques RSA sont converties en format PEM
/// et enregistrées dans les fichiers "private_key.pem" et "public_key.pem". Un message de confirmation
/// est affiché en cas de succès, et un message d'erreur est affiché en cas de problème.
///
/// # Remarques
///
/// - Assurez-vous que le chemin spécifié pour les fichiers est accessible en écriture pour éviter
///   les erreurs de permission lors de la sauvegarde des clés.
/// - La clé privée doit être stockée dans un emplacement sécurisé pour éviter tout accès non autorisé.
/// - La clé publique peut être partagée de manière sécurisée, mais elle doit également être protégée contre
///   les modifications non autorisées.
///
/// # Erreurs
///
/// La fonction peut renvoyer une `Err` si :
/// - La conversion de la clé privée ou de la clé publique au format PEM échoue.
/// - L'écriture des données dans les fichiers spécifiés échoue (par exemple, en raison de permissions insuffisantes
///   ou si le chemin n'existe pas).
pub fn save_keys_to_files(
    private_key: &RsaPrivateKey,
    public_key: &RsaPublicKey,
    priv_path: &str,
    pub_path: &str,
) -> Result<(), String> {
    let private_pem = private_key
        .to_pkcs1_pem(Default::default())
        .map_err(|e| format!("Erreur lors de la conversion de la clé privée : {:?}", e))?;
    let public_pem = public_key
        .to_pkcs1_pem(Default::default())
        .map_err(|e| format!("Erreur lors de la conversion de la clé publique : {:?}", e))?;

    std::fs::write(priv_path, private_pem)
        .map_err(|e| format!("Erreur lors de l'écriture de la clé privée : {:?}", e))?;
    std::fs::write(pub_path, public_pem)
        .map_err(|e| format!("Erreur lors de l'écriture de la clé publique : {:?}", e))?;

    Ok(())
}
