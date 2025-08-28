use ironcrypt::{CryptoStandard, IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
use std::collections::HashMap;

#[tokio::test]
async fn test_nist_standard_applies_correct_params() {
    // Arrange - Setup test environment for NIST cryptographic standard validation
    println!("Testing NIST cryptographic standard parameter application...");
    let temp_dir = tempfile::tempdir()
        .expect("Failed to create temporary directory for NIST test");
    let key_dir = temp_dir.path().to_str()
        .expect("Failed to convert temporary directory path to string");
    
    let mut config = IronCryptConfig::default();
    config.standard = CryptoStandard::Nist;
    println!("✓ Configuration set to NIST standard");

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

    // Act - Initialize IronCrypt with NIST standard
    let crypt = IronCrypt::new(config, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with NIST standard");
    println!("✓ IronCrypt initialized successfully with NIST standard");

    // Assert - Verify NIST parameters are correctly applied
    let expected_params = CryptoStandard::Nist.get_params()
        .expect("Failed to get NIST standard parameters");
    
    // Validate symmetric algorithm configuration
    assert_eq!(
        crypt.config.symmetric_algorithm, 
        expected_params.symmetric_algorithm,
        "NIST standard should use AES-256-GCM symmetric algorithm, got {:?}",
        crypt.config.symmetric_algorithm
    );
    println!("✓ Symmetric algorithm correctly set to {:?}", expected_params.symmetric_algorithm);
    
    // Validate asymmetric algorithm configuration  
    assert_eq!(
        crypt.config.asymmetric_algorithm, 
        expected_params.asymmetric_algorithm,
        "NIST standard should use RSA asymmetric algorithm, got {:?}",
        crypt.config.asymmetric_algorithm
    );
    println!("✓ Asymmetric algorithm correctly set to {:?}", expected_params.asymmetric_algorithm);
    
    // Validate RSA key size configuration
    assert_eq!(
        crypt.config.rsa_key_size, 
        expected_params.rsa_key_size,
        "NIST standard should use 3072-bit RSA keys, got {}",
        crypt.config.rsa_key_size
    );
    println!("✓ RSA key size correctly set to {} bits", expected_params.rsa_key_size);
    
    // Additional validation: ensure standard is preserved
    assert_eq!(
        crypt.config.standard,
        CryptoStandard::Nist,
        "Standard should remain NIST after initialization"
    );
    println!("✓ NIST standard configuration validation completed successfully");
}

#[tokio::test]
async fn test_fips_standard_applies_correct_params() {
    // Arrange - Setup test environment for FIPS 140-2 cryptographic standard validation
    println!("Testing FIPS 140-2 cryptographic standard parameter application...");
    let temp_dir = tempfile::tempdir()
        .expect("Failed to create temporary directory for FIPS test");
    let key_dir = temp_dir.path().to_str()
        .expect("Failed to convert temporary directory path to string");
    
    let mut config = IronCryptConfig::default();
    config.standard = CryptoStandard::Fips140_2;
    println!("✓ Configuration set to FIPS 140-2 standard");

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

    // Act - Initialize IronCrypt with FIPS 140-2 standard
    let crypt = IronCrypt::new(config, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with FIPS 140-2 standard");
    println!("✓ IronCrypt initialized successfully with FIPS 140-2 standard");

    // Assert - Verify FIPS 140-2 parameters are correctly applied
    let expected_params = CryptoStandard::Fips140_2.get_params()
        .expect("Failed to get FIPS 140-2 standard parameters");
    
    // Validate symmetric algorithm configuration (FIPS 140-2 approved algorithms)
    assert_eq!(
        crypt.config.symmetric_algorithm, 
        expected_params.symmetric_algorithm,
        "FIPS 140-2 standard should use AES-256-GCM symmetric algorithm, got {:?}",
        crypt.config.symmetric_algorithm
    );
    println!("✓ Symmetric algorithm correctly set to {:?} (FIPS 140-2 approved)", expected_params.symmetric_algorithm);
    
    // Validate asymmetric algorithm configuration (FIPS 140-2 approved algorithms)
    assert_eq!(
        crypt.config.asymmetric_algorithm, 
        expected_params.asymmetric_algorithm,
        "FIPS 140-2 standard should use RSA asymmetric algorithm, got {:?}",
        crypt.config.asymmetric_algorithm
    );
    println!("✓ Asymmetric algorithm correctly set to {:?} (FIPS 140-2 approved)", expected_params.asymmetric_algorithm);
    
    // Validate RSA key size configuration (FIPS 140-2 minimum requirements)
    assert_eq!(
        crypt.config.rsa_key_size, 
        expected_params.rsa_key_size,
        "FIPS 140-2 standard should use 3072-bit RSA keys (exceeds 2048-bit minimum), got {}",
        crypt.config.rsa_key_size
    );
    println!("✓ RSA key size correctly set to {} bits (exceeds FIPS 140-2 minimum)", expected_params.rsa_key_size);
    
    // Additional validation: ensure standard is preserved
    assert_eq!(
        crypt.config.standard,
        CryptoStandard::Fips140_2,
        "Standard should remain FIPS 140-2 after initialization"
    );
    println!("✓ FIPS 140-2 standard configuration validation completed successfully");
}

#[tokio::test]
async fn test_custom_standard_retains_user_params() {
    // Arrange - Setup test environment for custom cryptographic standard validation
    println!("Testing custom cryptographic standard parameter retention...");
    let temp_dir = tempfile::tempdir()
        .expect("Failed to create temporary directory for custom standard test");
    let key_dir = temp_dir.path().to_str()
        .expect("Failed to convert temporary directory path to string");
    
    let mut config = IronCryptConfig {
        standard: CryptoStandard::Custom,
        symmetric_algorithm: ironcrypt::algorithms::SymmetricAlgorithm::ChaCha20Poly1305,
        asymmetric_algorithm: ironcrypt::algorithms::AsymmetricAlgorithm::Ecc,
        rsa_key_size: 4096, // This will be ignored for ECC, but we test it's not overwritten
        ..Default::default()
    };
    println!("✓ Configuration set to custom standard with user-defined parameters");
    println!("  - Symmetric: {:?}", config.symmetric_algorithm);
    println!("  - Asymmetric: {:?}", config.asymmetric_algorithm);
    println!("  - RSA key size: {} bits", config.rsa_key_size);

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

    // Store original config values for comparison
    let original_config = config.clone();

    // Act - Initialize IronCrypt with custom standard
    let crypt = IronCrypt::new(config, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with custom standard");
    println!("✓ IronCrypt initialized successfully with custom standard");

    // Assert - Verify that custom parameters are preserved and not overridden
    assert_eq!(
        crypt.config.standard, 
        CryptoStandard::Custom,
        "Standard should remain Custom after initialization"
    );
    println!("✓ Standard correctly preserved as Custom");
    
    // Validate that user-defined symmetric algorithm is preserved
    assert_eq!(
        crypt.config.symmetric_algorithm, 
        original_config.symmetric_algorithm,
        "Custom standard should preserve user-defined symmetric algorithm {:?}, got {:?}",
        original_config.symmetric_algorithm,
        crypt.config.symmetric_algorithm
    );
    println!("✓ User-defined symmetric algorithm preserved: {:?}", crypt.config.symmetric_algorithm);
    
    // Validate that user-defined asymmetric algorithm is preserved
    assert_eq!(
        crypt.config.asymmetric_algorithm, 
        original_config.asymmetric_algorithm,
        "Custom standard should preserve user-defined asymmetric algorithm {:?}, got {:?}",
        original_config.asymmetric_algorithm,
        crypt.config.asymmetric_algorithm
    );
    println!("✓ User-defined asymmetric algorithm preserved: {:?}", crypt.config.asymmetric_algorithm);
    
    // Validate that user-defined RSA key size is preserved
    assert_eq!(
        crypt.config.rsa_key_size, 
        original_config.rsa_key_size,
        "Custom standard should preserve user-defined RSA key size {} bits, got {}",
        original_config.rsa_key_size,
        crypt.config.rsa_key_size
    );
    println!("✓ User-defined RSA key size preserved: {} bits", crypt.config.rsa_key_size);
    
    // Additional validation: verify that no standard parameters were auto-applied
    let custom_params = CryptoStandard::Custom.get_params();
    assert!(
        custom_params.is_none(),
        "Custom standard should not provide default parameters"
    );
    println!("✓ Custom standard correctly returns no default parameters (user configuration preserved)");
    println!("✓ Custom standard configuration validation completed successfully");
}

#[tokio::test]
async fn test_standards_parameter_consistency() {
    println!("Testing cryptographic standards parameter consistency and edge cases...");
    
    // Test 1: Ensure all standards (except Custom) provide valid parameters
    println!("Validating that all standards provide consistent parameters...");
    
    let standards = vec![
        CryptoStandard::Nist,
        CryptoStandard::Fips140_2,
        CryptoStandard::Anssi,
    ];
    
    for standard in standards {
        let params = standard.get_params()
            .expect(&format!("Standard {:?} should provide parameters", standard));
        
        // Validate that RSA key sizes meet minimum security requirements
        assert!(
            params.rsa_key_size >= 2048,
            "Standard {:?} should specify RSA key size >= 2048 bits, got {}",
            standard,
            params.rsa_key_size
        );
        
        // Validate that symmetric algorithms are strong
        match params.symmetric_algorithm {
            ironcrypt::algorithms::SymmetricAlgorithm::Aes256Gcm |
            ironcrypt::algorithms::SymmetricAlgorithm::ChaCha20Poly1305 => {
                println!("✓ Standard {:?} uses secure symmetric algorithm: {:?}", 
                        standard, params.symmetric_algorithm);
            },
        }
        
        // Validate asymmetric algorithms
        match params.asymmetric_algorithm {
            ironcrypt::algorithms::AsymmetricAlgorithm::Rsa |
            ironcrypt::algorithms::AsymmetricAlgorithm::Ecc => {
                println!("✓ Standard {:?} uses secure asymmetric algorithm: {:?}", 
                        standard, params.asymmetric_algorithm);
            },
        }
    }
    
    // Test 2: Verify Custom standard doesn't interfere with other standards
    println!("Testing Custom standard isolation...");
    let custom_params = CryptoStandard::Custom.get_params();
    assert!(custom_params.is_none(), "Custom standard should not provide default parameters");
    println!("✓ Custom standard correctly provides no default parameters");
    
    // Test 3: Test that changing standard updates configuration correctly
    println!("Testing standard switching behavior...");
    let temp_dir = tempfile::tempdir()
        .expect("Failed to create temporary directory");
    let key_dir = temp_dir.path().to_str()
        .expect("Failed to convert path to string");
    
    // Start with NIST
    let mut config = IronCryptConfig::default(); // Default is NIST
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config.clone());
    
    let crypt_nist = IronCrypt::new(config.clone(), DataType::Generic).await
        .expect("Failed to initialize with NIST standard");
    
    // Verify NIST parameters are applied
    let nist_params = CryptoStandard::Nist.get_params().unwrap();
    assert_eq!(crypt_nist.config.symmetric_algorithm, nist_params.symmetric_algorithm);
    assert_eq!(crypt_nist.config.asymmetric_algorithm, nist_params.asymmetric_algorithm);
    assert_eq!(crypt_nist.config.rsa_key_size, nist_params.rsa_key_size);
    println!("✓ NIST standard parameters correctly applied");
    
    // Switch to FIPS 140-2
    config.standard = CryptoStandard::Fips140_2;
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v2".to_string(),  // Different version to avoid key conflicts
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);
    
    let crypt_fips = IronCrypt::new(config, DataType::Generic).await
        .expect("Failed to initialize with FIPS 140-2 standard");
    
    // Verify FIPS parameters are applied
    let fips_params = CryptoStandard::Fips140_2.get_params().unwrap();
    assert_eq!(crypt_fips.config.symmetric_algorithm, fips_params.symmetric_algorithm);
    assert_eq!(crypt_fips.config.asymmetric_algorithm, fips_params.asymmetric_algorithm);
    assert_eq!(crypt_fips.config.rsa_key_size, fips_params.rsa_key_size);
    println!("✓ FIPS 140-2 standard parameters correctly applied");
    
    // Test 4: Verify standards provide consistent security levels
    println!("Verifying consistent security levels across standards...");
    
    // All our defined standards should use strong key sizes
    assert_eq!(nist_params.rsa_key_size, 3072, "NIST should use 3072-bit RSA keys");
    assert_eq!(fips_params.rsa_key_size, 3072, "FIPS should use 3072-bit RSA keys");
    
    let anssi_params = CryptoStandard::Anssi.get_params().unwrap();
    assert_eq!(anssi_params.rsa_key_size, 3072, "ANSSI should specify 3072-bit RSA keys");
    
    // All should use AES-256-GCM for symmetric encryption
    assert_eq!(nist_params.symmetric_algorithm, ironcrypt::algorithms::SymmetricAlgorithm::Aes256Gcm);
    assert_eq!(fips_params.symmetric_algorithm, ironcrypt::algorithms::SymmetricAlgorithm::Aes256Gcm);
    assert_eq!(anssi_params.symmetric_algorithm, ironcrypt::algorithms::SymmetricAlgorithm::Aes256Gcm);
    
    println!("✓ All standards provide consistent and secure parameter choices");
    println!("✓ Standards parameter consistency validation completed successfully");
}

#[tokio::test]
async fn test_anssi_standard_applies_correct_params() {
    // Arrange - Setup test environment for ANSSI cryptographic standard validation
    println!("Testing ANSSI (French national agency) cryptographic standard parameter application...");
    let temp_dir = tempfile::tempdir()
        .expect("Failed to create temporary directory for ANSSI test");
    let key_dir = temp_dir.path().to_str()
        .expect("Failed to convert temporary directory path to string");
    
    let mut config = IronCryptConfig::default();
    config.standard = CryptoStandard::Anssi;
    println!("✓ Configuration set to ANSSI standard");

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

    // Act - Initialize IronCrypt with ANSSI standard
    let crypt = IronCrypt::new(config, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with ANSSI standard");
    println!("✓ IronCrypt initialized successfully with ANSSI standard");

    // Assert - Verify ANSSI parameters are correctly applied
    let expected_params = CryptoStandard::Anssi.get_params()
        .expect("Failed to get ANSSI standard parameters");
    
    // Validate symmetric algorithm configuration (ANSSI recommendations)
    assert_eq!(
        crypt.config.symmetric_algorithm, 
        expected_params.symmetric_algorithm,
        "ANSSI standard should use AES-256-GCM symmetric algorithm, got {:?}",
        crypt.config.symmetric_algorithm
    );
    println!("✓ Symmetric algorithm correctly set to {:?} (ANSSI recommended)", expected_params.symmetric_algorithm);
    
    // Validate asymmetric algorithm configuration (ANSSI prefers ECC over RSA)
    assert_eq!(
        crypt.config.asymmetric_algorithm, 
        expected_params.asymmetric_algorithm,
        "ANSSI standard should prefer ECC asymmetric algorithm, got {:?}",
        crypt.config.asymmetric_algorithm
    );
    println!("✓ Asymmetric algorithm correctly set to {:?} (ANSSI prefers ECC over RSA)", expected_params.asymmetric_algorithm);
    
    // Validate RSA key size configuration (even though ECC is preferred, RSA size is specified for fallback)
    assert_eq!(
        crypt.config.rsa_key_size, 
        expected_params.rsa_key_size,
        "ANSSI standard should specify 3072-bit RSA keys for fallback scenarios, got {}",
        crypt.config.rsa_key_size
    );
    println!("✓ RSA key size correctly set to {} bits (ANSSI fallback specification)", expected_params.rsa_key_size);
    
    // Additional validation: ensure standard is preserved
    assert_eq!(
        crypt.config.standard,
        CryptoStandard::Anssi,
        "Standard should remain ANSSI after initialization"
    );
    println!("✓ ANSSI standard configuration validation completed successfully");
}
