// tests/cli.rs

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;

#[test]
fn test_generate_keys() {
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("generate")
        .arg("-v")
        .arg("v_test")
        .arg("-d")
        .arg("test_keys_cli");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Clés RSA sauvegardées avec succès."));

    assert!(fs::metadata("test_keys_cli/private_key_v_test.pem").is_ok());
    assert!(fs::metadata("test_keys_cli/public_key_v_test.pem").is_ok());

    // Cleanup
    fs::remove_dir_all("test_keys_cli").unwrap();
}

#[test]
fn test_encrypt_decrypt_password() {
    // 1. Generate keys
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("generate")
        .arg("-v")
        .arg("v_test_enc")
        .arg("-d")
        .arg("test_keys_cli_enc");
    cmd.assert().success();

    // 2. Encrypt
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("encrypt")
        .arg("-w")
        .arg("MySuperSecretPassword123!")
        .arg("-d")
        .arg("test_keys_cli_enc")
        .arg("-v")
        .arg("v_test_enc");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Mot de passe chiffré dans 'encrypted_data.json'.",
        ));

    assert!(fs::metadata("encrypted_data.json").is_ok());

    // 3. Decrypt with correct password
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("decrypt")
        .arg("-w")
        .arg("MySuperSecretPassword123!")
        .arg("-k")
        .arg("test_keys_cli_enc")
        .arg("-v")
        .arg("v_test_enc")
        .arg("-f")
        .arg("encrypted_data.json");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Mot de passe correct."));

    // 4. Decrypt with incorrect password
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("decrypt")
        .arg("-w")
        .arg("WrongPassword")
        .arg("-k")
        .arg("test_keys_cli_enc")
        .arg("-v")
        .arg("v_test_enc")
        .arg("-f")
        .arg("encrypted_data.json");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Mot de passe invalide"));

    // Cleanup
    fs::remove_dir_all("test_keys_cli_enc").unwrap();
    fs::remove_file("encrypted_data.json").unwrap();
}

#[test]
fn test_encrypt_decrypt_file() {
    // 1. Generate keys
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("generate")
        .arg("-v")
        .arg("v_test_file")
        .arg("-d")
        .arg("test_keys_cli_file");
    cmd.assert().success();

    // 2. Create a dummy file to encrypt
    let file_content = "This is a test file for ironcrypt.";
    fs::write("test_file.txt", file_content).unwrap();

    // 3. Encrypt the file
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("encrypt-file")
        .arg("-i")
        .arg("test_file.txt")
        .arg("-o")
        .arg("test_file.enc")
        .arg("-d")
        .arg("test_keys_cli_file")
        .arg("-v")
        .arg("v_test_file");
    cmd.assert().success();
    assert!(fs::metadata("test_file.enc").is_ok());

    // 4. Decrypt the file
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("decrypt-file")
        .arg("-i")
        .arg("test_file.enc")
        .arg("-o")
        .arg("test_file.dec")
        .arg("-k")
        .arg("test_keys_cli_file")
        .arg("-v")
        .arg("v_test_file");
    cmd.assert().success();
    assert!(fs::metadata("test_file.dec").is_ok());

    // 5. Verify content
    let decrypted_content = fs::read_to_string("test_file.dec").unwrap();
    assert_eq!(file_content, decrypted_content);

    // Cleanup
    fs::remove_dir_all("test_keys_cli_file").unwrap();
    fs::remove_file("test_file.txt").unwrap();
    fs::remove_file("test_file.enc").unwrap();
    fs::remove_file("test_file.dec").unwrap();
}

#[test]
fn test_encrypt_decrypt_dir() {
    // 1. Generate keys
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("generate")
        .arg("-v")
        .arg("v_test_dir")
        .arg("-d")
        .arg("test_keys_cli_dir");
    cmd.assert().success();

    // 2. Create a dummy directory with a file
    let dir_to_encrypt = "test_dir_to_encrypt";
    fs::create_dir(dir_to_encrypt).unwrap();
    fs::write(format!("{}/test.txt", dir_to_encrypt), "hello from dir").unwrap();

    // 3. Encrypt the directory
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("encrypt-dir")
        .arg("-i")
        .arg(dir_to_encrypt)
        .arg("-o")
        .arg("test_dir.enc")
        .arg("-d")
        .arg("test_keys_cli_dir")
        .arg("-v")
        .arg("v_test_dir");
    cmd.assert().success();
    assert!(fs::metadata("test_dir.enc").is_ok());

    // 4. Decrypt the directory
    let output_dir = "test_dir_decrypted";
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("decrypt-dir")
        .arg("-i")
        .arg("test_dir.enc")
        .arg("-o")
        .arg(output_dir)
        .arg("-k")
        .arg("test_keys_cli_dir")
        .arg("-v")
        .arg("v_test_dir");
    cmd.assert().success();
    assert!(fs::metadata(output_dir).is_ok());
    assert!(fs::metadata(format!("{}/test.txt", output_dir)).is_ok());

    // 5. Verify content
    let decrypted_content = fs::read_to_string(format!("{}/test.txt", output_dir)).unwrap();
    assert_eq!("hello from dir", decrypted_content);

    // Cleanup
    fs::remove_dir_all("test_keys_cli_dir").unwrap();
    fs::remove_dir_all(dir_to_encrypt).unwrap();
    fs::remove_dir_all(output_dir).unwrap();
    fs::remove_file("test_dir.enc").unwrap();
}

#[test]
fn test_rotate_key() {
    let encrypted_file = "encrypted_data_rotate.json";
    // 1. Générer une clé v1
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("generate")
        .arg("-v")
        .arg("v1_rotate")
        .arg("-d")
        .arg("test_keys_rotate");
    cmd.assert().success();

    // 2. Chiffrer un mot de passe avec v1
    let password = "MyRotationP@ssw0rd";
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("encrypt")
        .arg("-w")
        .arg(password)
        .arg("-d")
        .arg("test_keys_rotate")
        .arg("-v")
        .arg("v1_rotate");

    cmd.assert().success(); // Crée encrypted_data.json

    // Rename the output file to avoid conflicts
    fs::rename("encrypted_data.json", encrypted_file).unwrap();

    // 3. Effectuer la rotation de la clé de v1 à v2
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("rotate-key")
        .arg("--old-version")
        .arg("v1_rotate")
        .arg("--new-version")
        .arg("v2_rotate")
        .arg("-k")
        .arg("test_keys_rotate")
        .arg("-f")
        .arg(encrypted_file);
    cmd.assert().success();

    // 4. Vérifier que la nouvelle clé v2 existe
    assert!(fs::metadata("test_keys_rotate/private_key_v2_rotate.pem").is_ok());

    // 5. Vérifier que le mot de passe peut être déchiffré avec la nouvelle clé v2
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("decrypt")
        .arg("-w")
        .arg(password)
        .arg("-k")
        .arg("test_keys_rotate")
        .arg("-v")
        .arg("v2_rotate")
        .arg("-f")
        .arg(encrypted_file);
    cmd.assert().success();

    // 6. Vérifier que le mot de passe ne peut plus être déchiffré avec l'ancienne clé v1
    let mut cmd = Command::cargo_bin("ironcrypt-cli").unwrap();
    cmd.arg("decrypt")
        .arg("-w")
        .arg(password)
        .arg("-k")
        .arg("test_keys_rotate")
        .arg("-v")
        .arg("v1_rotate")
        .arg("-f")
        .arg(encrypted_file);
    cmd.assert().failure();

    // Cleanup
    fs::remove_dir_all("test_keys_rotate").unwrap();
    fs::remove_file(encrypted_file).unwrap();
}
