// tests/cli.rs

use std::path::Path;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

const STRONG_PWD: &str = "Str0ngP@ssw0rd42!";
const WRONG_STRONG_PWD: &str = "Wr0ngP@ssw0rd!!"; // Fort mais différent

fn p(base: &Path, rel: &str) -> String {
    base.join(rel).to_string_lossy().into_owned()
}

#[test]
fn test_generate_keys() {
    let td = tempdir().unwrap();
    let cwd = td.path().to_path_buf();
    let keys_dir = p(&cwd, "test_keys_cli");

    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("generate")
        .arg("-v")
        .arg("v_test")
        .arg("-d")
        .arg(&keys_dir);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("RSA keys saved successfully."));

    assert!(fs::metadata(p(&cwd, "test_keys_cli/private_key_v_test.pem")).is_ok());
    assert!(fs::metadata(p(&cwd, "test_keys_cli/public_key_v_test.pem")).is_ok());
}

#[test]
fn test_encrypt_decrypt_password() {
    let td = tempdir().unwrap();
    let cwd = td.path().to_path_buf();
    let keys_dir = p(&cwd, "test_keys_cli_enc");

    // 1) Generate keys
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("generate")
        .arg("-v")
        .arg("v_test_enc")
        .arg("-d")
        .arg(&keys_dir);
    cmd.assert().success();

    // 2) Encrypt
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("encrypt")
        .arg("-w")
        .arg(STRONG_PWD)
        .arg("-d")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_enc");

    // Capture the output (which is the JSON) and write it to a file
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let encrypted_json_path = p(&cwd, "encrypted_data_cli.json");
    fs::write(&encrypted_json_path, output.stdout).unwrap();
    assert!(fs::metadata(&encrypted_json_path).is_ok());

    // 3) Decrypt with correct password
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("decrypt")
        .arg("-w")
        .arg(STRONG_PWD)
        .arg("-k")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_enc")
        .arg("-f")
        .arg(p(&cwd, "encrypted_data_cli.json"));
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Password correct."));

    // 4) Decrypt with incorrect password (mais fort)
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("decrypt")
        .arg("-w")
        .arg(WRONG_STRONG_PWD)
        .arg("-k")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_enc")
        .arg("-f")
        .arg(p(&cwd, "encrypted_data_cli.json"));

    cmd.assert().failure().stderr(
        predicate::str::contains("could not verify password")
            .or(predicate::str::contains("Invalid password")),
    );
}

#[test]
fn test_encrypt_decrypt_file() {
    let td = tempdir().unwrap();
    let cwd = td.path().to_path_buf();
    let keys_dir = p(&cwd, "test_keys_cli_file");

    // 1) Generate keys
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("generate")
        .arg("-v")
        .arg("v_test_file")
        .arg("-d")
        .arg(&keys_dir);
    cmd.assert().success();

    // 2) Create file
    let file_content = "This is a test file for ironcrypt.";
    fs::write(p(&cwd, "test_file.txt"), file_content).unwrap();

    // 3) Encrypt
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("encrypt-file")
        .arg("-i")
        .arg(p(&cwd, "test_file.txt"))
        .arg("-o")
        .arg(p(&cwd, "test_file.enc"))
        .arg("-d")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_file");
    cmd.assert().success();
    assert!(fs::metadata(p(&cwd, "test_file.enc")).is_ok());

    // 4) Decrypt
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("decrypt-file")
        .arg("-i")
        .arg(p(&cwd, "test_file.enc"))
        .arg("-o")
        .arg(p(&cwd, "test_file.dec"))
        .arg("-k")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_file");
    cmd.assert().success();
    assert!(fs::metadata(p(&cwd, "test_file.dec")).is_ok());

    // 5) Verify content
    let decrypted_content = fs::read_to_string(p(&cwd, "test_file.dec")).unwrap();
    assert_eq!(file_content, decrypted_content);
}

#[test]
fn test_encrypt_decrypt_dir() {
    let td = tempdir().unwrap();
    let cwd = td.path().to_path_buf();
    let keys_dir = p(&cwd, "test_keys_cli_dir");

    // 1) Generate keys
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("generate")
        .arg("-v")
        .arg("v_test_dir")
        .arg("-d")
        .arg(&keys_dir);
    cmd.assert().success();

    // 2) Create dir with file
    let dir_to_encrypt = p(&cwd, "test_dir_to_encrypt");
    fs::create_dir_all(&dir_to_encrypt).unwrap();
    fs::write(format!("{}/test.txt", dir_to_encrypt), "hello from dir").unwrap();
    assert!(fs::metadata(format!("{}/test.txt", dir_to_encrypt)).is_ok());

    // 3) Encrypt dir
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("encrypt-dir")
        .arg("-i")
        .arg(&dir_to_encrypt)
        .arg("-o")
        .arg(p(&cwd, "test_dir.enc"))
        .arg("-d")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_dir");
    cmd.assert().success();
    assert!(fs::metadata(p(&cwd, "test_dir.enc")).is_ok());

    // 4) Decrypt dir
    let output_dir = p(&cwd, "test_dir_decrypted");
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("decrypt-dir")
        .arg("-i")
        .arg(p(&cwd, "test_dir.enc"))
        .arg("-o")
        .arg(&output_dir)
        .arg("-k")
        .arg(&keys_dir)
        .arg("-v")
        .arg("v_test_dir");
    cmd.assert().success();
    assert!(fs::metadata(&output_dir).is_ok());
    assert!(fs::metadata(format!("{}/test.txt", &output_dir)).is_ok());

    // 5) Verify content
    let decrypted_content = fs::read_to_string(format!("{}/test.txt", &output_dir)).unwrap();
    assert_eq!("hello from dir", decrypted_content);
}

#[test]
fn test_rotate_key() {
    let td = tempdir().unwrap();
    let cwd = td.path().to_path_buf();
    let keys_dir = p(&cwd, "test_keys_rotate");
    let encrypted_file_path = p(&cwd, "encrypted_data_rotate.json");
    let v1 = "v1_rotate";
    let v2 = "v2_rotate";

    // 1) Generate v1
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("generate")
        .arg("-v")
        .arg(v1)
        .arg("-d")
        .arg(&keys_dir);
    cmd.assert().success();

    // 2) Encrypt with v1 and save output
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("encrypt")
        .arg("-w")
        .arg(STRONG_PWD)
        .arg("-d")
        .arg(&keys_dir)
        .arg("-v")
        .arg(v1);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    fs::write(&encrypted_file_path, output.stdout).unwrap();
    assert!(fs::metadata(&encrypted_file_path).is_ok());

    // 3) Rotate v1 -> v2
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("rotate-key")
        .arg("--old-version")
        .arg(v1)
        .arg("--new-version")
        .arg(v2)
        .arg("-k")
        .arg(&keys_dir)
        .arg("-f")
        .arg(&encrypted_file_path);
    cmd.assert().success();

    // 4) v2 keys exist
    assert!(fs::metadata(p(&cwd, "test_keys_rotate/private_key_v2_rotate.pem")).is_ok());
    assert!(fs::metadata(p(&cwd, "test_keys_rotate/public_key_v2_rotate.pem")).is_ok());

    // 5) Decrypt with v2 (success)
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("decrypt")
        .arg("-w")
        .arg(STRONG_PWD)
        .arg("-k")
        .arg(&keys_dir)
        .arg("-v")
        .arg(v2)
        .arg("-f")
        .arg(&encrypted_file_path);
    cmd.assert().success();

    // 6) Decrypt with v1 (should fail)
    let mut cmd = Command::cargo_bin("ironcrypt").unwrap();
    cmd.current_dir(&cwd)
        .arg("decrypt")
        .arg("-w")
        .arg(STRONG_PWD)
        .arg("-k")
        .arg(&keys_dir)
        .arg("-v")
        .arg(v1)
        .arg("-f")
        .arg(&encrypted_file_path);
    cmd.assert().failure();
}
