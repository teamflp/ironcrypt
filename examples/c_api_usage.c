#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ironcrypt.h" // Include the header file

void check_result(int result, const char* message) {
    if (result == -1) {
        fprintf(stderr, "Error: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

int main() {
    // 1. Generate RSA keys
    char* private_key = NULL;
    char* public_key = NULL;
    printf("Generating 2048-bit RSA key pair...\n");
    int32_t result = ironcrypt_generate_rsa_keys(2048, &private_key, &public_key);
    check_result(result, "Failed to generate RSA keys.");

    printf("Generated Private Key:\n%s\n", private_key);
    printf("Generated Public Key:\n%s\n", public_key);

    // 2. Encrypt a password
    const char* password = "MySuperSecretPassword123!";
    const char* key_version = "v1";
    char* encrypted_json = NULL;

    printf("\nEncrypting password: '%s'\n", password);
    result = ironcrypt_password_encrypt(password, public_key, key_version, &encrypted_json);
    check_result(result, "Failed to encrypt password.");

    printf("Encrypted JSON payload:\n%s\n", encrypted_json);

    // 3. Verify the correct password
    printf("\nVerifying correct password...\n");
    result = ironcrypt_password_verify(encrypted_json, password, private_key, NULL);
    if (result == 1) {
        printf("Result: SUCCESS - Password is valid.\n");
    } else {
        fprintf(stderr, "Result: FAILURE - Correct password was not verified. Code: %d\n", result);
    }

    // 4. Verify an incorrect password
    const char* wrong_password = "WrongPassword!";
    printf("\nVerifying incorrect password: '%s'\n", wrong_password);
    result = ironcrypt_password_verify(encrypted_json, wrong_password, private_key, NULL);
    if (result == 0) {
        printf("Result: SUCCESS - Password is invalid, as expected.\n");
    } else {
        fprintf(stderr, "Result: FAILURE - Incorrect password was not rejected. Code: %d\n", result);
    }

    // 5. Clean up memory
    printf("\nCleaning up allocated strings...\n");
    ironcrypt_free_string(private_key);
    ironcrypt_free_string(public_key);
    ironcrypt_free_string(encrypted_json);
    printf("Cleanup complete.\n");

    return EXIT_SUCCESS;
}
