# IronCrypt — FFI (API C)

Ce document explique comment appeler IronCrypt **en process** depuis un autre langage, via la bibliothèque dynamique et l’en-tête C [`ironcrypt.h`](ironcrypt.h).

Contrairement au [SDK PHP HTTP](sdks/php/README.md) (qui parle à `ironcryptd`), le FFI **charge `libironcrypt` dans le même processus** : pas de démon, pas de Bearer — vous passez les PEM vous‑même.

```text
┌──────────────────┐     appel natif (C ABI)     ┌─────────────────────┐
│ Python / Java /  │ ──────────────────────────► │ libironcrypt(.so/    │
│ C# / C / PHP FFI │   ironcrypt_*.c             │  .dylib / .dll)     │
└──────────────────┘                             └─────────────────────┘
```

## Quand utiliser le FFI ?

| Approche | Intérêt |
| --- | --- |
| **HTTP + `ironcryptd`** ([`sdks/php`](sdks/php/), [`sdks/python`](sdks/python/)) | Apps web, microservices, clés centralisées, permissions API |
| **FFI / `cdylib`** (ce guide) | CLI natives, services sans HTTP, intégration JVM/.NET/C, latence minimale |
| **Crate Rust** | Applications Rust (`encrypt_stream`, etc.) |

**Portée actuelle de l’API C :** workflow **mots de passe** (hash Argon2 + enveloppe RSA) — génération de clés, chiffrement, vérification. Le chiffrement de fichiers / streaming reste côté CLI, crate Rust, ou démon HTTP (`/write` / `/read`).

## Fonctions exposées (`ironcrypt.h`)

| Fonction | Retour | Rôle |
| --- | --- | --- |
| `ironcrypt_generate_rsa_keys(bits, &priv, &pub)` | `0` ok, `-1` erreur | Génère une paire RSA (PEM PKCS#8 / SPKI) |
| `ironcrypt_password_encrypt(password, pub_pem, version, &out)` | `0` ok, `-1` erreur | Produit le JSON chiffré (hash Argon2 encapsulé) |
| `ironcrypt_password_verify(json, password, priv_pem, passphrase)` | `1` valide, `0` invalide, `-1` erreur | Vérifie un mot de passe |
| `ironcrypt_free_string(ptr)` | — | **Obligatoire** pour toute chaîne allouée par Rust |

Règles mémoire :

- Toute `char*` remplie par la lib **doit** être libérée avec `ironcrypt_free_string`.
- Ne pas utiliser `free()` du C standard sur ces pointeurs.
- `passphrase` peut être `NULL` si la clé privée n’est pas protégée.

## Compiler la bibliothèque

```bash
# À la racine du dépôt (Cargo.toml : crate-type = ["lib", "cdylib"])
cargo build --release
```

Artefacts typiques :

| OS | Fichier |
| --- | --- |
| Linux | `target/release/libironcrypt.so` |
| macOS | `target/release/libironcrypt.dylib` |
| Windows | `target/release/ironcrypt.dll` |

En-tête de référence : [`ironcrypt.h`](ironcrypt.h).  
Exemple C natif : [`examples/c_api_usage.c`](examples/c_api_usage.c).

### Compiler / lancer l’exemple C

```bash
# Linux
cc -O2 examples/c_api_usage.c -o c_api_usage \
  -I. -L target/release -lironcrypt -Wl,-rpath,$PWD/target/release
./c_api_usage

# macOS
cc -O2 examples/c_api_usage.c -o c_api_usage \
  -I. -L target/release -lironcrypt -Wl,-rpath,@loader_path/target/release
./c_api_usage
```

---

## Python (ctypes)

Utilise la bibliothèque standard `ctypes` (pas de dépendance extra).

```python
import ctypes
import os
import platform

# --- 1. Load the library ---
def get_lib_path():
    """Determines the path to the dynamic library based on the OS."""
    if platform.system() == "Linux":
        lib_name = "libironcrypt.so"
    elif platform.system() == "Darwin":  # macOS
        lib_name = "libironcrypt.dylib"
    elif platform.system() == "Windows":
        lib_name = "ironcrypt.dll"
    else:
        raise Exception(f"Unsupported OS: {platform.system()}")

    # Assumes the library is in target/release relative to the project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "target/release", lib_name)

lib_path = get_lib_path()
if not os.path.exists(lib_path):
    raise FileNotFoundError(
        f"Library not found at {lib_path}. Please compile with 'cargo build --release'."
    )

lib = ctypes.CDLL(lib_path)

# --- 2. Define function signatures ---
lib.ironcrypt_generate_rsa_keys.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_char_p),
]
lib.ironcrypt_generate_rsa_keys.restype = ctypes.c_int32

lib.ironcrypt_password_encrypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p),
]
lib.ironcrypt_password_encrypt.restype = ctypes.c_int32

lib.ironcrypt_password_verify.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.ironcrypt_password_verify.restype = ctypes.c_int32

lib.ironcrypt_free_string.argtypes = [ctypes.c_void_p]
lib.ironcrypt_free_string.restype = None

# --- 3. Use the functions ---
print("--- Python ctypes Example ---")

private_key_ptr = ctypes.c_char_p()
public_key_ptr = ctypes.c_char_p()
print("Generating keys...")
result = lib.ironcrypt_generate_rsa_keys(
    2048, ctypes.byref(private_key_ptr), ctypes.byref(public_key_ptr)
)
if result != 0:
    raise Exception("Key generation failed")

private_key = private_key_ptr.value.decode("utf-8")
public_key = public_key_ptr.value.decode("utf-8")
print(f"Generated Public Key length: {len(public_key)}")

password = b"PythonistasSecret123!"
key_version = b"v1-python"
encrypted_json_ptr = ctypes.c_char_p()
print("\nEncrypting password...")
result = lib.ironcrypt_password_encrypt(
    password,
    public_key.encode("utf-8"),
    key_version,
    ctypes.byref(encrypted_json_ptr),
)
if result != 0:
    raise Exception("Password encryption failed")

encrypted_json = encrypted_json_ptr.value.decode("utf-8")
print(f"Encrypted JSON length: {len(encrypted_json)}")

print("\nVerifying correct password...")
result = lib.ironcrypt_password_verify(
    encrypted_json.encode("utf-8"), password, private_key.encode("utf-8"), None
)
print(f"Verification result: {'OK' if result == 1 else 'FAIL'}")

print("\nVerifying incorrect password...")
wrong_password = b"NotThePassword"
result = lib.ironcrypt_password_verify(
    encrypted_json.encode("utf-8"),
    wrong_password,
    private_key.encode("utf-8"),
    None,
)
print(f"Verification result: {'OK (rejected)' if result == 0 else 'FAIL'}")

print("\nCleaning up memory...")
lib.ironcrypt_free_string(private_key_ptr)
lib.ironcrypt_free_string(public_key_ptr)
lib.ironcrypt_free_string(encrypted_json_ptr)
print("Done.")
```

---

## Java (JNA)

Nécessite [JNA](https://github.com/java-native-access/jna) (`jna` + éventuellement `jna-platform` sur le classpath).

**Dépendance `pom.xml` :**

```xml
<dependencies>
    <dependency>
        <groupId>net.java.dev.jna</groupId>
        <artifactId>jna</artifactId>
        <version>5.12.1</version>
    </dependency>
</dependencies>
```

**Code Java :**

```java
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public class IronCryptJNAExample {

    public interface IronCryptLib extends Library {
        // Linux: libironcrypt.so — Windows: ironcrypt.dll — macOS: libironcrypt.dylib
        IronCryptLib INSTANCE = Native.load("ironcrypt", IronCryptLib.class);

        int ironcrypt_generate_rsa_keys(int bits, PointerByReference private_key_pem, PointerByReference public_key_pem);
        void ironcrypt_free_string(Pointer s);
        int ironcrypt_password_encrypt(String password, String public_key_pem, String key_version, PointerByReference encrypted_output);
        int ironcrypt_password_verify(String encrypted_json, String password, String private_key_pem, String passphrase);
    }

    public static void main(String[] args) {
        System.out.println("--- Java JNA Example ---");

        // Si la lib n'est pas dans le chemin système :
        // System.setProperty("jna.library.path", "target/release");

        System.out.println("Generating keys...");
        PointerByReference private_key_ref = new PointerByReference();
        PointerByReference public_key_ref = new PointerByReference();
        int result = IronCryptLib.INSTANCE.ironcrypt_generate_rsa_keys(2048, private_key_ref, public_key_ref);
        if (result != 0) {
            throw new RuntimeException("Key generation failed");
        }

        Pointer private_key_ptr = private_key_ref.getValue();
        Pointer public_key_ptr = public_key_ref.getValue();
        String private_key = private_key_ptr.getString(0);
        String public_key = public_key_ptr.getString(0);
        System.out.println("Generated Public Key length: " + public_key.length());

        System.out.println("\nEncrypting password...");
        String password = "JavasSecretPassword123!";
        String key_version = "v1-java";
        PointerByReference encrypted_json_ref = new PointerByReference();
        result = IronCryptLib.INSTANCE.ironcrypt_password_encrypt(password, public_key, key_version, encrypted_json_ref);
        if (result != 0) {
            throw new RuntimeException("Password encryption failed");
        }
        Pointer encrypted_json_ptr = encrypted_json_ref.getValue();
        String encrypted_json = encrypted_json_ptr.getString(0);
        System.out.println("Encrypted JSON length: " + encrypted_json.length());

        System.out.println("\nVerifying correct password...");
        result = IronCryptLib.INSTANCE.ironcrypt_password_verify(encrypted_json, password, private_key, null);
        System.out.println("Verification result: " + (result == 1 ? "OK" : "FAIL"));

        System.out.println("\nVerifying incorrect password...");
        result = IronCryptLib.INSTANCE.ironcrypt_password_verify(encrypted_json, "NotThePassword", private_key, null);
        System.out.println("Verification result: " + (result == 0 ? "OK (rejected)" : "FAIL"));

        System.out.println("\nCleaning up memory...");
        IronCryptLib.INSTANCE.ironcrypt_free_string(private_key_ptr);
        IronCryptLib.INSTANCE.ironcrypt_free_string(public_key_ptr);
        IronCryptLib.INSTANCE.ironcrypt_free_string(encrypted_json_ptr);
        System.out.println("Done.");
    }
}
```

---

## C# (P/Invoke)

```csharp
using System;
using System.Runtime.InteropServices;

public class IronCryptExample
{
    // Linux: libironcrypt.so — Windows: ironcrypt.dll — macOS: libironcrypt.dylib
    private const string LibName = "ironcrypt";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ironcrypt_generate_rsa_keys(uint bits, out IntPtr private_key_pem, out IntPtr public_key_pem);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void ironcrypt_free_string(IntPtr s);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int ironcrypt_password_encrypt(string password, string public_key_pem, string key_version, out IntPtr encrypted_output);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int ironcrypt_password_verify(string encrypted_json, string password, string private_key_pem, string passphrase);

    public static void Main(string[] args)
    {
        Console.WriteLine("--- C# P/Invoke Example ---");

        Console.WriteLine("Generating keys...");
        int result = ironcrypt_generate_rsa_keys(2048, out IntPtr private_key_ptr, out IntPtr public_key_ptr);
        if (result != 0) throw new Exception("Key generation failed");

        string privateKey = Marshal.PtrToStringAnsi(private_key_ptr);
        string publicKey = Marshal.PtrToStringAnsi(public_key_ptr);
        Console.WriteLine($"Public Key length: {publicKey.Length}");

        Console.WriteLine("\nEncrypting password...");
        string password = "CSharpSecretPassword123!";
        string keyVersion = "v1-csharp";
        result = ironcrypt_password_encrypt(password, publicKey, keyVersion, out IntPtr encrypted_json_ptr);
        if (result != 0) throw new Exception("Password encryption failed");

        string encryptedJson = Marshal.PtrToStringAnsi(encrypted_json_ptr);
        Console.WriteLine($"Encrypted JSON length: {encryptedJson.Length}");

        Console.WriteLine("\nVerifying correct password...");
        result = ironcrypt_password_verify(encryptedJson, password, privateKey, null);
        Console.WriteLine($"Verification result: {(result == 1 ? "OK" : "FAIL")}");

        Console.WriteLine("\nVerifying incorrect password...");
        result = ironcrypt_password_verify(encryptedJson, "NotThePassword", privateKey, null);
        Console.WriteLine($"Verification result: {(result == 0 ? "OK (rejected)" : "FAIL")}");

        Console.WriteLine("\nCleaning up memory...");
        ironcrypt_free_string(private_key_ptr);
        ironcrypt_free_string(public_key_ptr);
        ironcrypt_free_string(encrypted_json_ptr);
        Console.WriteLine("Done.");
    }
}
```

Placez `libironcrypt` à côté de l’exécutable ou dans le chemin de recherche du chargeur dynamique (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, ou répertoire de l’app).

---

## PHP (extension FFI)

Pour du chiffrement de **fichiers / flux** en PHP, préférez le [SDK HTTP](sdks/php/README.md).  
L’API C actuelle cible surtout les **mots de passe** ; avec l’extension [`ffi`](https://www.php.net/manual/en/book.ffi.php) :

```php
<?php
$ffi = FFI::cdef('
    int32_t ironcrypt_generate_rsa_keys(uint32_t bits, char **private_key_pem, char **public_key_pem);
    int32_t ironcrypt_password_encrypt(const char *password, const char *public_key_pem, const char *key_version, char **encrypted_output);
    int32_t ironcrypt_password_verify(const char *encrypted_json, const char *password, const char *private_key_pem, const char *passphrase);
    void ironcrypt_free_string(char *s);
', 'target/release/libironcrypt.dylib'); // .so sous Linux

$priv = FFI::new('char*');
$pub = FFI::new('char*');
if ($ffi->ironcrypt_generate_rsa_keys(2048, FFI::addr($priv), FFI::addr($pub)) !== 0) {
    throw new RuntimeException('keygen failed');
}
// … encrypt / verify, puis :
$ffi->ironcrypt_free_string($priv);
$ffi->ironcrypt_free_string($pub);
```

Activez `ffi.enable=true` (ou `preload`) dans `php.ini`. Gérez les fuites : toujours `ironcrypt_free_string`.

---

## Bonnes pratiques

- Ne loggez jamais les PEM privés ni les mots de passe en clair.
- Appelez **toujours** `ironcrypt_free_string` (y compris après une erreur partielle si un pointeur a été alloué).
- Alignez la version de `libironcrypt` avec celle de `ironcrypt.h` (rebuild après `git pull`).
- Pour plusieurs services / permissions / gros fichiers : utilisez plutôt **`ironcryptd`**.

## Dépannage

| Symptôme | Cause probable |
| --- | --- |
| `Library not found` / `UnsatisfiedLinkError` | `cargo build --release` manquant, ou mauvais `jna.library.path` / `LD_LIBRARY_PATH` |
| Crash / double free | `free()` C au lieu de `ironcrypt_free_string`, ou double free |
| Verify retourne `-1` | JSON invalide, mauvaise clé, ou passphrase incorrecte |
| Verify retourne `0` | Mot de passe incorrect (comportement attendu) |
| Besoin de chiffrer un fichier depuis PHP | Utiliser [`sdks/php`](sdks/php/) + démon, pas cette API C |
