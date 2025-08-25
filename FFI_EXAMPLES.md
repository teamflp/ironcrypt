# IronCrypt FFI Usage Examples

This document provides examples of how to use the `ironcrypt` C-style API from various programming languages.

## Prerequisites

You must have a compiled dynamic library of `ironcrypt` (`libironcrypt.so` on Linux, `libironcrypt.dylib` on macOS, or `ironcrypt.dll` on Windows). You can compile it by running `cargo build --release` in the project root.

The C header file `ironcrypt.h` is also required for reference.

---

## Python (ctypes)

This example uses the built-in `ctypes` library to call the C functions.

```python
import ctypes
import os
import platform

# --- 1. Load the library ---
def get_lib_path():
    """Determines the path to the dynamic library based on the OS."""
    lib_name = ""
    if platform.system() == "Linux":
        lib_name = "libironcrypt.so"
    elif platform.system() == "Darwin": # macOS
        lib_name = "libironcrypt.dylib"
    elif platform.system() == "Windows":
        lib_name = "ironcrypt.dll"
    else:
        raise Exception(f"Unsupported OS: {platform.system()}")

    # Assumes the library is in target/release relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "target/release", lib_name)

lib_path = get_lib_path()
if not os.path.exists(lib_path):
    raise FileNotFoundError(f"Library not found at {lib_path}. Please compile with 'cargo build --release'.")

lib = ctypes.CDLL(lib_path)

# --- 2. Define function signatures ---
# ironcrypt_generate_rsa_keys
lib.ironcrypt_generate_rsa_keys.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.ironcrypt_generate_rsa_keys.restype = ctypes.c_int32

# ironcrypt_password_encrypt
lib.ironcrypt_password_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
lib.ironcrypt_password_encrypt.restype = ctypes.c_int32

# ironcrypt_password_verify
lib.ironcrypt_password_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.ironcrypt_password_verify.restype = ctypes.c_int32

# ironcrypt_free_string
lib.ironcrypt_free_string.argtypes = [ctypes.c_void_p] # Use c_void_p for broader compatibility
lib.ironcrypt_free_string.restype = None

# --- 3. Use the functions ---
print("--- Python ctypes Example ---")

# Generate keys
private_key_ptr = ctypes.c_char_p()
public_key_ptr = ctypes.c_char_p()
print("Generating keys...")
result = lib.ironcrypt_generate_rsa_keys(2048, ctypes.byref(private_key_ptr), ctypes.byref(public_key_ptr))
if result != 0:
    raise Exception("Key generation failed")

private_key = private_key_ptr.value.decode('utf-8')
public_key = public_key_ptr.value.decode('utf-8')
print(f"Generated Public Key length: {len(public_key)}")

# Encrypt password
password = b"PythonistasSecret123!"
key_version = b"v1-python"
encrypted_json_ptr = ctypes.c_char_p()
print("\nEncrypting password...")
result = lib.ironcrypt_password_encrypt(password, public_key.encode('utf-8'), key_version, ctypes.byref(encrypted_json_ptr))
if result != 0:
    raise Exception("Password encryption failed")

encrypted_json = encrypted_json_ptr.value.decode('utf-8')
print(f"Encrypted JSON length: {len(encrypted_json)}")

# Verify correct password
print("\nVerifying correct password...")
result = lib.ironcrypt_password_verify(encrypted_json.encode('utf-8'), password, private_key.encode('utf-8'), None)
print(f"Verification result: {'OK' if result == 1 else 'FAIL'}")

# Verify incorrect password
print("\nVerifying incorrect password...")
wrong_password = b"NotThePassword"
result = lib.ironcrypt_password_verify(encrypted_json.encode('utf-8'), wrong_password, private_key.encode('utf-8'), None)
print(f"Verification result: {'OK (rejected)' if result == 0 else 'FAIL'}")

# --- 4. Free memory ---
print("\nCleaning up memory...")
lib.ironcrypt_free_string(private_key_ptr)
lib.ironcrypt_free_string(public_key_ptr)
lib.ironcrypt_free_string(encrypted_json_ptr)
print("Done.")
```

---

## Java (JNA)

This example requires the [JNA](https://github.com/java-native-access/jna) library. You would need to add `jna.jar` and `jna-platform.jar` to your classpath.

**`pom.xml` dependency:**
```xml
<dependencies>
    <dependency>
        <groupId>net.java.dev.jna</groupId>
        <artifactId>jna</artifactId>
        <version>5.12.1</version>
    </dependency>
</dependencies>
```

**Java code:**
```java
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public class IronCryptJNAExample {

    public interface IronCryptLib extends Library {
        // Load the native library.
        // On Linux, this will look for "libironcrypt.so"
        // On Windows, "ironcrypt.dll"
        // On macOS, "libironcrypt.dylib"
        IronCryptLib INSTANCE = Native.load("ironcrypt", IronCryptLib.class);

        // Define function mappings
        int ironcrypt_generate_rsa_keys(int bits, PointerByReference private_key_pem, PointerByReference public_key_pem);
        void ironcrypt_free_string(Pointer s);
        int ironcrypt_password_encrypt(String password, String public_key_pem, String key_version, PointerByReference encrypted_output);
        int ironcrypt_password_verify(String encrypted_json, String password, String private_key_pem, String passphrase);
    }

    public static void main(String[] args) {
        System.out.println("--- Java JNA Example ---");

        // Set jna.library.path if the library is not in a standard location.
        // For example, if running from the project root:
        // System.setProperty("jna.library.path", "target/release");

        // 1. Generate keys
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

        // 2. Encrypt password
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

        // 3. Verify passwords
        System.out.println("\nVerifying correct password...");
        result = IronCryptLib.INSTANCE.ironcrypt_password_verify(encrypted_json, password, private_key, null);
        System.out.println("Verification result: " + (result == 1 ? "OK" : "FAIL"));

        System.out.println("\nVerifying incorrect password...");
        String wrong_password = "NotThePassword";
        result = IronCryptLib.INSTANCE.ironcrypt_password_verify(encrypted_json, wrong_password, private_key, null);
        System.out.println("Verification result: " + (result == 0 ? "OK (rejected)" : "FAIL"));

        // 4. Free memory
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

This example uses the standard P/Invoke mechanism in .NET.

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

public class IronCryptExample
{
    // The name of the library as it will be found by the dynamic linker.
    // On Linux, it will look for "libironcrypt.so".
    // On Windows, "ironcrypt.dll".
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

        // 1. Generate keys
        Console.WriteLine("Generating keys...");
        int result = ironcrypt_generate_rsa_keys(2048, out IntPtr private_key_ptr, out IntPtr public_key_ptr);
        if (result != 0) throw new Exception("Key generation failed");

        string privateKey = Marshal.PtrToStringAnsi(private_key_ptr);
        string publicKey = Marshal.PtrToStringAnsi(public_key_ptr);
        Console.WriteLine($"Public Key length: {publicKey.Length}");

        // 2. Encrypt password
        Console.WriteLine("\nEncrypting password...");
        string password = "CSharpSecretPassword123!";
        string keyVersion = "v1-csharp";
        result = ironcrypt_password_encrypt(password, publicKey, keyVersion, out IntPtr encrypted_json_ptr);
        if (result != 0) throw new Exception("Password encryption failed");

        string encryptedJson = Marshal.PtrToStringAnsi(encrypted_json_ptr);
        Console.WriteLine($"Encrypted JSON length: {encryptedJson.Length}");

        // 3. Verify passwords
        Console.WriteLine("\nVerifying correct password...");
        result = ironcrypt_password_verify(encryptedJson, password, privateKey, null);
        Console.WriteLine($"Verification result: {(result == 1 ? "OK" : "FAIL")}");

        Console.WriteLine("\nVerifying incorrect password...");
        string wrongPassword = "NotThePassword";
        result = ironcrypt_password_verify(encryptedJson, wrongPassword, privateKey, null);
        Console.WriteLine($"Verification result: {(result == 0 ? "OK (rejected)" : "FAIL")}");

        // 4. Free memory
        Console.WriteLine("\nCleaning up memory...");
        ironcrypt_free_string(private_key_ptr);
        ironcrypt_free_string(public_key_ptr);
        ironcrypt_free_string(encrypted_json_ptr);
        Console.WriteLine("Done.");
    }
}
```
