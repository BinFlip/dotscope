# StringsEncryption

| Property | Value |
|----------|-------|
| **Protection** | `StringsEncryption` |
| **Class** | `Protection` |
| **Category** | Value (string encryption) |
| **Targets** | Method instructions (`ldstr`) |
| **Attributes** | `[DoNotResolve(MemberInclusionFlags.SpecialRuntime)]` |
| **Dependencies** | `Renamer` (for naming injected members) |
| **Runtime** | `BitMono.Runtime.Decryptor`, `BitMono.Runtime.Data` |

## Overview

Encrypts all string literals using AES-256-CBC with PBKDF2 key derivation. Each `ldstr` instruction is replaced with a sequence that loads the encrypted bytes and calls a runtime decryptor method. The encryption keys are injected as static byte array fields in the module type.

## Algorithm

### Encryption (Obfuscation Time)

Uses `BitMono.Runtime.Encryptor.EncryptContent()`:

```csharp
var aes = new RijndaelManaged { KeySize = 256, BlockSize = 128, Mode = CipherMode.CBC };
var key = new Rfc2898DeriveBytes(saltBytes, cryptKeyBytes, 1000);
aes.Key = key.GetBytes(32);  // 256-bit key
aes.IV = key.GetBytes(16);   // 128-bit IV
// Encrypt string bytes with AES-CBC
```

### Decryption (Runtime)

Uses `BitMono.Runtime.Decryptor.Decrypt()`:

```csharp
var aes = new RijndaelManaged { KeySize = 256, BlockSize = 128, Mode = CipherMode.CBC };
var key = new Rfc2898DeriveBytes(cryptKeyBytes, saltBytes, 1000);
aes.Key = key.GetBytes(32);
aes.IV = key.GetBytes(16);
// Decrypt bytes, return UTF-8 string
```

### Key Material

`Data.cs` initializes both `CryptKeyBytes` and `SaltBytes` to `new byte[8]` (all zeros). These have never been randomized across the entire git history of BitMono. The arrays are injected as FieldRVA data into the target assembly.

Since both arrays are always all-zero, the AES key derived via `Rfc2898DeriveBytes(zeros, zeros, 1000)` is **deterministic and identical for every BitMono-protected assembly**.

The parameter order is swapped between `Encryptor` and `Decryptor` (`Rfc2898DeriveBytes(saltBytes, cryptKeyBytes)` vs `Rfc2898DeriveBytes(cryptKeyBytes, saltBytes)`). This works because both arrays contain the same all-zero values, so the derived key is identical regardless of parameter order.

## IL Transformation

```
// Before:
ldstr      "hello"

// After:
ldsfld     byte[] <encrypted_data_field>     // Per-string encrypted byte array (FieldRVA)
ldsfld     byte[] <salt_field>               // Shared salt bytes (8 zero bytes)
ldsfld     byte[] <crypt_key_field>          // Shared crypt key bytes (8 zero bytes)
call       string Decryptor::Decrypt(byte[], byte[], byte[])
```

## Injected Artifacts

1. **Decryptor type** — Cloned from `BitMono.Runtime.Decryptor` into `<Module>`, renamed with word pool
2. **Nested value types** — `ExplicitLayout` types holding FieldRVA data for each encrypted byte array
3. **Salt field** — `byte[]` field in `<Module>` with FieldRVA data (8 zero bytes)
4. **CryptKey field** — `byte[]` field in `<Module>` with FieldRVA data (8 zero bytes)
5. **Per-string data fields** — One `byte[]` field per encrypted string constant

All injected names use `Renamer.RenameUnsafely()` — random words from the `RandomStrings` pool, producing names with spaces.

## Detection Signatures

- Static method with signature `string(byte[], byte[], byte[])` in `<Module>` that references `RijndaelManaged`/`Aes` + `Rfc2898DeriveBytes` + `CryptoStream`
- Call pattern: `ldsfld byte[]` + `ldsfld byte[]` + `ldsfld byte[]` + `call Decrypt` replacing original `ldstr`
- Multiple nested `ExplicitLayout` value types in `<Module>` (FieldRVA containers)
- Two 8-byte FieldRVA fields that are all zeros (key and salt)

## dotscope Handling

Handled by `BitMonoStrings` technique (detection) and `StringDecryptionPass` (reversal). The pass derives the PBKDF2 key material from the salt/key fields and performs static AES-256-CBC decryption. Requires the `legacy-crypto` feature flag.
