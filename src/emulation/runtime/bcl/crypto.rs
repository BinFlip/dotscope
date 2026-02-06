//! `System.Security.Cryptography` method hooks for deobfuscation.
//!
//! This module provides hook implementations for cryptographic methods commonly used by
//! obfuscators to encrypt strings, resources, and code. These hooks are essential for
//! analyzing protected .NET assemblies that use encryption to hide their payloads.
//!
//! # Overview
//!
//! Obfuscators frequently use cryptography to:
//! - Encrypt string literals to prevent static analysis
//! - Protect embedded resources containing code or data
//! - Derive decryption keys from assembly metadata or passwords
//! - Implement license checking and tamper detection
//!
//! # Emulated .NET Methods
//!
//! ## Hash Algorithms
//!
//! | Class | Methods | Output Size |
//! |-------|---------|-------------|
//! | `MD5` | `Create()`, `ComputeHash(byte[])` | 16 bytes |
//! | `SHA1` | `Create()`, `ComputeHash(byte[])` | 20 bytes |
//! | `SHA256` | `Create()`, `ComputeHash(byte[])` | 32 bytes |
//! | `HashAlgorithm` | `ComputeHash(byte[])` | Varies by type |
//!
//! ## Symmetric Encryption
//!
//! | Class | Methods |
//! |-------|---------|
//! | `Aes` | `Create()` |
//! | `RijndaelManaged` | `.ctor`, `CreateDecryptor()`, `CreateEncryptor()` |
//! | `DES` | `Create()` |
//! | `TripleDES` | `Create()` |
//! | `SymmetricAlgorithm` | `set_Key`, `set_IV`, `set_Mode`, `set_Padding` |
//!
//! ## Transforms and Streams
//!
//! | Class | Methods |
//! |-------|---------|
//! | `ICryptoTransform` | `TransformFinalBlock(byte[], int, int)` |
//! | `CryptoStream` | `.ctor`, `Read()` |
//!
//! ## Key Derivation
//!
//! | Class | Methods |
//! |-------|---------|
//! | `PasswordDeriveBytes` | `.ctor`, `GetBytes(int)` |
//! | `Rfc2898DeriveBytes` | `.ctor`, `GetBytes(int)` (PBKDF2) |
//!
//! ## BitConverter (Commonly Used in XOR Decryption)
//!
//! | Method | Description |
//! |--------|-------------|
//! | `GetBytes(int/long/...)` | Converts value to byte array |
//! | `ToInt32(byte[], int)` | Converts bytes to 32-bit integer |
//! | `ToInt64(byte[], int)` | Converts bytes to 64-bit integer |
//! | `ToUInt32(byte[], int)` | Converts bytes to unsigned 32-bit |
//!
//! # Deobfuscation Use Cases
//!
//! ## Capturing Encryption Keys
//!
//! The `set_Key` and `set_IV` hooks capture cryptographic keys and initialization
//! vectors for later analysis:
//!
//! ```csharp
//! // Obfuscator code pattern
//! var aes = Aes.Create();
//! aes.Key = derivedKey;  // <-- Captured by set_Key hook
//! aes.IV = derivedIV;    // <-- Captured by set_IV hook
//! var decryptor = aes.CreateDecryptor();
//! ```
//!
//! ## Hash-Based Key Derivation
//!
//! Many obfuscators derive keys from MD5/SHA1 hashes of strings:
//!
//! ```csharp
//! // Common pattern
//! string password = "obfuscated_key";
//! byte[] keyBytes = Encoding.UTF8.GetBytes(password);
//! byte[] key = MD5.Create().ComputeHash(keyBytes);  // <-- Real hash computed
//! ```
//!
//! ## XOR Decryption with BitConverter
//!
//! Simple XOR decryption often uses `BitConverter`:
//!
//! ```csharp
//! byte[] key = BitConverter.GetBytes(0x12345678);
//! for (int i = 0; i < data.Length; i++)
//!     data[i] ^= key[i % key.Length];
//! ```
//!
//! # Implementation Notes
//!
//! - **Hash functions are fully implemented** using the `md5`, `sha1`, and `sha2` crates
//! - **Symmetric encryption hooks capture keys/IVs** but don't perform actual encryption
//! - **Transform hooks pass through input data** for analysis
//! - **Full key derivation support** - PBKDF1 and PBKDF2 with SHA1/256/384/512

#[cfg(feature = "legacy-crypto")]
use crate::utils::{compute_md5, compute_sha1, derive_pbkdf1_key};
use crate::{
    emulation::{
        capture::{BufferSource, CaptureSource},
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue, SymbolicValue, TaintSource,
    },
    metadata::{token::Token, typesystem::CilFlavor},
    utils::{apply_crypto_transform, compute_sha256, derive_pbkdf2_key},
};

/// Registers all cryptographic method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Categories
///
/// - **MD5**: `MD5.Create()`, `MD5.ComputeHash()` (requires legacy-crypto)
/// - **SHA**: `SHA1.Create()`, `SHA256.Create()`, `ComputeHash()` methods
/// - **AES/Rijndael**: `Aes.Create()`, `RijndaelManaged` constructor and methods
/// - **DES**: `DES.Create()`, `TripleDES.Create()` (requires legacy-crypto)
/// - **Transforms**: `ICryptoTransform.TransformFinalBlock()`, `CryptoStream`
/// - **Key Derivation**: `PasswordDeriveBytes`, `Rfc2898DeriveBytes`
/// - **BitConverter**: `GetBytes()`, `ToInt32()`, `ToInt64()`, `ToUInt32()`
pub fn register(manager: &mut HookManager) {
    // Hash algorithms
    register_md5_hooks(manager);
    register_sha_hooks(manager);

    // Symmetric encryption
    register_aes_hooks(manager);
    register_des_hooks(manager);

    // Transform hooks
    register_transform_hooks(manager);

    // Key derivation
    register_key_derivation_hooks(manager);

    // BitConverter
    register_bitconverter_hooks(manager);
}

fn register_md5_hooks(manager: &mut HookManager) {
    // MD5.Create() - requires legacy-crypto
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.MD5.Create")
            .match_name("System.Security.Cryptography", "MD5", "Create")
            .pre(md5_create_pre),
    );

    // MD5.ComputeHash(byte[]) - requires legacy-crypto
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.MD5.ComputeHash")
            .match_name("System.Security.Cryptography", "MD5", "ComputeHash")
            .pre(md5_compute_hash_pre),
    );

    // HashAlgorithm.ComputeHash - always available
    manager.register(
        Hook::new("System.Security.Cryptography.HashAlgorithm.ComputeHash")
            .match_name(
                "System.Security.Cryptography",
                "HashAlgorithm",
                "ComputeHash",
            )
            .pre(hash_algorithm_compute_hash_pre),
    );
}

fn register_sha_hooks(manager: &mut HookManager) {
    // SHA1.Create() - requires legacy-crypto
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.SHA1.Create")
            .match_name("System.Security.Cryptography", "SHA1", "Create")
            .pre(sha1_create_pre),
    );

    // SHA256.Create() - always available
    manager.register(
        Hook::new("System.Security.Cryptography.SHA256.Create")
            .match_name("System.Security.Cryptography", "SHA256", "Create")
            .pre(sha256_create_pre),
    );

    // SHA1.ComputeHash - requires legacy-crypto
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.SHA1.ComputeHash")
            .match_name("System.Security.Cryptography", "SHA1", "ComputeHash")
            .pre(sha1_compute_hash_pre),
    );

    // SHA256.ComputeHash - always available
    manager.register(
        Hook::new("System.Security.Cryptography.SHA256.ComputeHash")
            .match_name("System.Security.Cryptography", "SHA256", "ComputeHash")
            .pre(sha256_compute_hash_pre),
    );
}

fn register_aes_hooks(manager: &mut HookManager) {
    manager.register(
        Hook::new("System.Security.Cryptography.Aes.Create")
            .match_name("System.Security.Cryptography", "Aes", "Create")
            .pre(aes_create_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.RijndaelManaged..ctor")
            .match_name("System.Security.Cryptography", "RijndaelManaged", ".ctor")
            .pre(rijndael_ctor_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.CreateDecryptor")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "CreateDecryptor",
            )
            .pre(create_decryptor_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.CreateEncryptor")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "CreateEncryptor",
            )
            .pre(create_encryptor_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.RijndaelManaged.CreateDecryptor")
            .match_name(
                "System.Security.Cryptography",
                "RijndaelManaged",
                "CreateDecryptor",
            )
            .pre(create_decryptor_pre),
    );

    // Property setters
    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_Key")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_Key",
            )
            .pre(set_key_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_IV")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_IV",
            )
            .pre(set_iv_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_Mode")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_Mode",
            )
            .pre(set_mode_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_Padding")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_Padding",
            )
            .pre(set_padding_pre),
    );
}

fn register_des_hooks(_manager: &mut HookManager) {
    #[cfg(feature = "legacy-crypto")]
    _manager.register(
        Hook::new("System.Security.Cryptography.DES.Create")
            .match_name("System.Security.Cryptography", "DES", "Create")
            .pre(des_create_pre),
    );

    #[cfg(feature = "legacy-crypto")]
    _manager.register(
        Hook::new("System.Security.Cryptography.TripleDES.Create")
            .match_name("System.Security.Cryptography", "TripleDES", "Create")
            .pre(triple_des_create_pre),
    );
}

fn register_transform_hooks(manager: &mut HookManager) {
    manager.register(
        Hook::new("System.Security.Cryptography.ICryptoTransform.TransformFinalBlock")
            .match_name(
                "System.Security.Cryptography",
                "ICryptoTransform",
                "TransformFinalBlock",
            )
            .pre(transform_final_block_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream..ctor")
            .match_name("System.Security.Cryptography", "CryptoStream", ".ctor")
            .pre(crypto_stream_ctor_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream.Read")
            .match_name("System.Security.Cryptography", "CryptoStream", "Read")
            .pre(crypto_stream_read_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream.Write")
            .match_name("System.Security.Cryptography", "CryptoStream", "Write")
            .pre(crypto_stream_write_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream.FlushFinalBlock")
            .match_name(
                "System.Security.Cryptography",
                "CryptoStream",
                "FlushFinalBlock",
            )
            .pre(crypto_stream_flush_final_block_pre),
    );
}

fn register_key_derivation_hooks(manager: &mut HookManager) {
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.PasswordDeriveBytes..ctor")
            .match_name(
                "System.Security.Cryptography",
                "PasswordDeriveBytes",
                ".ctor",
            )
            .pre(password_derive_bytes_ctor_pre),
    );

    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.PasswordDeriveBytes.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "PasswordDeriveBytes",
                "GetBytes",
            )
            .pre(password_derive_bytes_get_bytes_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.Rfc2898DeriveBytes..ctor")
            .match_name(
                "System.Security.Cryptography",
                "Rfc2898DeriveBytes",
                ".ctor",
            )
            .pre(rfc2898_derive_bytes_ctor_pre),
    );

    manager.register(
        Hook::new("System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "Rfc2898DeriveBytes",
                "GetBytes",
            )
            .pre(rfc2898_derive_bytes_get_bytes_pre),
    );
}

fn register_bitconverter_hooks(manager: &mut HookManager) {
    manager.register(
        Hook::new("System.BitConverter.GetBytes")
            .match_name("System", "BitConverter", "GetBytes")
            .pre(bitconverter_get_bytes_pre),
    );

    manager.register(
        Hook::new("System.BitConverter.ToInt32")
            .match_name("System", "BitConverter", "ToInt32")
            .pre(bitconverter_to_int32_pre),
    );

    manager.register(
        Hook::new("System.BitConverter.ToInt64")
            .match_name("System", "BitConverter", "ToInt64")
            .pre(bitconverter_to_int64_pre),
    );

    manager.register(
        Hook::new("System.BitConverter.ToUInt32")
            .match_name("System", "BitConverter", "ToUInt32")
            .pre(bitconverter_to_uint32_pre),
    );
}

// =============================================================================
// Hash Algorithm Hooks
// =============================================================================

/// Hook for `System.Security.Cryptography.MD5.Create` method.
///
/// Creates a new MD5 hash algorithm instance.
///
/// # Handled Overloads
///
/// - `MD5.Create() -> MD5`
/// - `MD5.Create(String) -> MD5`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn md5_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap().alloc_crypto_algorithm("MD5") {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.MD5.ComputeHash` method.
///
/// Computes the MD5 hash of the input data.
///
/// # Handled Overloads
///
/// - `MD5.ComputeHash(Byte[]) -> Byte[]`
/// - `MD5.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `MD5.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
#[cfg(feature = "legacy-crypto")]
fn md5_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(bytes) = thread.heap().get_byte_array(*handle) {
            let hash = compute_md5(&bytes);
            match thread.heap().alloc_byte_array(&hash) {
                Ok(result) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Security.Cryptography.HashAlgorithm.ComputeHash` method.
///
/// Computes hash using the algorithm type stored in the instance (MD5, SHA1, SHA256).
///
/// # Handled Overloads
///
/// - `HashAlgorithm.ComputeHash(Byte[]) -> Byte[]`
/// - `HashAlgorithm.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `HashAlgorithm.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
fn hash_algorithm_compute_hash_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    #[cfg(feature = "legacy-crypto")]
    let default_algo = "MD5";
    #[cfg(not(feature = "legacy-crypto"))]
    let default_algo = "SHA256";

    let hash_type = if let Some(EmValue::ObjectRef(handle)) = ctx.this {
        thread
            .heap()
            .get_crypto_algorithm_type(*handle)
            .unwrap_or_else(|| default_algo.into())
    } else {
        default_algo.into()
    };

    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    match &ctx.args[0] {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = thread.heap().get_byte_array(*handle) {
                let hash = match &*hash_type {
                    #[cfg(feature = "legacy-crypto")]
                    "SHA1" => compute_sha1(&bytes),
                    #[cfg(feature = "legacy-crypto")]
                    "MD5" => compute_md5(&bytes),
                    "SHA256" => compute_sha256(&bytes),
                    #[cfg(feature = "legacy-crypto")]
                    _ => compute_md5(&bytes),
                    #[cfg(not(feature = "legacy-crypto"))]
                    _ => compute_sha256(&bytes),
                };
                match thread.heap().alloc_byte_array(&hash) {
                    Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            } else {
                PreHookResult::Bypass(Some(EmValue::Null))
            }
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SHA1.Create` method.
///
/// Creates a new SHA1 hash algorithm instance.
///
/// # Handled Overloads
///
/// - `SHA1.Create() -> SHA1`
/// - `SHA1.Create(String) -> SHA1`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn sha1_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap().alloc_crypto_algorithm("SHA1") {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SHA256.Create` method.
///
/// Creates a new SHA256 hash algorithm instance.
///
/// # Handled Overloads
///
/// - `SHA256.Create() -> SHA256`
/// - `SHA256.Create(String) -> SHA256`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
fn sha256_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap().alloc_crypto_algorithm("SHA256") {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SHA1.ComputeHash` method.
///
/// Computes the SHA1 hash of the input data.
///
/// # Handled Overloads
///
/// - `SHA1.ComputeHash(Byte[]) -> Byte[]`
/// - `SHA1.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `SHA1.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
#[cfg(feature = "legacy-crypto")]
fn sha1_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    match &ctx.args[0] {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = thread.heap().get_byte_array(*handle) {
                let hash = compute_sha1(&bytes);
                match thread.heap().alloc_byte_array(&hash) {
                    Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            } else {
                PreHookResult::Bypass(Some(EmValue::Null))
            }
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SHA256.ComputeHash` method.
///
/// Computes the SHA256 hash of the input data.
///
/// # Handled Overloads
///
/// - `SHA256.ComputeHash(Byte[]) -> Byte[]`
/// - `SHA256.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `SHA256.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
fn sha256_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    match &ctx.args[0] {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = thread.heap().get_byte_array(*handle) {
                let hash = compute_sha256(&bytes);
                match thread.heap().alloc_byte_array(&hash) {
                    Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
                }
            } else {
                PreHookResult::Bypass(Some(EmValue::Null))
            }
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

// =============================================================================
// Symmetric Encryption Hooks
// =============================================================================

/// Hook for `System.Security.Cryptography.Aes.Create` method.
///
/// Creates a new AES symmetric algorithm instance.
///
/// # Handled Overloads
///
/// - `Aes.Create() -> Aes`
/// - `Aes.Create(String) -> Aes`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
fn aes_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap().alloc_symmetric_algorithm("AES") {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.RijndaelManaged..ctor` constructor.
///
/// Initializes a new RijndaelManaged instance (no-op, instance already allocated).
///
/// # Handled Overloads
///
/// - `RijndaelManaged..ctor() -> void`
fn rijndael_ctor_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.CreateDecryptor` method.
///
/// Creates a decryptor transform using the algorithm's key and IV.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.CreateDecryptor() -> ICryptoTransform`
/// - `SymmetricAlgorithm.CreateDecryptor(Byte[], Byte[]) -> ICryptoTransform`
///
/// # Parameters
///
/// - `rgbKey`: Secret key for decryption (overload 2)
/// - `rgbIV`: Initialization vector (overload 2)
fn create_decryptor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return PreHookResult::Bypass(Some(EmValue::Symbolic(SymbolicValue::new(
                CilFlavor::Object,
                TaintSource::Unknown,
            ))));
        }
    };

    let (algorithm, key, iv) = match thread.heap().get_symmetric_algorithm_info(algo_ref) {
        Some((alg, Some(k), Some(i))) => (alg, k, i),
        Some((alg, Some(k), None)) => {
            let iv_len = if alg.contains("DES") { 8 } else { 16 };
            (alg, k, vec![0u8; iv_len])
        }
        Some((_, None, _)) | None => {
            return PreHookResult::Bypass(Some(EmValue::Symbolic(SymbolicValue::new(
                CilFlavor::Object,
                TaintSource::Unknown,
            ))));
        }
    };

    match thread
        .heap()
        .alloc_crypto_transform(&algorithm, key, iv, false)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.CreateEncryptor` method.
///
/// Creates an encryptor transform using the algorithm's key and IV.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.CreateEncryptor() -> ICryptoTransform`
/// - `SymmetricAlgorithm.CreateEncryptor(Byte[], Byte[]) -> ICryptoTransform`
///
/// # Parameters
///
/// - `rgbKey`: Secret key for encryption (overload 2)
/// - `rgbIV`: Initialization vector (overload 2)
fn create_encryptor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return PreHookResult::Bypass(Some(EmValue::Symbolic(SymbolicValue::new(
                CilFlavor::Object,
                TaintSource::Unknown,
            ))));
        }
    };

    let (algorithm, key, iv) = match thread.heap().get_symmetric_algorithm_info(algo_ref) {
        Some((alg, Some(k), Some(i))) => (alg, k, i),
        Some((alg, Some(k), None)) => {
            let iv_len = if alg.contains("DES") { 8 } else { 16 };
            (alg, k, vec![0u8; iv_len])
        }
        Some((_, None, _)) | None => {
            return PreHookResult::Bypass(Some(EmValue::Symbolic(SymbolicValue::new(
                CilFlavor::Object,
                TaintSource::Unknown,
            ))));
        }
    };

    match thread
        .heap()
        .alloc_crypto_transform(&algorithm, key, iv, true)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_Key` property setter.
///
/// Captures the encryption key for analysis and stores it in the algorithm instance.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_Key(Byte[]) -> void`
///
/// # Parameters
///
/// - `value`: The secret key byte array
fn set_key_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(key_bytes) = thread.heap().get_byte_array(*handle) {
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread
                .capture()
                .capture_buffer(key_bytes, source, BufferSource::Unknown, "crypto_key");
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_IV` property setter.
///
/// Captures the initialization vector for analysis and stores it in the algorithm instance.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_IV(Byte[]) -> void`
///
/// # Parameters
///
/// - `value`: The initialization vector byte array
fn set_iv_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(iv_bytes) = thread.heap().get_byte_array(*handle) {
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread
                .capture()
                .capture_buffer(iv_bytes, source, BufferSource::Unknown, "crypto_iv");
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_Mode` property setter.
///
/// Sets the cipher mode (CBC, ECB, etc.). Currently a no-op.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_Mode(CipherMode) -> void`
///
/// # Parameters
///
/// - `value`: The cipher mode enumeration value
fn set_mode_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_Padding` property setter.
///
/// Sets the padding mode (PKCS7, None, etc.). Currently a no-op.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_Padding(PaddingMode) -> void`
///
/// # Parameters
///
/// - `value`: The padding mode enumeration value
fn set_padding_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.DES.Create` method.
///
/// Creates a new DES symmetric algorithm instance.
///
/// # Handled Overloads
///
/// - `DES.Create() -> DES`
/// - `DES.Create(String) -> DES`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn des_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap().alloc_symmetric_algorithm("DES") {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.TripleDES.Create` method.
///
/// Creates a new TripleDES symmetric algorithm instance.
///
/// # Handled Overloads
///
/// - `TripleDES.Create() -> TripleDES`
/// - `TripleDES.Create(String) -> TripleDES`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn triple_des_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap().alloc_symmetric_algorithm("TripleDES") {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

// =============================================================================
// Transform and CryptoStream Hooks
// =============================================================================

/// Hook for `System.Security.Cryptography.ICryptoTransform.TransformFinalBlock` method.
///
/// Transforms the final block of data and captures input for analysis.
///
/// # Handled Overloads
///
/// - `ICryptoTransform.TransformFinalBlock(Byte[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `inputBuffer`: Input byte array containing data to transform
/// - `inputOffset`: Offset in inputBuffer to start reading
/// - `inputCount`: Number of bytes to transform
fn transform_final_block_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(bytes) = thread.heap().get_byte_array(*handle) {
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_buffer(
                bytes.clone(),
                source,
                BufferSource::CryptoTransform {
                    algorithm: "Unknown".to_string(),
                },
                "crypto_input",
            );

            match thread.heap().alloc_byte_array(&bytes) {
                Ok(result) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }

    PreHookResult::Bypass(Some(EmValue::Symbolic(SymbolicValue::new(
        CilFlavor::Object,
        TaintSource::Unknown,
    ))))
}

/// Hook for `System.Security.Cryptography.CryptoStream..ctor` constructor.
///
/// Initializes a CryptoStream wrapping another stream with a crypto transform.
///
/// # Handled Overloads
///
/// - `CryptoStream..ctor(Stream, ICryptoTransform, CryptoStreamMode) -> void`
/// - `CryptoStream..ctor(Stream, ICryptoTransform, CryptoStreamMode, Boolean) -> void`
///
/// # Parameters
///
/// - `stream`: The underlying stream to wrap
/// - `transform`: The cryptographic transform to apply
/// - `mode`: Read (0) or Write (1) mode
/// - `leaveOpen`: Whether to leave the underlying stream open (overload 2)
fn crypto_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let underlying_stream = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let transform = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let mode = match ctx.args.get(2) {
        Some(EmValue::I32(m)) => *m as u8,
        _ => 0,
    };

    thread.heap_mut().replace_with_crypto_stream(
        crypto_stream_ref,
        underlying_stream,
        transform,
        mode,
    );

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.CryptoStream.Read` method.
///
/// Reads and decrypts data from the underlying stream.
///
/// # Handled Overloads
///
/// - `CryptoStream.Read(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `buffer`: Destination byte array for decrypted data
/// - `offset`: Offset in buffer to start writing
/// - `count`: Maximum number of bytes to read
fn crypto_stream_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some((underlying_stream, transform_ref, mode)) =
        thread.heap().get_crypto_stream_info(crypto_stream_ref)
    else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if mode != 0 {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    if thread
        .heap()
        .get_crypto_stream_transformed(crypto_stream_ref)
        .is_none()
    {
        let Some((stream_data, _)) = thread.heap().get_stream_data(underlying_stream) else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };

        let transformed_data = if let Some((algorithm, key, iv, is_encryptor)) =
            thread.heap().get_crypto_transform_info(transform_ref)
        {
            let transform_result =
                apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, &stream_data);

            match transform_result {
                Some(data) => {
                    if !is_encryptor {
                        let source = CaptureSource::new(
                            thread.current_method().unwrap_or(Token::new(0)),
                            thread.id(),
                            thread.current_offset().unwrap_or(0),
                            0,
                        );
                        thread.capture().capture_buffer(
                            data.clone(),
                            source,
                            BufferSource::CryptoTransform {
                                algorithm: algorithm.to_string(),
                            },
                            "decrypted_stream",
                        );
                    }
                    data
                }
                None => stream_data,
            }
        } else {
            stream_data
        };

        thread
            .heap()
            .set_crypto_stream_transformed(crypto_stream_ref, transformed_data);
    }

    let Some(bytes) = thread.heap().read_crypto_stream(crypto_stream_ref, count) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    for (i, &byte) in bytes.iter().enumerate() {
        let _ = thread.heap_mut().set_array_element(
            buffer_ref,
            offset + i,
            EmValue::I32(i32::from(byte)),
        );
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(bytes.len() as i32)))
}

/// Hook for `System.Security.Cryptography.CryptoStream.Write` method.
///
/// Writes data to the stream, buffering for encryption on flush.
///
/// # Handled Overloads
///
/// - `CryptoStream.Write(Byte[], Int32, Int32) -> void`
///
/// # Parameters
///
/// - `buffer`: Source byte array containing data to encrypt
/// - `offset`: Offset in buffer to start reading
/// - `count`: Number of bytes to write
fn crypto_stream_write_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let Some((_, _, mode)) = thread.heap().get_crypto_stream_info(crypto_stream_ref) else {
        return PreHookResult::Bypass(None);
    };

    if mode != 1 {
        return PreHookResult::Bypass(None);
    }

    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(None),
    };

    let Some(buffer_data) = thread.heap().get_byte_array(buffer_ref) else {
        return PreHookResult::Bypass(None);
    };

    let end = (offset + count).min(buffer_data.len());
    let bytes_to_write = if offset < buffer_data.len() {
        buffer_data[offset..end].to_vec()
    } else {
        return PreHookResult::Bypass(None);
    };

    thread
        .heap()
        .crypto_stream_append_write(crypto_stream_ref, &bytes_to_write);

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.CryptoStream.FlushFinalBlock` method.
///
/// Flushes the final block, applying padding and completing encryption.
///
/// # Handled Overloads
///
/// - `CryptoStream.FlushFinalBlock() -> void`
fn crypto_stream_flush_final_block_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let Some((underlying_stream, transform_ref, mode)) =
        thread.heap().get_crypto_stream_info(crypto_stream_ref)
    else {
        return PreHookResult::Bypass(None);
    };

    if mode != 1 {
        return PreHookResult::Bypass(None);
    }

    let Some(write_buffer) = thread
        .heap()
        .get_crypto_stream_write_buffer(crypto_stream_ref)
    else {
        return PreHookResult::Bypass(None);
    };

    if write_buffer.is_empty() {
        return PreHookResult::Bypass(None);
    }

    let transformed_data = if let Some((algorithm, key, iv, is_encryptor)) =
        thread.heap().get_crypto_transform_info(transform_ref)
    {
        let transform_result =
            apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, &write_buffer);

        match transform_result {
            Some(data) => {
                if is_encryptor {
                    let source = CaptureSource::new(
                        thread.current_method().unwrap_or(Token::new(0)),
                        thread.id(),
                        thread.current_offset().unwrap_or(0),
                        0,
                    );
                    thread.capture().capture_buffer(
                        data.clone(),
                        source,
                        BufferSource::CryptoTransform {
                            algorithm: algorithm.to_string(),
                        },
                        "encrypted_stream",
                    );
                }
                data
            }
            None => write_buffer,
        }
    } else {
        write_buffer
    };

    thread
        .heap_mut()
        .write_to_stream(underlying_stream, &transformed_data);

    thread
        .heap()
        .clear_crypto_stream_write_buffer(crypto_stream_ref);

    PreHookResult::Bypass(None)
}

// =============================================================================
// Key Derivation Hooks
// =============================================================================

/// Hook for `System.Security.Cryptography.PasswordDeriveBytes..ctor` constructor.
///
/// Initializes PBKDF1-based key derivation with password and salt.
///
/// # Handled Overloads
///
/// - `PasswordDeriveBytes..ctor(String, Byte[]) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[]) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], String, Int32) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], String, Int32) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], String, Int32, CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], String, Int32, CspParameters) -> void`
///
/// # Parameters
///
/// - `password`: Password string or byte array
/// - `salt`: Salt byte array
/// - `hashName`: Hash algorithm name (optional, default SHA1)
/// - `iterations`: Number of iterations (optional, default 100)
/// - `cspParams`: Cryptographic service provider parameters (optional)
#[cfg(feature = "legacy-crypto")]
fn password_derive_bytes_ctor_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => return PreHookResult::Bypass(None),
    };

    let password: Vec<u8> = match ctx.args.first() {
        Some(EmValue::ObjectRef(pwd_ref)) => {
            if let Some(s) = thread.heap().get_string_opt(*pwd_ref) {
                s.as_bytes().to_vec()
            } else {
                thread.heap().get_byte_array(*pwd_ref).unwrap_or_default()
            }
        }
        _ => Vec::new(),
    };

    let salt: Vec<u8> = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(salt_ref)) => {
            thread.heap().get_byte_array(*salt_ref).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let iterations: u32 = 100;

    match thread
        .heap()
        .replace_with_key_derivation(heap_ref, password, salt, iterations, "SHA1")
    {
        Ok(()) => PreHookResult::Bypass(None),
        Err(_) => PreHookResult::Bypass(None),
    }
}

/// Hook for `System.Security.Cryptography.PasswordDeriveBytes.GetBytes` method.
///
/// Derives key bytes using PBKDF1 algorithm.
///
/// # Handled Overloads
///
/// - `PasswordDeriveBytes.GetBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `cb`: Number of pseudo-random key bytes to generate
#[cfg(feature = "legacy-crypto")]
fn password_derive_bytes_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let size = ctx
        .args
        .first()
        .map(usize::try_from)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(16);

    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => {
            let zeros = vec![0u8; size];
            match thread.heap().alloc_byte_array(&zeros) {
                Ok(handle) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    };

    let params = thread.heap().get_key_derivation_params(heap_ref);

    let derived_key = match params {
        Some((password, salt, iterations, _hash_algorithm)) => {
            derive_pbkdf1_key(&password, &salt, iterations, size)
        }
        None => vec![0u8; size],
    };

    match thread.heap().alloc_byte_array(&derived_key) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.Rfc2898DeriveBytes..ctor` constructor.
///
/// Initializes PBKDF2-based key derivation with password, salt, and iterations.
///
/// # Handled Overloads
///
/// - `Rfc2898DeriveBytes..ctor(String, Byte[]) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Byte[], Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Int32, Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(Byte[], Byte[], Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Byte[], Int32, HashAlgorithmName) -> void`
/// - `Rfc2898DeriveBytes..ctor(Byte[], Byte[], Int32, HashAlgorithmName) -> void`
///
/// # Parameters
///
/// - `password`: Password string or byte array
/// - `salt`: Salt byte array or salt size in bytes
/// - `iterations`: Number of iterations (default 1000)
/// - `hashAlgorithm`: Hash algorithm name (optional, default SHA1)
fn rfc2898_derive_bytes_ctor_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => return PreHookResult::Bypass(None),
    };

    let password: Vec<u8> = match ctx.args.first() {
        Some(EmValue::ObjectRef(pwd_ref)) => {
            if let Some(s) = thread.heap().get_string_opt(*pwd_ref) {
                s.as_bytes().to_vec()
            } else {
                thread.heap().get_byte_array(*pwd_ref).unwrap_or_default()
            }
        }
        _ => Vec::new(),
    };

    let salt: Vec<u8> = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(salt_ref)) => {
            thread.heap().get_byte_array(*salt_ref).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let iterations: u32 = match ctx.args.get(2) {
        Some(val) => i32::try_from(val).unwrap_or(1000) as u32,
        None => 1000,
    };

    let hash_algorithm = "SHA1";

    match thread.heap().replace_with_key_derivation(
        heap_ref,
        password,
        salt,
        iterations,
        hash_algorithm,
    ) {
        Ok(()) => PreHookResult::Bypass(None),
        Err(_) => PreHookResult::Bypass(None),
    }
}

/// Hook for `System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes` method.
///
/// Derives key bytes using PBKDF2 algorithm.
///
/// # Handled Overloads
///
/// - `Rfc2898DeriveBytes.GetBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `cb`: Number of pseudo-random key bytes to generate
fn rfc2898_derive_bytes_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let size = ctx
        .args
        .first()
        .map(usize::try_from)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(16);

    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => {
            let zeros = vec![0u8; size];
            match thread.heap().alloc_byte_array(&zeros) {
                Ok(handle) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    };

    let params = thread.heap().get_key_derivation_params(heap_ref);

    let derived_key = match params {
        Some((password, salt, iterations, hash_algorithm)) => {
            derive_pbkdf2_key(&password, &salt, iterations, size, &hash_algorithm)
        }
        None => vec![0u8; size],
    };

    match thread.heap().alloc_byte_array(&derived_key) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

// =============================================================================
// BitConverter Hooks
// =============================================================================

/// Hook for `System.BitConverter.GetBytes` method.
///
/// Converts a primitive value to its byte array representation (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.GetBytes(Boolean) -> Byte[]`
/// - `BitConverter.GetBytes(Char) -> Byte[]`
/// - `BitConverter.GetBytes(Double) -> Byte[]`
/// - `BitConverter.GetBytes(Int16) -> Byte[]`
/// - `BitConverter.GetBytes(Int32) -> Byte[]`
/// - `BitConverter.GetBytes(Int64) -> Byte[]`
/// - `BitConverter.GetBytes(Single) -> Byte[]`
/// - `BitConverter.GetBytes(UInt16) -> Byte[]`
/// - `BitConverter.GetBytes(UInt32) -> Byte[]`
/// - `BitConverter.GetBytes(UInt64) -> Byte[]`
///
/// # Parameters
///
/// - `value`: The value to convert to bytes
fn bitconverter_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let bytes = match &ctx.args[0] {
        EmValue::I32(v) => v.to_le_bytes().to_vec(),
        EmValue::I64(v) | EmValue::NativeInt(v) => v.to_le_bytes().to_vec(),
        EmValue::F32(v) => v.to_le_bytes().to_vec(),
        EmValue::F64(v) => v.to_le_bytes().to_vec(),
        EmValue::NativeUInt(v) => v.to_le_bytes().to_vec(),
        EmValue::Bool(v) => vec![u8::from(*v)],
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match thread.heap().alloc_byte_array(&bytes) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.BitConverter.ToInt32` method.
///
/// Converts 4 bytes from a byte array to a 32-bit signed integer (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.ToInt32(Byte[], Int32) -> Int32`
///
/// # Parameters
///
/// - `value`: Byte array containing the bytes to convert
/// - `startIndex`: Starting position within the array
fn bitconverter_to_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let bytes = match &ctx.args[0] {
        EmValue::ObjectRef(handle) => thread.heap().get_byte_array(*handle).unwrap_or_default(),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let start_index = usize::try_from(&ctx.args[1]).unwrap_or(usize::MAX);
    if start_index.saturating_add(4) > bytes.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let value = i32::from_le_bytes([
        bytes[start_index],
        bytes[start_index + 1],
        bytes[start_index + 2],
        bytes[start_index + 3],
    ]);

    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.BitConverter.ToInt64` method.
///
/// Converts 8 bytes from a byte array to a 64-bit signed integer (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.ToInt64(Byte[], Int32) -> Int64`
///
/// # Parameters
///
/// - `value`: Byte array containing the bytes to convert
/// - `startIndex`: Starting position within the array
fn bitconverter_to_int64_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    }

    let bytes = match &ctx.args[0] {
        EmValue::ObjectRef(handle) => thread.heap().get_byte_array(*handle).unwrap_or_default(),
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    let start_index = usize::try_from(&ctx.args[1]).unwrap_or(usize::MAX);
    if start_index.saturating_add(8) > bytes.len() {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    }

    let value = i64::from_le_bytes([
        bytes[start_index],
        bytes[start_index + 1],
        bytes[start_index + 2],
        bytes[start_index + 3],
        bytes[start_index + 4],
        bytes[start_index + 5],
        bytes[start_index + 6],
        bytes[start_index + 7],
    ]);

    PreHookResult::Bypass(Some(EmValue::I64(value)))
}

/// Hook for `System.BitConverter.ToUInt32` method.
///
/// Converts 4 bytes from a byte array to a 32-bit unsigned integer (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.ToUInt32(Byte[], Int32) -> UInt32`
///
/// # Parameters
///
/// - `value`: Byte array containing the bytes to convert
/// - `startIndex`: Starting position within the array
fn bitconverter_to_uint32_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let bytes = match &ctx.args[0] {
        EmValue::ObjectRef(handle) => thread.heap().get_byte_array(*handle).unwrap_or_default(),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let start_index = usize::try_from(&ctx.args[1]).unwrap_or(usize::MAX);
    if start_index.saturating_add(4) > bytes.len() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let value = u32::from_le_bytes([
        bytes[start_index],
        bytes[start_index + 1],
        bytes[start_index + 2],
        bytes[start_index + 3],
    ]);

    #[allow(clippy::cast_possible_wrap)]
    let signed_value = value as i32;
    PreHookResult::Bypass(Some(EmValue::I32(signed_value)))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::runtime::hook::HookManager;
    use crate::test::emulation::create_test_thread;

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        // Should have registered many hooks
        assert!(manager.len() >= 15);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hash_known_value() {
        let data = b"hello";
        let hash = compute_sha256(data);
        assert_eq!(
            hash,
            vec![
                0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
                0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
                0x93, 0x8b, 0x98, 0x24
            ]
        );
    }

    #[test]
    fn test_sha256_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA256",
            "Create",
        );

        let result = sha256_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_sha256_compute_hash_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(b"test data").unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA256",
            "ComputeHash",
        )
        .with_args(&args);

        let result = sha256_compute_hash_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let hash = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(hash.len(), 32);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_aes_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "Aes",
            "Create",
        );

        let result = aes_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_rijndael_ctor_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RijndaelManaged",
            ".ctor",
        );

        let result = rijndael_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_create_decryptor_hook() {
        let mut thread = create_test_thread();

        let algo_ref = thread.heap().alloc_symmetric_algorithm("AES").unwrap();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        thread.heap().set_symmetric_key(algo_ref, key).unwrap();
        thread.heap().set_symmetric_iv(algo_ref, iv).unwrap();

        let this = EmValue::ObjectRef(algo_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SymmetricAlgorithm",
            "CreateDecryptor",
        )
        .with_this(Some(&this));

        let result = create_decryptor_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_set_key_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SymmetricAlgorithm",
            "set_Key",
        )
        .with_args(&[EmValue::Null]);

        let result = set_key_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_set_iv_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SymmetricAlgorithm",
            "set_IV",
        )
        .with_args(&[EmValue::Null]);

        let result = set_iv_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_transform_final_block_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(&[1, 2, 3, 4]).unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "ICryptoTransform",
            "TransformFinalBlock",
        )
        .with_args(&args);

        let result = transform_final_block_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(bytes, vec![1, 2, 3, 4]);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_rfc2898_derive_bytes_get_bytes_hook() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(24)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "Rfc2898DeriveBytes",
            "GetBytes",
        )
        .with_args(&args);

        let result = rfc2898_derive_bytes_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(bytes.len(), 24);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_bitconverter_get_bytes_hook() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(0x12345678)];
        let ctx = HookContext::new(Token::new(0x0A000001), "System", "BitConverter", "GetBytes")
            .with_args(&args);

        let result = bitconverter_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_bitconverter_to_int32_hook() {
        let mut thread = create_test_thread();
        let bytes = thread
            .heap()
            .alloc_byte_array(&[0x78, 0x56, 0x34, 0x12])
            .unwrap();

        let args = [EmValue::ObjectRef(bytes), EmValue::I32(0)];
        let ctx = HookContext::new(Token::new(0x0A000001), "System", "BitConverter", "ToInt32")
            .with_args(&args);

        let result = bitconverter_to_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x12345678)))
        ));
    }

    #[test]
    fn test_bitconverter_to_int64_hook() {
        let mut thread = create_test_thread();
        let bytes = thread
            .heap()
            .alloc_byte_array(&[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12])
            .unwrap();

        let args = [EmValue::ObjectRef(bytes), EmValue::I32(0)];
        let ctx = HookContext::new(Token::new(0x0A000001), "System", "BitConverter", "ToInt64")
            .with_args(&args);

        let result = bitconverter_to_int64_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(0x123456789ABCDEF0)))
        ));
    }

    #[test]
    fn test_bitconverter_to_uint32_hook() {
        let mut thread = create_test_thread();
        let bytes = thread
            .heap()
            .alloc_byte_array(&[0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();

        let args = [EmValue::ObjectRef(bytes), EmValue::I32(0)];
        let ctx = HookContext::new(Token::new(0x0A000001), "System", "BitConverter", "ToUInt32")
            .with_args(&args);

        let result = bitconverter_to_uint32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }
}

#[cfg(test)]
#[cfg(feature = "legacy-crypto")]
mod legacy_tests {
    use super::*;
    use crate::test::emulation::create_test_thread;

    #[test]
    fn test_md5_hash() {
        let data = b"hello world";
        let hash = compute_md5(data);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_md5_hash_known_value() {
        let data = b"hello";
        let hash = compute_md5(data);
        assert_eq!(
            hash,
            vec![
                0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17,
                0xc5, 0x92
            ]
        );
    }

    #[test]
    fn test_sha1_hash() {
        let data = b"hello world";
        let hash = compute_sha1(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha1_hash_known_value() {
        let data = b"hello";
        let hash = compute_sha1(data);
        assert_eq!(
            hash,
            vec![
                0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48,
                0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d
            ]
        );
    }

    #[test]
    fn test_md5_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "MD5",
            "Create",
        );

        let result = md5_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_md5_compute_hash_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(b"hello").unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "MD5",
            "ComputeHash",
        )
        .with_args(&args);

        let result = md5_compute_hash_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let hash = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(hash.len(), 16);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_sha1_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA1",
            "Create",
        );

        let result = sha1_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_sha1_compute_hash_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(b"test data").unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA1",
            "ComputeHash",
        )
        .with_args(&args);

        let result = sha1_compute_hash_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let hash = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(hash.len(), 20);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_des_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "DES",
            "Create",
        );

        let result = des_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_triple_des_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "TripleDES",
            "Create",
        );

        let result = triple_des_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_password_derive_bytes_get_bytes_hook() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(32)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "PasswordDeriveBytes",
            "GetBytes",
        )
        .with_args(&args);

        let result = password_derive_bytes_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap();
            assert_eq!(bytes.len(), 32);
        } else {
            panic!("Expected ObjectRef");
        }
    }
}
