//! `System.Security.Cryptography` method hooks for deobfuscation.
//!
//! This module provides hook implementations for cryptographic methods commonly used by
//! obfuscators to encrypt strings, resources, and code. These hooks are essential for
//! analyzing protected .NET assemblies that use encryption to hide their payloads.
//!
//! # Module Hierarchy
//!
//! The crypto hooks are organized into five submodules by category:
//!
//! - [`hashing`] — Hash algorithms (MD5, SHA1, SHA256, HashAlgorithm) and CryptoConfig.
//!   Hash functions are the foundation of key derivation and checksum
//!   verification in obfuscated assemblies.
//!
//! - [`hmac`] — HMAC keyed hashing (HMACSHA256, HMACSHA512). Combines a secret key
//!   with a hash function to produce authenticated message digests.
//!
//! - [`rng`] — Random number generation (RNGCryptoServiceProvider, RandomNumberGenerator).
//!   Implemented as a deterministic xorshift64 PRNG for reproducible emulation.
//!
//! - [`symmetric`] — Symmetric ciphers (AES, DES, TripleDES), asymmetric algorithms (RSA),
//!   and crypto transform/stream operations. These perform the actual encryption and
//!   decryption of protected payloads.
//!
//! - [`derivation`] — Key derivation functions (PBKDF1 via `PasswordDeriveBytes`, PBKDF2
//!   via `Rfc2898DeriveBytes`). Obfuscators use these to derive encryption keys from
//!   embedded password strings.
//!
//! # Shared Helpers
//!
//! This root module exports two helpers used across submodules:
//!
//! - [`resolve_crypto_key_iv`] — Resolves algorithm name, key, IV, cipher mode, and
//!   padding from a `CreateDecryptor`/`CreateEncryptor` call context. Used by the
//!   symmetric module's decryptor/encryptor hooks.
//!
//! - [`extract_xml_element`] — Simple string-based XML element extraction. Used by the
//!   symmetric module's RSA `FromXmlString` hook to parse public key XML.
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
//! | `ICryptoTransform` | `TransformBlock(byte[], int, int, byte[], int)`, `TransformFinalBlock(byte[], int, int)` |
//! | `CryptoStream` | `.ctor`, `Read()`, `Write()`, `FlushFinalBlock()` |
//!
//! ## Key Derivation
//!
//! | Class | Methods |
//! |-------|---------|
//! | `PasswordDeriveBytes` | `.ctor`, `GetBytes(int)` |
//! | `Rfc2898DeriveBytes` | `.ctor`, `GetBytes(int)` (PBKDF2) |
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
//! # Implementation Notes
//!
//! - **Hash functions are fully implemented** using the `md5`, `sha1`, and `sha2` crates
//! - **Symmetric encryption hooks capture keys/IVs** but don't perform actual encryption
//! - **Transform hooks pass through input data** for analysis
//! - **Full key derivation support** - PBKDF1 and PBKDF2 with SHA1/256/384/512

mod derivation;
mod hashing;
mod hmac;
mod rng;
mod symmetric;

use crate::{
    emulation::{
        runtime::hook::{HookContext, HookManager},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    Result,
};

/// Registers all cryptographic method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Categories
///
/// - **Hashing**: MD5, SHA1, SHA256, HashAlgorithm, CryptoConfig
/// - **HMAC**: HMACSHA256, HMACSHA512
/// - **RNG**: RNGCryptoServiceProvider, RandomNumberGenerator
/// - **Symmetric/Asymmetric**: AES, Rijndael, DES, TripleDES, RSA, ICryptoTransform, CryptoStream
/// - **Key Derivation**: PasswordDeriveBytes (PBKDF1), Rfc2898DeriveBytes (PBKDF2)
pub fn register(manager: &HookManager) -> Result<()> {
    hashing::register(manager)?;
    hmac::register(manager)?;
    rng::register(manager)?;
    symmetric::register(manager)?;
    derivation::register(manager)?;
    Ok(())
}

/// Resolves the algorithm name, key, IV, mode, and padding for a `CreateDecryptor`/`CreateEncryptor` call.
///
/// Handles both overloads:
/// - No-arg: reads key/IV from the `SymmetricAlgorithm` heap object
/// - Two-arg `(byte[] rgbKey, byte[] rgbIV)`: extracts key/IV from the explicit arguments
///
/// Returns `(algorithm, Option<key>, Option<iv>, mode, padding)`.
pub(crate) fn resolve_crypto_key_iv(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
    algo_ref: HeapRef,
) -> (String, Option<Vec<u8>>, Option<Vec<u8>>, u8, u8) {
    // Try explicit arguments first (2-arg overload: CreateDecryptor(byte[], byte[]))
    if ctx.args.len() == 2 {
        let arg_key = match ctx.args.first() {
            Some(EmValue::ObjectRef(h)) => thread.heap().get_byte_array(*h).ok().flatten(),
            _ => None,
        };
        let arg_iv = match ctx.args.get(1) {
            Some(EmValue::ObjectRef(h)) => thread.heap().get_byte_array(*h).ok().flatten(),
            _ => None,
        };

        if let Some(key) = arg_key {
            // Get algo name and mode/padding from the object, but use explicit key/IV
            let (algorithm, _, _, mode, padding) = thread
                .heap()
                .get_symmetric_algorithm_info(algo_ref)
                .ok()
                .flatten()
                .unwrap_or_else(|| ("AES".into(), None, None, 1, 2));
            let iv = arg_iv.unwrap_or_else(|| {
                let iv_len = if algorithm.contains("DES") { 8 } else { 16 };
                vec![0u8; iv_len]
            });
            return (algorithm.to_string(), Some(key), Some(iv), mode, padding);
        }
    }

    // Fall back to stored key/IV on the algorithm object
    match thread.heap().get_symmetric_algorithm_info(algo_ref) {
        Ok(Some((alg, Some(k), Some(i), m, p))) => (alg.to_string(), Some(k), Some(i), m, p),
        Ok(Some((alg, Some(k), None, m, p))) => {
            let iv_len = if alg.contains("DES") { 8 } else { 16 };
            (alg.to_string(), Some(k), Some(vec![0u8; iv_len]), m, p)
        }
        Ok(Some((alg, None, iv, m, p))) => (alg.to_string(), None, iv, m, p),
        _ => ("AES".to_string(), None, None, 1, 2),
    }
}

/// Extracts the text content of an XML element by tag name.
///
/// Simple string-based extraction (no full XML parser needed).
pub(crate) fn extract_xml_element(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::{bcl::crypto::register, hook::HookManager};

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        // Should have registered many hooks
        assert!(manager.len() >= 15);
    }
}
