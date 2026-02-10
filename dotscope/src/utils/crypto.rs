//! Cryptographic utilities for deobfuscation and .NET compatibility.
//!
//! This module provides implementations of cryptographic functions used by .NET's
//! cryptographic primitives. These are essential for deobfuscation scenarios where
//! protected code uses encryption to hide payloads, as well as for assembly identity
//! verification and hash computation.
//!
//! # Hash Functions
//!
//! - **MD5** (128-bit, legacy) - Used for assembly hash verification
//! - **SHA1** (160-bit, legacy) - Used for public key tokens and assembly verification
//! - **SHA256/384/512** - Modern hash algorithms for assembly verification
//!
//! # Key Derivation
//!
//! - **PBKDF2** (RFC 2898 Section 5.2) - Used by `Rfc2898DeriveBytes`
//! - **PBKDF1** (RFC 2898 Section 5.1) - Used by `PasswordDeriveBytes`
//!
//! # Symmetric Encryption
//!
//! - **AES** (128/192/256-bit CBC mode with PKCS7 padding)
//! - **DES** (56-bit CBC mode with PKCS7 padding)
//! - **TripleDES** (168-bit CBC mode with PKCS7 padding)

use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
#[cfg(feature = "legacy-crypto")]
use des::{Des, TdesEde3};
#[cfg(feature = "legacy-crypto")]
use md5::{Digest as Md5Digest, Md5};
use pbkdf2::pbkdf2_hmac;
#[cfg(feature = "legacy-crypto")]
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};

// Type aliases for AES CBC modes
type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;
type Aes192CbcEnc = Encryptor<aes::Aes192>;
type Aes192CbcDec = Decryptor<aes::Aes192>;
type Aes256CbcEnc = Encryptor<aes::Aes256>;
type Aes256CbcDec = Decryptor<aes::Aes256>;

// Type aliases for DES CBC modes (legacy-crypto feature)
#[cfg(feature = "legacy-crypto")]
type DesCbcEnc = Encryptor<Des>;
#[cfg(feature = "legacy-crypto")]
type DesCbcDec = Decryptor<Des>;
#[cfg(feature = "legacy-crypto")]
type TdesCbcEnc = Encryptor<TdesEde3>;
#[cfg(feature = "legacy-crypto")]
type TdesCbcDec = Decryptor<TdesEde3>;

/// Computes the MD5 hash of input bytes.
///
/// **Security Warning**: MD5 is cryptographically broken and should not be used
/// for security purposes. This function exists for compatibility with legacy
/// .NET assemblies and forensic analysis.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 16-byte vector containing the MD5 hash.
///
/// # Feature Requirements
///
/// This function requires the `legacy-crypto` feature.
#[cfg(feature = "legacy-crypto")]
#[must_use]
pub fn compute_md5(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-1 hash of input bytes.
///
/// **Security Warning**: SHA-1 is cryptographically broken and should not be used
/// for security purposes. This function exists for compatibility with legacy
/// .NET assemblies (public key tokens, assembly verification) and forensic analysis.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 20-byte vector containing the SHA-1 hash.
///
/// # Feature Requirements
///
/// This function requires the `legacy-crypto` feature.
#[cfg(feature = "legacy-crypto")]
#[must_use]
pub fn compute_sha1(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    Sha1Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-256 hash of input bytes.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 32-byte vector containing the SHA-256 hash.
#[must_use]
pub fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-384 hash of input bytes.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 48-byte vector containing the SHA-384 hash.
#[must_use]
pub fn compute_sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    Sha2Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-512 hash of input bytes.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 64-byte vector containing the SHA-512 hash.
#[must_use]
pub fn compute_sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    Sha2Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Derives a key using PBKDF2 (RFC 2898 Section 5.2).
///
/// PBKDF2 is the algorithm used by .NET's `Rfc2898DeriveBytes` class.
/// It uses HMAC as the pseudorandom function.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - The salt bytes
/// * `iterations` - Number of iterations (minimum 1000 recommended)
/// * `key_len` - Desired length of the derived key
/// * `hash_algorithm` - Hash algorithm: "SHA1", "SHA256", "SHA384", "SHA512"
///
/// # Returns
///
/// The derived key bytes of the specified length.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::utils::crypto::derive_pbkdf2_key;
///
/// let password = b"mypassword";
/// let salt = b"somesalt";
/// let key = derive_pbkdf2_key(password, salt, 1000, 32, "SHA256");
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_pbkdf2_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
    hash_algorithm: &str,
) -> Vec<u8> {
    let mut key = vec![0u8; key_len];

    match hash_algorithm.to_uppercase().as_str() {
        "SHA256" => {
            pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, &mut key);
        }
        "SHA384" => {
            pbkdf2_hmac::<sha2::Sha384>(password, salt, iterations, &mut key);
        }
        "SHA512" => {
            pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut key);
        }
        #[cfg(feature = "legacy-crypto")]
        _ => {
            // Default to SHA1 (most common in .NET Framework)
            pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut key);
        }
        #[cfg(not(feature = "legacy-crypto"))]
        _ => {
            // Default to SHA256 when legacy-crypto is disabled
            pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, &mut key);
        }
    }

    key
}

/// Derives a key using PBKDF1 (RFC 2898 Section 5.1).
///
/// PBKDF1 is the algorithm used by .NET's `PasswordDeriveBytes` class.
///
/// # Algorithm
///
/// 1. T_1 = SHA1(Password || Salt)
/// 2. For i = 2 to iterations: T_i = SHA1(T_{i-1})
/// 3. Output first key_len bytes of T_iterations
///
/// # Extended Output
///
/// For output longer than the hash size (20 bytes for SHA1), .NET uses a proprietary
/// extension that derives additional blocks using: SHA1(counter_string || T_iterations)
/// where counter_string is "1", "2", "3", etc.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - The salt bytes
/// * `iterations` - Number of iterations (default 100 for PasswordDeriveBytes)
/// * `key_len` - Desired length of the derived key
///
/// # Returns
///
/// The derived key bytes of the specified length.
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::utils::crypto::derive_pbkdf1_key;
///
/// let password = b"mypassword";
/// let salt = b"somesalt";
/// let key = derive_pbkdf1_key(password, salt, 100, 16);
/// assert_eq!(key.len(), 16);
/// ```
///
/// # Feature Requirements
///
/// This function requires the `legacy-crypto` feature because PBKDF1 is
/// inherently SHA1-based per RFC 2898.
#[cfg(feature = "legacy-crypto")]
pub fn derive_pbkdf1_key(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    // Step 1: T_1 = SHA1(Password || Salt)
    let mut hasher = sha1::Sha1::new();
    hasher.update(password);
    hasher.update(salt);
    let mut t = hasher.finalize();

    // Step 2: For i = 2 to iterations: T_i = SHA1(T_{i-1})
    for _ in 1..iterations {
        let mut hasher = sha1::Sha1::new();
        hasher.update(t);
        t = hasher.finalize();
    }

    // The base key (first 20 bytes from PBKDF1)
    let base_key: [u8; 20] = t.into();

    if key_len <= 20 {
        // Simple case: just return the first key_len bytes
        base_key[..key_len].to_vec()
    } else {
        // Extended output using .NET's proprietary extension
        // For each additional block: SHA1(counter_string || base_key)
        let mut result = base_key.to_vec();
        let mut counter = 1u32;

        while result.len() < key_len {
            let mut hasher = sha1::Sha1::new();
            // .NET uses the string representation of the counter
            hasher.update(counter.to_string().as_bytes());
            hasher.update(base_key);
            let block = hasher.finalize();
            result.extend_from_slice(&block);
            counter += 1;
        }

        result.truncate(key_len);
        result
    }
}

/// Applies a crypto transformation (encryption or decryption) to data.
///
/// This function handles the actual cryptographic operations for AES, DES, and
/// TripleDES in CBC mode with PKCS7 padding.
///
/// # Arguments
///
/// * `algorithm` - The algorithm name (e.g., "AES", "Rijndael", "DES", "TripleDES")
/// * `key` - The encryption/decryption key
/// * `iv` - The initialization vector
/// * `is_encryptor` - True for encryption, false for decryption
/// * `data` - The input data to transform
///
/// # Returns
///
/// The transformed data, or `None` if the algorithm/key size is unsupported.
///
/// # Supported Algorithms
///
/// | Algorithm | Key Sizes | Block Size |
/// |-----------|-----------|------------|
/// | AES/Rijndael | 16, 24, 32 bytes | 16 bytes |
/// | DES | 8 bytes | 8 bytes |
/// | TripleDES/3DES | 24 bytes | 8 bytes |
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::utils::crypto::apply_crypto_transform;
///
/// let key = [0u8; 16];  // 128-bit AES key
/// let iv = [0u8; 16];   // 128-bit IV
/// let plaintext = b"Hello, World!";
///
/// // Encrypt
/// let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext).unwrap();
///
/// // Decrypt
/// let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext).unwrap();
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn apply_crypto_transform(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    is_encryptor: bool,
    data: &[u8],
) -> Option<Vec<u8>> {
    // Normalize algorithm name
    let alg_upper = algorithm.to_uppercase();

    if alg_upper.contains("AES") || alg_upper.contains("RIJNDAEL") {
        // AES - key size determines variant
        return match key.len() {
            16 => {
                if is_encryptor {
                    aes_encrypt::<Aes128CbcEnc>(key, iv, data)
                } else {
                    aes_decrypt::<Aes128CbcDec>(key, iv, data)
                }
            }
            24 => {
                if is_encryptor {
                    aes_encrypt::<Aes192CbcEnc>(key, iv, data)
                } else {
                    aes_decrypt::<Aes192CbcDec>(key, iv, data)
                }
            }
            32 => {
                if is_encryptor {
                    aes_encrypt::<Aes256CbcEnc>(key, iv, data)
                } else {
                    aes_decrypt::<Aes256CbcDec>(key, iv, data)
                }
            }
            _ => None, // Unsupported key size
        };
    }

    // DES/3DES support requires legacy-crypto feature
    #[cfg(feature = "legacy-crypto")]
    if alg_upper.contains("TRIPLEDES") || alg_upper.contains("3DES") {
        // Triple DES - requires 24-byte key
        if key.len() == 24 && iv.len() >= 8 {
            return if is_encryptor {
                tdes_encrypt(key, iv, data)
            } else {
                tdes_decrypt(key, iv, data)
            };
        } else {
            return None;
        }
    }

    #[cfg(feature = "legacy-crypto")]
    if alg_upper.contains("DES") {
        // Single DES - requires 8-byte key
        if key.len() == 8 && iv.len() >= 8 {
            return if is_encryptor {
                des_encrypt(key, iv, data)
            } else {
                des_decrypt(key, iv, data)
            };
        } else {
            return None;
        }
    }

    // DES/3DES not available without legacy-crypto
    #[cfg(not(feature = "legacy-crypto"))]
    if alg_upper.contains("DES") {
        return None;
    }

    // Unknown algorithm - return None (passthrough handled by caller)
    None
}

/// AES encryption helper (CBC mode with PKCS7 padding).
fn aes_encrypt<E: BlockEncryptMut + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    if iv.len() < 16 {
        return None;
    }
    let cipher = E::new_from_slices(key, &iv[..16]).ok()?;
    // Allocate buffer with padding space (PKCS7 adds up to block_size bytes)
    let block_size = 16;
    let padded_len = ((data.len() / block_size) + 1) * block_size;
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    let result = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .ok()?;
    Some(result.to_vec())
}

/// AES decryption helper (CBC mode with PKCS7 padding).
fn aes_decrypt<D: BlockDecryptMut + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    if iv.len() < 16 || data.is_empty() {
        return None;
    }
    let cipher = D::new_from_slices(key, &iv[..16]).ok()?;
    let mut buf = data.to_vec();
    let result = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?;
    Some(result.to_vec())
}

/// DES encryption helper (CBC mode with PKCS7 padding).
#[cfg(feature = "legacy-crypto")]
fn des_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = DesCbcEnc::new_from_slices(key, &iv[..8]).ok()?;
    let block_size = 8;
    let padded_len = ((data.len() / block_size) + 1) * block_size;
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    let result = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .ok()?;
    Some(result.to_vec())
}

/// DES decryption helper (CBC mode with PKCS7 padding).
#[cfg(feature = "legacy-crypto")]
fn des_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let cipher = DesCbcDec::new_from_slices(key, &iv[..8]).ok()?;
    let mut buf = data.to_vec();
    let result = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?;
    Some(result.to_vec())
}

/// TripleDES encryption helper (CBC mode with PKCS7 padding).
#[cfg(feature = "legacy-crypto")]
fn tdes_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = TdesCbcEnc::new_from_slices(key, &iv[..8]).ok()?;
    let block_size = 8;
    let padded_len = ((data.len() / block_size) + 1) * block_size;
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    let result = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .ok()?;
    Some(result.to_vec())
}

/// TripleDES decryption helper (CBC mode with PKCS7 padding).
#[cfg(feature = "legacy-crypto")]
fn tdes_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let cipher = TdesCbcDec::new_from_slices(key, &iv[..8]).ok()?;
    let mut buf = data.to_vec();
    let result = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?;
    Some(result.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::utils::crypto::derive_pbkdf2_key;

    #[test]
    fn test_pbkdf2_sha256_basic() {
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf2_key(password, salt, 1, 32, "SHA256");

        // Verify length
        assert_eq!(key.len(), 32);

        // The result should be deterministic
        let key2 = derive_pbkdf2_key(password, salt, 1, 32, "SHA256");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pbkdf2_sha384() {
        let password = b"test";
        let salt = b"salt123";
        let key = derive_pbkdf2_key(password, salt, 1000, 48, "SHA384");
        assert_eq!(key.len(), 48);
    }

    #[test]
    fn test_pbkdf2_sha512() {
        let password = b"test";
        let salt = b"salt123";
        let key = derive_pbkdf2_key(password, salt, 1000, 64, "SHA512");
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_pbkdf2_iterations_affect_output() {
        let password = b"password";
        let salt = b"salt";

        let key_1 = derive_pbkdf2_key(password, salt, 1, 20, "SHA256");
        let key_1000 = derive_pbkdf2_key(password, salt, 1000, 20, "SHA256");

        // Different iteration counts should produce different keys
        assert_ne!(key_1, key_1000);
    }

    #[test]
    fn test_pbkdf2_salt_affects_output() {
        let password = b"password";
        let salt1 = b"salt1";
        let salt2 = b"salt2";

        let key1 = derive_pbkdf2_key(password, salt1, 1000, 20, "SHA256");
        let key2 = derive_pbkdf2_key(password, salt2, 1000, 20, "SHA256");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf2_case_insensitive_algorithm() {
        let password = b"test";
        let salt = b"salt";

        let key_upper = derive_pbkdf2_key(password, salt, 1, 32, "SHA256");
        let key_lower = derive_pbkdf2_key(password, salt, 1, 32, "sha256");
        let key_mixed = derive_pbkdf2_key(password, salt, 1, 32, "Sha256");

        assert_eq!(key_upper, key_lower);
        assert_eq!(key_upper, key_mixed);
    }

    #[test]
    fn test_pbkdf2_empty_password() {
        let password = b"";
        let salt = b"salt";
        let key = derive_pbkdf2_key(password, salt, 1000, 16, "SHA256");

        assert_eq!(key.len(), 16);
        // Empty password should still produce non-zero key
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_pbkdf2_empty_salt() {
        let password = b"password";
        let salt = b"";
        let key = derive_pbkdf2_key(password, salt, 1000, 16, "SHA256");

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf2_variable_key_length() {
        let password = b"password";
        let salt = b"salt";

        for len in [1, 16, 20, 32, 48, 64, 100] {
            let key = derive_pbkdf2_key(password, salt, 1, len, "SHA256");
            assert_eq!(key.len(), len);
        }
    }

    // NOTE: PBKDF1 tests are in the legacy_tests module below
    // because they require the legacy-crypto feature (PBKDF1 uses SHA1)
    use super::apply_crypto_transform;

    #[test]
    fn test_aes_128_encrypt_decrypt() {
        let key = [0u8; 16]; // 128-bit key
        let iv = [0u8; 16]; // 128-bit IV
        let plaintext = b"Hello, World!";

        // Encrypt
        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext);
        assert!(ciphertext.is_some(), "Encryption should succeed");
        let ciphertext = ciphertext.unwrap();
        assert_ne!(
            ciphertext.as_slice(),
            plaintext,
            "Ciphertext should differ from plaintext"
        );

        // Decrypt
        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext);
        assert!(decrypted.is_some(), "Decryption should succeed");
        assert_eq!(
            decrypted.unwrap(),
            plaintext,
            "Decrypted should match original"
        );
    }

    #[test]
    fn test_aes_192_encrypt_decrypt() {
        let key = [0u8; 24]; // 192-bit key
        let iv = [0u8; 16];
        let plaintext = b"Test message for AES-192";

        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext).unwrap();
        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_encrypt_decrypt() {
        let key = [0u8; 32]; // 256-bit key
        let iv = [0u8; 16];
        let plaintext = b"Test message for AES-256";

        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext).unwrap();
        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rijndael_alias() {
        // Rijndael should work the same as AES
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"Test for Rijndael";

        let ciphertext = apply_crypto_transform("Rijndael", &key, &iv, true, plaintext).unwrap();
        let decrypted = apply_crypto_transform("Rijndael", &key, &iv, false, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Should produce same output as "AES"
        let aes_ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext).unwrap();
        assert_eq!(ciphertext, aes_ciphertext);
    }

    #[test]
    fn test_unsupported_key_size() {
        let bad_key = [0u8; 15]; // Invalid AES key size
        let iv = [0u8; 16];
        let plaintext = b"test";

        let result = apply_crypto_transform("AES", &bad_key, &iv, true, plaintext);
        assert!(result.is_none(), "Should fail with invalid key size");
    }

    #[test]
    fn test_unsupported_algorithm() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"test";

        let result = apply_crypto_transform("UNKNOWN_ALGO", &key, &iv, true, plaintext);
        assert!(result.is_none(), "Should return None for unknown algorithm");
    }

    #[test]
    fn test_case_insensitive_algorithm() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"case test";

        let ct1 = apply_crypto_transform("AES", &key, &iv, true, plaintext).unwrap();
        let ct2 = apply_crypto_transform("aes", &key, &iv, true, plaintext).unwrap();
        let ct3 = apply_crypto_transform("Aes", &key, &iv, true, plaintext).unwrap();

        assert_eq!(ct1, ct2);
        assert_eq!(ct1, ct3);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"test";

        let ct1 = apply_crypto_transform("AES", &key1, &iv, true, plaintext).unwrap();
        let ct2 = apply_crypto_transform("AES", &key2, &iv, true, plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_ivs_produce_different_ciphertext() {
        let key = [0u8; 16];
        let iv1 = [0u8; 16];
        let iv2 = [1u8; 16];
        let plaintext = b"test";

        let ct1 = apply_crypto_transform("AES", &key, &iv1, true, plaintext).unwrap();
        let ct2 = apply_crypto_transform("AES", &key, &iv2, true, plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"";

        // Encryption of empty data should produce padding block
        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext).unwrap();
        assert_eq!(ciphertext.len(), 16); // One full block of padding

        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_block_aligned_plaintext() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = [0u8; 32]; // Exactly 2 blocks

        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, &plaintext).unwrap();
        // PKCS7 adds another block for padding
        assert_eq!(ciphertext.len(), 48);

        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

/// Tests for PBKDF1 and SHA1-based operations that require the legacy-crypto feature
#[cfg(test)]
#[cfg(feature = "legacy-crypto")]
mod legacy_tests {
    use crate::utils::crypto::{derive_pbkdf1_key, derive_pbkdf2_key};
    use sha1::Digest;

    #[test]
    fn test_pbkdf2_sha1_basic() {
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf2_key(password, salt, 1, 20, "SHA1");

        // Verify length
        assert_eq!(key.len(), 20);

        // The result should be deterministic
        let key2 = derive_pbkdf2_key(password, salt, 1, 20, "SHA1");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pbkdf2_sha256_vs_sha1() {
        let password = b"password";
        let salt = b"salt";
        let key_sha256 = derive_pbkdf2_key(password, salt, 1, 32, "SHA256");
        let key_sha1 = derive_pbkdf2_key(password, salt, 1, 32, "SHA1");

        // Different algorithms produce different keys
        assert_ne!(key_sha256, key_sha1);
    }

    #[test]
    fn test_pbkdf2_unknown_algorithm_defaults_to_sha1() {
        let password = b"test";
        let salt = b"salt";

        let key_unknown = derive_pbkdf2_key(password, salt, 1000, 20, "UNKNOWN");
        let key_sha1 = derive_pbkdf2_key(password, salt, 1000, 20, "SHA1");

        assert_eq!(key_unknown, key_sha1);
    }

    #[test]
    fn test_pbkdf1_basic() {
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 16);

        assert_eq!(key.len(), 16);

        // Should be deterministic
        let key2 = derive_pbkdf1_key(password, salt, 100, 16);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pbkdf1_max_natural_length() {
        // PBKDF1 with SHA1 can naturally produce up to 20 bytes
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 20);

        assert_eq!(key.len(), 20);
    }

    #[test]
    fn test_pbkdf1_extended_length() {
        // Request more than 20 bytes (extended mode)
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 32);

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pbkdf1_very_long_key() {
        // Request a very long key (requires multiple extension blocks)
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 100);

        assert_eq!(key.len(), 100);
    }

    #[test]
    fn test_pbkdf1_iterations_affect_output() {
        let password = b"password";
        let salt = b"salt";

        let key_1 = derive_pbkdf1_key(password, salt, 1, 20);
        let key_100 = derive_pbkdf1_key(password, salt, 100, 20);

        assert_ne!(key_1, key_100);
    }

    #[test]
    fn test_pbkdf1_salt_affects_output() {
        let password = b"password";
        let salt1 = b"salt1";
        let salt2 = b"salt2";

        let key1 = derive_pbkdf1_key(password, salt1, 100, 20);
        let key2 = derive_pbkdf1_key(password, salt2, 100, 20);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf1_password_affects_output() {
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = b"salt";

        let key1 = derive_pbkdf1_key(password1, salt, 100, 20);
        let key2 = derive_pbkdf1_key(password2, salt, 100, 20);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf1_empty_password() {
        let password = b"";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 16);

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf1_empty_salt() {
        let password = b"password";
        let salt = b"";
        let key = derive_pbkdf1_key(password, salt, 100, 16);

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf1_single_iteration() {
        // With 1 iteration, the result is just SHA1(password || salt)
        let password = b"test";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 1, 20);

        // Verify it matches SHA1(password || salt)
        let mut hasher = sha1::Sha1::new();
        hasher.update(password);
        hasher.update(salt);
        let expected: [u8; 20] = hasher.finalize().into();

        assert_eq!(key, expected);
    }

    #[test]
    fn test_pbkdf1_variable_key_length() {
        let password = b"password";
        let salt = b"salt";

        for len in [1, 8, 16, 20, 32, 48, 64] {
            let key = derive_pbkdf1_key(password, salt, 100, len);
            assert_eq!(key.len(), len);
        }
    }

    #[test]
    fn test_pbkdf1_different_from_pbkdf2() {
        let password = b"password";
        let salt = b"salt";

        let key1 = derive_pbkdf1_key(password, salt, 100, 20);
        let key2 = derive_pbkdf2_key(password, salt, 100, 20, "SHA1");

        // PBKDF1 and PBKDF2 are different algorithms
        assert_ne!(key1, key2);
    }

    // DES encryption tests

    use super::apply_crypto_transform;

    #[test]
    fn test_des_encrypt_decrypt() {
        let key = [0u8; 8]; // 56-bit key (8 bytes with parity)
        let iv = [0u8; 8]; // 64-bit IV
        let plaintext = b"DES test";

        let ciphertext = apply_crypto_transform("DES", &key, &iv, true, plaintext).unwrap();
        let decrypted = apply_crypto_transform("DES", &key, &iv, false, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tripledes_encrypt_decrypt() {
        let key = [0u8; 24]; // 168-bit key (24 bytes)
        let iv = [0u8; 8]; // 64-bit IV
        let plaintext = b"TripleDES test message";

        let ciphertext = apply_crypto_transform("TripleDES", &key, &iv, true, plaintext).unwrap();
        let decrypted = apply_crypto_transform("TripleDES", &key, &iv, false, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // 3DES alias
        let ciphertext_3des = apply_crypto_transform("3DES", &key, &iv, true, plaintext).unwrap();
        assert_eq!(ciphertext, ciphertext_3des);
    }
}
