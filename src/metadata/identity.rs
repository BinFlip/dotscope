//! Assembly identity and verification for .NET CIL assemblies.
//!
//! This module provides cryptographic identity representation and verification for .NET assemblies
//! according to ECMA-335 specifications. It supports both full public key storage and compact
//! token-based identity through standardized hashing algorithms (MD5, SHA1).
//!
//! # Identity Types
//!
//! .NET assemblies can be identified in two ways:
//! - **Public Key**: Full RSA public key data for strong-named assemblies
//! - **Public Key Token**: 8-byte hash of the public key for compact representation
//!
//! # Supported Hash Algorithms
//!
//! - **MD5**: Legacy hash algorithm still supported for compatibility
//! - **SHA1**: Standard hash algorithm used by most .NET tools
//! - **Custom**: Framework for additional algorithms (future extension)
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::metadata::identity::Identity;
//! use dotscope::metadata::tables::AssemblyHashAlgorithm;
//!
//! // Create identity from public key
//! let pubkey_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
//! let identity = Identity::from(&pubkey_data, true)?;
//!
//! // Generate token using SHA1
//! let token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
//! println!("Public key token: 0x{:016X}", token);
//!
//! // Create identity directly from token
//! let token_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
//! let token_identity = Identity::from(&token_data, false)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Security Considerations
//!
//! - **Strong Naming**: Public keys provide cryptographic verification of assembly integrity
//! - **Token Collision**: 8-byte tokens may have collisions but are sufficient for most use cases
//! - **Algorithm Choice**: SHA1 is recommended over MD5 for new assemblies
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe. The [`crate::metadata::identity::Identity`]
//! enum contains only owned data and is [`std::marker::Send`] and [`std::marker::Sync`].
//! Hashing operations are stateless and can be called concurrently from multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Assembly and AssemblyRef table identity verification
//! - Binary data reading utilities for key material parsing
//! - External cryptographic libraries (`md5`, `sha1`) for token generation
//!
//! # Assembly Loading
//!
//! The .NET runtime uses assembly identity for:
//! - Version resolution and binding policies
//! - Security policy enforcement
//! - Global Assembly Cache (GAC) storage and retrieval
//! - Type loading and assembly isolation
//! - Cross-assembly type reference resolution

use crate::{metadata::tables::AssemblyHashAlgorithm, utils::read_le, Result};

use md5::{Digest, Md5};
use sha1::Sha1;

/// Assembly identity representation for .NET CIL assemblies.
///
/// Represents the cryptographic identity of a .NET assembly using either a full RSA public key
/// or a compact 8-byte token derived from hashing the public key. This enum supports the two
/// primary assembly identification mechanisms used throughout the .NET ecosystem.
///
/// # Variants
///
/// - [`Identity::PubKey`]: Stores the complete RSA public key data for strong-named assemblies
/// - [`Identity::Token`]: Stores an 8-byte hash of the public key for compact representation
///
/// # Usage in .NET
///
/// - **Strong-named assemblies**: Use public keys for cryptographic verification
/// - **Assembly references**: Often use tokens for compact storage in metadata
/// - **GAC storage**: Uses tokens as part of the unique assembly identifier
/// - **Security policies**: May require full public key validation
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::identity::Identity;
/// use dotscope::metadata::tables::AssemblyHashAlgorithm;
///
/// // Full public key identity
/// let pubkey_data = vec![0x30, 0x82, 0x01, 0x0A]; // RSA public key start
/// let identity = Identity::from(&pubkey_data, true)?;
///
/// // Generate token for compact representation
/// match identity {
///     Identity::PubKey(ref key_data) => {
///         let token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
///         println!("Key length: {} bytes, Token: 0x{:016X}", key_data.len(), token);
///     }
///     Identity::Token(token) => {
///         println!("Direct token: 0x{:016X}", token);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub enum Identity {
    /// Complete RSA public key data for strong-named assemblies.
    ///
    /// Contains the full binary representation of an RSA public key as stored in .NET
    /// assembly metadata. This data can be used for cryptographic verification of
    /// assembly signatures and strong name validation.
    ///
    /// # Format
    /// The data typically follows the standard RSA public key format used by .NET:
    /// - ASN.1 DER encoding for the public key structure
    /// - May include additional .NET-specific metadata
    /// - Variable length depending on key size (typically 1024-4096 bits)
    PubKey(Vec<u8>),

    /// Compact 8-byte token derived from hashing the public key.
    ///
    /// The token is computed as the last 8 bytes of the hash (MD5 or SHA1) of the
    /// public key data. This provides a compact identifier while maintaining
    /// reasonable uniqueness for assembly identification purposes.
    ///
    /// # Token Generation
    /// 1. Hash the complete public key using the specified algorithm
    /// 2. Extract the last 8 bytes of the hash result
    /// 3. Interpret as little-endian 64-bit unsigned integer
    ///
    /// # Collision Resistance
    /// While 8 bytes provides only 64 bits of collision resistance, this is
    /// considered sufficient for .NET assembly identification in practice.
    Token(u64),
}

impl Identity {
    /// Create an [`Identity`] from raw binary data.
    ///
    /// Constructs either a public key or token identity based on the `is_pub` flag.
    /// This is the primary constructor for identity objects parsed from .NET metadata.
    ///
    /// # Arguments
    /// * `data` - Raw binary data from assembly metadata
    /// * `is_pub` - `true` for public key data, `false` for token data
    ///
    /// # Data Requirements
    /// - **Public Key**: Any length data (copied as-is)
    /// - **Token**: Exactly 8 bytes interpreted as little-endian `u64`
    ///
    /// # Returns
    /// - [`Identity::PubKey`] if `is_pub` is `true`
    /// - [`Identity::Token`] if `is_pub` is `false`
    ///
    /// # Errors
    /// Returns [`crate::Error::OutOfBounds`] if:
    /// - Token creation requested but data has fewer than 8 bytes
    /// - Data cannot be read as little-endian `u64`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::Identity;
    ///
    /// // Create public key identity
    /// let pubkey_data = vec![0x30, 0x82, 0x01, 0x0A, /* ... rest of key ... */];
    /// let pubkey_identity = Identity::from(&pubkey_data, true)?;
    ///
    /// // Create token identity
    /// let token_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    /// let token_identity = Identity::from(&token_data, false)?;
    ///
    /// match token_identity {
    ///     Identity::Token(token) => println!("Token: 0x{:016X}", token),
    ///     _ => unreachable!(),
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from(data: &[u8], is_pub: bool) -> Result<Self> {
        Ok(if is_pub {
            Identity::PubKey(data.to_vec())
        } else {
            Identity::Token(read_le::<u64>(data)?)
        })
    }

    /// Generate a token from this identity using the specified hash algorithm.
    ///
    /// Computes an 8-byte token that uniquely identifies this assembly. For public key
    /// identities, this involves hashing the key data. For token identities, this
    /// returns the stored token value regardless of the algorithm specified.
    ///
    /// # Algorithm Support
    /// - **MD5** ([`crate::metadata::tables::AssemblyHashAlgorithm::MD5`]): Legacy algorithm, 16-byte hash
    /// - **SHA1** ([`crate::metadata::tables::AssemblyHashAlgorithm::SHA1`]): Standard algorithm, 20-byte hash
    /// - **Others**: Will panic with `unimplemented!()` for unsupported algorithms
    ///
    /// # Token Extraction
    /// The token is always the **last 8 bytes** of the hash result, interpreted as
    /// a little-endian 64-bit unsigned integer. This follows the .NET runtime convention.
    ///
    /// # Arguments
    /// * `algo` - Hash algorithm identifier from [`crate::metadata::tables::AssemblyHashAlgorithm`]
    ///
    /// # Returns
    /// 64-bit token value suitable for assembly identification and comparison.
    ///
    /// # Errors
    /// Returns [`crate::Error::OutOfBounds`] if hash result cannot be read as `u64`.
    ///
    /// # Panics
    /// Panics with `unimplemented!()` for unsupported hash algorithms.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::Identity;
    /// use dotscope::metadata::tables::AssemblyHashAlgorithm;
    ///
    /// let pubkey_data = vec![0x30, 0x82, /* ... public key data ... */];
    /// let identity = Identity::from(&pubkey_data, true)?;
    ///
    /// // Generate token using SHA1 (recommended)
    /// let sha1_token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
    /// println!("SHA1 token: 0x{:016X}", sha1_token);
    ///
    /// // Generate token using MD5 (legacy)
    /// let md5_token = identity.to_token(AssemblyHashAlgorithm::MD5)?;
    /// println!("MD5 token: 0x{:016X}", md5_token);
    ///
    /// // Different algorithms produce different tokens
    /// assert_ne!(sha1_token, md5_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// Hash operations are stateless and do not modify the identity instance.
    pub fn to_token(&self, algo: u32) -> Result<u64> {
        match &self {
            Identity::PubKey(data) => match algo {
                AssemblyHashAlgorithm::MD5 => {
                    let mut hasher = Md5::new();
                    hasher.update(data);

                    let result = hasher.finalize();

                    read_le::<u64>(&result[result.len() - 8..])
                }
                AssemblyHashAlgorithm::SHA1 => {
                    let mut hasher = Sha1::new();
                    hasher.update(data);

                    let result = hasher.finalize();

                    read_le::<u64>(&result[result.len() - 8..])
                }
                _ => unimplemented!(),
            },
            Identity::Token(token) => Ok(*token),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::AssemblyHashAlgorithm;

    #[test]
    fn test_identity_from_pubkey() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::from(&data, true).unwrap();

        match identity {
            Identity::PubKey(pubkey_data) => {
                assert_eq!(pubkey_data, data);
            }
            Identity::Token(_) => panic!("Expected PubKey variant"),
        }
    }

    #[test]
    fn test_identity_from_token() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let identity = Identity::from(&data, false).unwrap();

        match identity {
            Identity::Token(token) => {
                // Token should be little-endian interpretation of the bytes
                assert_eq!(token, 0xF0DEBC9A78563412);
            }
            Identity::PubKey(_) => panic!("Expected Token variant"),
        }
    }

    #[test]
    fn test_identity_from_empty_pubkey() {
        let data = vec![];
        let identity = Identity::from(&data, true).unwrap();

        match identity {
            Identity::PubKey(pubkey_data) => {
                assert!(pubkey_data.is_empty());
            }
            Identity::Token(_) => panic!("Expected PubKey variant"),
        }
    }

    #[test]
    fn test_identity_from_token_insufficient_data() {
        let data = vec![1, 2, 3]; // Less than 8 bytes
        let result = Identity::from(&data, false);

        // Should return an error because we need 8 bytes for a u64
        assert!(result.is_err());
    }

    #[test]
    fn test_to_token_from_pubkey_md5() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        // Manually compute MD5 to verify
        let mut hasher = Md5::new();
        hasher.update(&pubkey_data);
        let result = hasher.finalize();
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = read_le::<u64>(last_8_bytes).unwrap();

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_pubkey_sha1() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();

        // Manually compute SHA1 to verify
        let mut hasher = Sha1::new();
        hasher.update(&pubkey_data);
        let result = hasher.finalize();
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = read_le::<u64>(last_8_bytes).unwrap();

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_token_identity() {
        let original_token = 0x123456789ABCDEF0;
        let identity = Identity::Token(original_token);

        // When called on a Token identity, should return the original token regardless of algorithm
        let result_md5 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();
        let result_sha1 = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();
        let result_none = identity.to_token(AssemblyHashAlgorithm::NONE).unwrap();

        assert_eq!(result_md5, original_token);
        assert_eq!(result_sha1, original_token);
        assert_eq!(result_none, original_token);
    }

    #[test]
    #[should_panic(expected = "not implemented")]
    fn test_to_token_unsupported_algorithm() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let identity = Identity::PubKey(pubkey_data);

        // Using an unsupported algorithm should panic with unimplemented!()
        let _ = identity.to_token(0x9999);
    }

    #[test]
    fn test_to_token_empty_pubkey_md5() {
        let identity = Identity::PubKey(vec![]);
        let token = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        // Hash of empty data should still produce a valid token
        let mut hasher = Md5::new();
        hasher.update([]);
        let result = hasher.finalize();
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = read_le::<u64>(last_8_bytes).unwrap();

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_empty_pubkey_sha1() {
        let identity = Identity::PubKey(vec![]);
        let token = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();

        // Hash of empty data should still produce a valid token
        let mut hasher = Sha1::new();
        hasher.update([]);
        let result = hasher.finalize();
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = read_le::<u64>(last_8_bytes).unwrap();

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_large_pubkey_data() {
        // Test with a larger public key (typical RSA key size)
        let large_pubkey: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let identity = Identity::PubKey(large_pubkey.clone());

        let token_md5 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();
        let token_sha1 = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();

        // MD5 and SHA1 should produce different tokens for the same data
        assert_ne!(token_md5, token_sha1);

        // Both tokens should be valid (non-zero in this case since we have substantial input data)
        assert_ne!(token_md5, 0);
        assert_ne!(token_sha1, 0);
    }

    #[test]
    fn test_hash_algorithm_consistency() {
        let pubkey_data = vec![42, 123, 255, 0, 17, 88, 99, 200];
        let identity = Identity::PubKey(pubkey_data);

        // Multiple calls with the same algorithm should produce the same result
        let token1 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();
        let token2 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        assert_eq!(token1, token2);
    }

    #[test]
    fn test_from_exact_8_bytes() {
        let data = vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88];
        let identity = Identity::from(&data, false).unwrap();

        match identity {
            Identity::Token(token) => {
                // Should be exactly the 8 bytes interpreted as little-endian u64
                assert_eq!(token, 0x8899AABBCCDDEEFF);
            }
            Identity::PubKey(_) => panic!("Expected Token variant"),
        }
    }

    #[test]
    fn test_from_more_than_8_bytes_token() {
        // When creating a token from more than 8 bytes, only the first 8 should be used
        let data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let identity = Identity::from(&data, false).unwrap();

        match identity {
            Identity::Token(token) => {
                // Should only use the first 8 bytes
                assert_eq!(token, 0x8877665544332211);
            }
            Identity::PubKey(_) => panic!("Expected Token variant"),
        }
    }

    #[test]
    fn test_identity_variants_different_behavior() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let pubkey_identity = Identity::from(&pubkey_data, true).unwrap();
        let token_identity = Identity::from(&pubkey_data, false).unwrap();

        // The PubKey identity will hash the data
        let pubkey_token = pubkey_identity
            .to_token(AssemblyHashAlgorithm::MD5)
            .unwrap();

        // The Token identity will return the direct interpretation
        let direct_token = token_identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        // These should be different values
        assert_ne!(pubkey_token, direct_token);
    }
}
