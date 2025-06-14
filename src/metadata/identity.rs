//! Assembly identity and verification for .NET CIL assemblies.
//!
//! This module provides the [`Identity`] enum and related logic for representing and computing
//! assembly identities in .NET, including public-key and token-based identities. It supports
//! hashing with MD5 and SHA1 as specified by the ECMA-335 standard.
//!
//! # Key Types
//! - [`Identity`] - Represents either a full public key or a token (hash) identity
//!
//! # Example
//! ```rust,no_run
//! use dotscope::metadata::identity::Identity;
//! let pubkey = vec![1,2,3,4,5,6,7,8];
//! let id = Identity::from(&pubkey, true).unwrap();
//! ```

use crate::{file::io::read_le, metadata::tables::AssemblyHashAlgorithm, Result};

use md5::{Digest, Md5};
use sha1::Sha1;

/// An identifier for `Assembly` in .NET CIL.
/// Can be either a public-key or a hashed Token, indication from 'Flags'.
pub enum Identity {
    /// The full RSA public-key
    PubKey(Vec<u8>),
    /// 8-byte end of the hash of the public-key and type defined by `AssemblyHashAlgorithm` of the target assembly
    Token(u64),
}

impl Identity {
    /// Create an `Identity` from raw data.
    ///
    /// # Arguments
    /// * `data`    - The data to create the identity from
    /// * `is_pub`  - Is it a token, or a public-key
    ///
    /// # Errors
    /// Returns an error if the data cannot be read as the appropriate type.
    pub fn from(data: &[u8], is_pub: bool) -> Result<Self> {
        Ok(if is_pub {
            Identity::PubKey(data.to_vec())
        } else {
            Identity::Token(read_le::<u64>(data)?)
        })
    }

    /// Get the token based on the provided `algo_id`; The token is the last 8 bytes of the hash of the public-key.
    ///
    /// # Arguments
    /// * `algo` - The `AssemblyHashAlgorithm` that the target `Assembly` uses
    ///
    /// # Errors
    /// Returns an error if the algorithm is not supported or if hashing fails.
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
