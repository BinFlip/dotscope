//! `AssemblyRef` Hash module.
//!
//! This module provides cryptographic hash support for `AssemblyRef` metadata table entries in
//! .NET assemblies. The [`crate::metadata::tables::assemblyref::assemblyrefhash::AssemblyRefHash`]
//! struct encapsulates hash values used for assembly identity verification, supporting both MD5
//! and SHA1 hash algorithms as specified in ECMA-335.
//!
//! # Architecture
//!
//! The module implements cryptographic hash handling for assembly reference verification,
//! providing utilities to create, validate, and format hash values from metadata blob data.
//! Hash algorithm detection is performed automatically based on data length.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyref::assemblyrefhash::AssemblyRefHash`] - Main hash wrapper structure
//! - [`crate::metadata::tables::assemblyref::assemblyrefhash::bytes_to_hex`] - Hex formatting utility
//!
//! # Assembly Reference Hashing
//!
//! `AssemblyRef` hash values serve as cryptographic fingerprints for referenced assemblies, enabling:
//! - **Assembly Identity Verification**: Confirming referenced assemblies match expected versions
//! - **Integrity Checking**: Detecting assembly tampering or corruption
//! - **Version Binding**: Ensuring strong name references resolve to correct assemblies
//! - **Security Analysis**: Identifying potentially malicious assembly substitution
//!
//! # Supported Hash Algorithms
//!
//! This module supports the standard hash algorithms used in .NET assemblies:
//! - **MD5**: 128-bit (16 bytes) hash values (legacy, security deprecated)
//! - **SHA1**: 160-bit (20 bytes) hash values (legacy, security deprecated)
//! - **Custom/Unknown**: Other hash lengths for extensibility
//!
//! # Hash Format
//!
//! Hash data is stored as raw bytes in the metadata blob heap, accessed through
//! [`crate::metadata::tables::assemblyref::AssemblyRef`] entries. The hash algorithm is identified
//! by examining the hash length and cross-referencing with assembly metadata.
//!
//! # Security Considerations
//!
//! Both MD5 and SHA1 are cryptographically broken and should not be used for new applications.
//! Modern .NET assemblies use SHA256 or stronger algorithms. This module supports legacy
//! algorithms for compatibility with older assemblies and forensic analysis.
//!
//! # Thread Safety
//!
//! All operations are thread-safe and do not modify shared state. Hash verification operations
//! create temporary hasher instances and do not affect global state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::assemblyref`] - `AssemblyRef` table entries that reference hash data
//! - [`crate::metadata::streams::Blob`] - Blob heap storage for hash data
//! - [`crate::metadata::tables::assembly`] - Hash algorithm identifiers
//!
//! # References
//!
//! - [ECMA-335 II.23.1.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification
//! - [RFC 1321](https://tools.ietf.org/html/rfc1321) - MD5 Message-Digest Algorithm (deprecated)
//! - [RFC 3174](https://tools.ietf.org/html/rfc3174) - SHA-1 Hash Function (deprecated)

use crate::Result;
use md5::Md5;
use sha1::{Digest, Sha1};
use std::fmt::Write;

/// Convert bytes to lowercase hexadecimal string representation
///
/// Utility function that transforms raw bytes into a lowercase hexadecimal string.
/// Each byte is converted to exactly two lowercase hex characters.
///
/// # Arguments
/// * `bytes` - Slice of bytes to convert
///
/// # Returns
/// String with lowercase hex representation. Length is `bytes.len() * 2`.
///
/// # Performance
/// Pre-allocates output string with exact capacity to avoid reallocations.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex_string, "{byte:02x}").unwrap();
    }
    hex_string
}

/// Cryptographic hash for `AssemblyRef` metadata table entries
///
/// Encapsulates hash values used for assembly identity verification and integrity checking
/// in .NET assembly references. Supports MD5 (16 bytes) and SHA1 (20 bytes) hash algorithms
/// as commonly found in .NET assembly metadata, with extensibility for custom hash formats.
///
/// Hash data originates from the blob heap and serves as a cryptographic fingerprint
/// for referenced assemblies, enabling strong-name binding and tamper detection.
///
/// # Hash Algorithm Detection
///
/// The hash algorithm is inferred from the data length:
/// - **16 bytes**: MD5 hash (legacy, cryptographically broken)
/// - **20 bytes**: SHA1 hash (legacy, cryptographically broken)
/// - **Other lengths**: Custom or unknown hash algorithms
///
/// # Security Notice
///
/// Both MD5 and SHA1 are cryptographically compromised and should not be used for
/// security-critical applications. This implementation exists for compatibility with
/// legacy .NET assemblies and forensic analysis purposes.
#[derive(Debug)]
pub struct AssemblyRefHash {
    /// Raw hash bytes (MD5, SHA1, or other)
    data: Vec<u8>,
}

impl AssemblyRefHash {
    /// Create a new `AssemblyRefHash` from hash data bytes
    ///
    /// Constructs an `AssemblyRefHash` instance from raw hash bytes, typically obtained
    /// from the metadata blob heap. The hash algorithm is inferred from the data length.
    ///
    /// # Arguments
    /// * `data` - Raw hash bytes from the blob heap
    ///
    /// # Returns
    /// * `Ok(AssemblyRefHash)` - Successfully created hash wrapper
    /// * `Err(Error)` - If input data is empty (invalid per ECMA-335)
    ///
    /// # Errors
    /// Returns [`crate::Error`] if the input data is empty, as `AssemblyRef` hash entries
    /// are required to contain actual hash data per ECMA-335 specification.
    pub fn new(data: &[u8]) -> Result<AssemblyRefHash> {
        if data.is_empty() {
            return Err(malformed_error!(
                "AssemblyRefHash entries are not allowed to be empty"
            ));
        }

        Ok(AssemblyRefHash {
            data: data.to_vec(),
        })
    }

    /// Get the underlying hash data bytes
    ///
    /// Returns a reference to the raw hash bytes stored in this instance. The data
    /// represents the cryptographic hash value as stored in the assembly metadata.
    ///
    /// # Returns
    /// Slice containing the raw hash bytes. Length indicates hash algorithm:
    /// - 16 bytes: MD5 hash
    /// - 20 bytes: SHA1 hash  
    /// - Other: Custom/unknown hash algorithm
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a lowercase hexadecimal representation of the hash
    ///
    /// Converts the hash bytes to a lowercase hexadecimal string representation,
    /// suitable for display, logging, and comparison operations.
    ///
    /// # Returns
    /// String containing lowercase hexadecimal representation of hash bytes.
    /// Length is exactly `data().len() * 2` characters.
    #[must_use]
    pub fn hex(&self) -> String {
        bytes_to_hex(&self.data)
    }

    /// Get a human-readable string representation with algorithm identification
    ///
    /// Returns a formatted string that includes both the detected hash algorithm
    /// and the hexadecimal hash value, suitable for debugging and user display.
    ///
    /// Algorithm detection is based on hash length:
    /// - 16 bytes: "MD5: {hex}"
    /// - 20 bytes: "SHA1: {hex}"
    /// - Other: "Unknown: {hex}"
    ///
    /// # Returns
    /// Formatted string with algorithm prefix and lowercase hex hash value.
    #[must_use]
    pub fn to_string_pretty(&self) -> String {
        let hex = self.hex();
        let algorithm = match self.data.len() {
            16 => "MD5",
            20 => "SHA1",
            _ => "Unknown",
        };

        format!("{algorithm}: {hex}")
    }

    /// Verify if this hash matches input data using MD5 algorithm
    ///
    /// Computes the MD5 hash of the provided input data and compares it against
    /// the stored hash value. Only valid for 16-byte (MD5) hashes.
    ///
    /// **Security Warning**: MD5 is cryptographically broken and should not be used
    /// for security purposes. This method exists for compatibility with legacy assemblies.
    ///
    /// # Arguments
    /// * `expected` - Input data to hash and verify against stored hash
    ///
    /// # Returns
    /// * `true` - Hash matches (stored hash is 16 bytes and MD5 computation matches)
    /// * `false` - Hash doesn't match or stored hash is not 16 bytes
    #[must_use]
    pub fn verify_md5(&self, expected: &[u8]) -> bool {
        if self.data.len() != 16 {
            return false;
        }

        let mut hasher = Md5::new();
        hasher.update(expected);
        let result = hasher.finalize();

        self.data == result.as_slice()
    }

    /// Verify if this hash matches input data using SHA1 algorithm
    ///
    /// Computes the SHA1 hash of the provided input data and compares it against
    /// the stored hash value. Only valid for 20-byte (SHA1) hashes.
    ///
    /// **Security Warning**: SHA1 is cryptographically broken and should not be used
    /// for security purposes. This method exists for compatibility with legacy assemblies.
    ///
    /// # Arguments
    /// * `expected` - Input data to hash and verify against stored hash
    ///
    /// # Returns
    /// * `true` - Hash matches (stored hash is 20 bytes and SHA1 computation matches)
    /// * `false` - Hash doesn't match or stored hash is not 20 bytes
    #[must_use]
    pub fn verify_sha1(&self, expected: &[u8]) -> bool {
        if self.data.len() != 20 {
            return false;
        }

        let mut hasher = Sha1::new();
        hasher.update(expected);
        let result = hasher.finalize();

        self.data == result.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create test MD5 hash
    fn create_test_md5_hash() -> Vec<u8> {
        let mut hasher = Md5::new();
        hasher.update(b"test data");
        hasher.finalize().to_vec()
    }

    // Helper function to create test SHA1 hash
    fn create_test_sha1_hash() -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(b"test data");
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_new_with_valid_data() {
        let data = vec![1, 2, 3, 4, 5];
        let hash = AssemblyRefHash::new(&data).unwrap();
        assert_eq!(hash.data(), &data);
    }

    #[test]
    fn test_new_with_empty_data_fails() {
        let result = AssemblyRefHash::new(&[]);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("not allowed to be empty"));
    }

    #[test]
    fn test_data_getter() {
        let test_data = vec![0x12, 0x34, 0x56, 0x78];
        let hash = AssemblyRefHash::new(&test_data).unwrap();
        assert_eq!(hash.data(), &test_data);
    }

    #[test]
    fn test_hex_formatting() {
        let test_data = vec![0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef];
        let hash = AssemblyRefHash::new(&test_data).unwrap();
        assert_eq!(hash.hex(), "12345678abcdef");
    }

    #[test]
    fn test_hex_formatting_with_zeros() {
        let test_data = vec![0x00, 0x01, 0x0a, 0xff];
        let hash = AssemblyRefHash::new(&test_data).unwrap();
        assert_eq!(hash.hex(), "00010aff");
    }

    #[test]
    fn test_to_string_pretty_md5() {
        let md5_hash = create_test_md5_hash();
        let hash = AssemblyRefHash::new(&md5_hash).unwrap();
        let pretty = hash.to_string_pretty();
        assert!(pretty.starts_with("MD5: "));
        assert_eq!(pretty.len(), 5 + 32); // "MD5: " + 32 hex chars
    }

    #[test]
    fn test_to_string_pretty_sha1() {
        let sha1_hash = create_test_sha1_hash();
        let hash = AssemblyRefHash::new(&sha1_hash).unwrap();
        let pretty = hash.to_string_pretty();
        assert!(pretty.starts_with("SHA1: "));
        assert_eq!(pretty.len(), 6 + 40); // "SHA1: " + 40 hex chars
    }

    #[test]
    fn test_to_string_pretty_unknown_length() {
        let unknown_hash = vec![1, 2, 3, 4, 5]; // 5 bytes, not MD5 or SHA1
        let hash = AssemblyRefHash::new(&unknown_hash).unwrap();
        let pretty = hash.to_string_pretty();
        assert!(pretty.starts_with("Unknown: "));
        assert_eq!(pretty, "Unknown: 0102030405");
    }

    #[test]
    fn test_verify_md5_success() {
        let test_input = b"test data";
        let expected_hash = create_test_md5_hash();
        let hash = AssemblyRefHash::new(&expected_hash).unwrap();

        assert!(hash.verify_md5(test_input));
    }

    #[test]
    fn test_verify_md5_failure_wrong_data() {
        let expected_hash = create_test_md5_hash();
        let hash = AssemblyRefHash::new(&expected_hash).unwrap();

        assert!(!hash.verify_md5(b"wrong data"));
    }

    #[test]
    fn test_verify_md5_failure_wrong_length() {
        let sha1_hash = create_test_sha1_hash(); // 20 bytes, not 16
        let hash = AssemblyRefHash::new(&sha1_hash).unwrap();

        assert!(!hash.verify_md5(b"test data"));
    }

    #[test]
    fn test_verify_sha1_success() {
        let test_input = b"test data";
        let expected_hash = create_test_sha1_hash();
        let hash = AssemblyRefHash::new(&expected_hash).unwrap();

        assert!(hash.verify_sha1(test_input));
    }

    #[test]
    fn test_verify_sha1_failure_wrong_data() {
        let expected_hash = create_test_sha1_hash();
        let hash = AssemblyRefHash::new(&expected_hash).unwrap();

        assert!(!hash.verify_sha1(b"wrong data"));
    }

    #[test]
    fn test_verify_sha1_failure_wrong_length() {
        let md5_hash = create_test_md5_hash(); // 16 bytes, not 20
        let hash = AssemblyRefHash::new(&md5_hash).unwrap();

        assert!(!hash.verify_sha1(b"test data"));
    }

    #[test]
    fn test_bytes_to_hex_helper() {
        let bytes = vec![0x00, 0x01, 0x0a, 0x10, 0xff];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "00010a10ff");
    }

    #[test]
    fn test_bytes_to_hex_empty() {
        let hex = bytes_to_hex(&[]);
        assert_eq!(hex, "");
    }

    #[test]
    fn test_with_real_md5_hash() {
        // Test with a known MD5 hash
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut hasher = Md5::new();
        hasher.update(input);
        let expected_hash = hasher.finalize().to_vec();

        let hash = AssemblyRefHash::new(&expected_hash).unwrap();
        assert_eq!(hash.data().len(), 16);
        assert!(hash.verify_md5(input));
        assert!(!hash.verify_sha1(input)); // Wrong algorithm

        let pretty = hash.to_string_pretty();
        assert!(pretty.starts_with("MD5: "));
    }

    #[test]
    fn test_with_real_sha1_hash() {
        // Test with a known SHA1 hash
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut hasher = Sha1::new();
        hasher.update(input);
        let expected_hash = hasher.finalize().to_vec();

        let hash = AssemblyRefHash::new(&expected_hash).unwrap();
        assert_eq!(hash.data().len(), 20);
        assert!(hash.verify_sha1(input));
        assert!(!hash.verify_md5(input)); // Wrong algorithm

        let pretty = hash.to_string_pretty();
        assert!(pretty.starts_with("SHA1: "));
    }

    #[test]
    fn test_edge_case_single_byte() {
        let single_byte = vec![0x42];
        let hash = AssemblyRefHash::new(&single_byte).unwrap();
        assert_eq!(hash.hex(), "42");
        assert_eq!(hash.to_string_pretty(), "Unknown: 42");
        assert!(!hash.verify_md5(b"anything"));
        assert!(!hash.verify_sha1(b"anything"));
    }

    #[test]
    fn test_edge_case_max_byte_values() {
        let max_bytes = vec![0xff; 32];
        let hash = AssemblyRefHash::new(&max_bytes).unwrap();
        assert_eq!(hash.hex(), "f".repeat(64));
        assert!(hash.to_string_pretty().starts_with("Unknown: "));
    }

    #[test]
    fn test_case_sensitivity_in_hex() {
        let test_data = vec![0xab, 0xcd, 0xef];
        let hash = AssemblyRefHash::new(&test_data).unwrap();
        let hex = hash.hex();
        // Verify all hex characters are lowercase
        assert_eq!(hex, "abcdef");
        assert!(!hex.contains('A'));
        assert!(!hex.contains('B'));
        assert!(!hex.contains('C'));
        assert!(!hex.contains('D'));
        assert!(!hex.contains('E'));
        assert!(!hex.contains('F'));
    }
}
