use crate::Result;
use md5::Md5;
use sha1::{Digest, Sha1};
use std::fmt::Write;

/// Helper function to convert bytes to lowercase hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex_string, "{:02x}", byte).unwrap();
    }
    hex_string
}

/// The hash of a reference, is a variant of `AssemblyHashAlgorithm`
#[derive(Debug)]
pub struct AssemblyRefHash {
    data: Vec<u8>,
}

impl AssemblyRefHash {
    /// Create a new `AssemblyRefHash` from the input data
    ///
    /// ## Arguments
    /// * 'data' - The data to parse from
    ///
    /// # Errors
    /// Returns an error if the input data is empty
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

    /// Get the underlying data
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a formatted hex representation of the hash
    #[must_use]
    pub fn hex(&self) -> String {
        bytes_to_hex(&self.data)
    }

    /// Return a human-readable representation
    #[must_use]
    pub fn to_string_pretty(&self) -> String {
        let hex = self.hex();
        let algorithm = match self.data.len() {
            16 => "MD5",
            20 => "SHA1",
            _ => "Unknown",
        };

        format!("{}: {}", algorithm, hex)
    }

    /// Verify if the hash matches the expected value using MD5
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

    /// Verify if the hash matches the expected value using SHA1
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
