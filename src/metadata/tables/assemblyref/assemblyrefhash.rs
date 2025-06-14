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
    #[must_use] pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a formatted hex representation of the hash
    #[must_use] pub fn hex(&self) -> String {
        bytes_to_hex(&self.data)
    }

    /// Return a human-readable representation
    #[must_use] pub fn to_string_pretty(&self) -> String {
        let hex = self.hex();
        let algorithm = match self.data.len() {
            16 => "MD5",
            20 => "SHA1",
            _ => "Unknown",
        };

        format!("{}: {}", algorithm, hex)
    }

    /// Verify if the hash matches the expected value using MD5
    #[must_use] pub fn verify_md5(&self, expected: &[u8]) -> bool {
        if self.data.len() != 16 {
            return false;
        }

        let mut hasher = Md5::new();
        hasher.update(expected);
        let result = hasher.finalize();

        self.data == result.as_slice()
    }

    /// Verify if the hash matches the expected value using SHA1
    #[must_use] pub fn verify_sha1(&self, expected: &[u8]) -> bool {
        if self.data.len() != 20 {
            return false;
        }

        let mut hasher = Sha1::new();
        hasher.update(expected);
        let result = hasher.finalize();

        self.data == result.as_slice()
    }
}
