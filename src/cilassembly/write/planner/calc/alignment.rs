//! Alignment and utility functions for size calculations.
//!
//! This module provides fundamental utility functions used across the calculation
//! modules for alignment and ECMA-335 compressed integer encoding.

/// Helper function to calculate the size of a compressed uint according to ECMA-335.
///
/// Returns the number of bytes needed to encode the given value using the
/// ECMA-335 compressed integer format:
/// - Values < 0x80 use 1 byte
/// - Values < 0x4000 use 2 bytes  
/// - Larger values use 4 bytes
///
/// # Arguments
/// * `value` - The value to calculate encoding size for
///
/// # Returns
/// The number of bytes (1, 2, or 4) needed to encode the value
pub fn compressed_uint_size(value: usize) -> u64 {
    if value < 0x80 {
        1
    } else if value < 0x4000 {
        2
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressed_uint_size() {
        // Single byte range (0-127)
        assert_eq!(compressed_uint_size(0), 1);
        assert_eq!(compressed_uint_size(0x7F), 1);

        // Two byte range (128-16383)
        assert_eq!(compressed_uint_size(0x80), 2);
        assert_eq!(compressed_uint_size(0x3FFF), 2);

        // Four byte range (16384+)
        assert_eq!(compressed_uint_size(0x4000), 4);
        assert_eq!(compressed_uint_size(0x10000), 4);
    }
}
