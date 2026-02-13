//! Base64 encoding and decoding utilities.
//!
//! This module provides dependency-free Base64 encoding and decoding functions
//! that match the behavior of .NET's `System.Convert.ToBase64String` and
//! `System.Convert.FromBase64String`.

/// Encodes binary data to a Base64 string.
///
/// This is a simple, dependency-free implementation of Base64 encoding that matches
/// the output of `System.Convert.ToBase64String`.
///
/// # Arguments
///
/// * `data` - The bytes to encode
///
/// # Returns
///
/// A Base64-encoded string with padding.
///
/// # Examples
///
/// ```rust, ignore
/// use dotscope::utils::base64_encode;
///
/// assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
/// assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
/// ```
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = data.get(i + 1).copied().unwrap_or(0);
        let b2 = data.get(i + 2).copied().unwrap_or(0);

        let n = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);

        result.push(char::from(ALPHABET[(n >> 18 & 0x3F) as usize]));
        result.push(char::from(ALPHABET[(n >> 12 & 0x3F) as usize]));

        if i + 1 < data.len() {
            result.push(char::from(ALPHABET[(n >> 6 & 0x3F) as usize]));
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(char::from(ALPHABET[(n & 0x3F) as usize]));
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Decodes a Base64 string to binary data.
///
/// This is a simple, dependency-free implementation of Base64 decoding that matches
/// the behavior of `System.Convert.FromBase64String`.
///
/// # Arguments
///
/// * `s` - The Base64-encoded string to decode
///
/// # Returns
///
/// `Some(Vec<u8>)` on successful decode, `None` if the input is invalid Base64.
///
/// # Examples
///
/// ```rust, ignore
/// use dotscope::utils::base64_decode;
///
/// assert_eq!(base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
/// assert_eq!(base64_decode("SGVsbG8sIFdvcmxkIQ=="), Some(b"Hello, World!".to_vec()));
/// ```
#[must_use]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const DECODE_TABLE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let s = s.trim();
    if s.is_empty() {
        return Some(Vec::new());
    }

    let mut result = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();

    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut i = 0;
    while i < bytes.len() {
        let mut n: u32 = 0;
        let mut pad_count = 0;

        for j in 0..4 {
            let b = bytes[i + j];
            if b == b'=' {
                pad_count += 1;
                continue;
            }
            if b >= 128 {
                return None;
            }
            let val = DECODE_TABLE[usize::from(b)];
            if val < 0 {
                return None;
            }
            // val is checked to be >= 0, so casting to u32 is safe
            // Sign loss is intentional: we've validated val >= 0
            #[allow(clippy::cast_sign_loss)]
            let val_u32 = val as u32;
            n |= val_u32 << (18 - j * 6);
        }

        // Truncation to u8 is intentional - we're extracting individual bytes
        #[allow(clippy::cast_possible_truncation)]
        {
            result.push((n >> 16) as u8);
            if pad_count < 2 {
                result.push((n >> 8) as u8);
            }
            if pad_count < 1 {
                result.push(n as u8);
            }
        }

        i += 4;
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(
            base64_decode("SGVsbG8sIFdvcmxkIQ=="),
            Some(b"Hello, World!".to_vec())
        );
        assert_eq!(base64_decode(""), Some(Vec::new()));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_invalid() {
        // Invalid character
        assert_eq!(base64_decode("SGVs!G8="), None);
        // Wrong length (not multiple of 4)
        assert_eq!(base64_decode("SGVsbG8"), None);
    }
}
