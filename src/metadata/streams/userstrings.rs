//! User String Heap (`#US`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#US` heap, which stores user-defined string literals in UTF-16 encoding.
//! This module exposes the [`crate::metadata::streams::UserStrings`] struct for safe access and parsing of user strings referenced by metadata tables.
//!
//! The `#US` heap contains string literals that appear directly in user source code, stored with length prefixes
//! and encoded in UTF-16 format. This is distinct from the [`crate::metadata::streams::strings`] heap which
//! contains system identifiers and metadata names.
//!
//! # Format
//!
//! The user strings heap starts with a null byte (index 0), followed by length-prefixed UTF-16 strings.
//! Each string entry consists of:
//! - Length byte(s) indicating the total size including the terminal byte
//! - UTF-16 encoded string data (variable length)
//! - UTF-16 null terminator (0x0000)  
//! - Terminal byte (0x00)
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::metadata::streams::UserStrings;
//!
//! // Sample heap data with "Hello" string
//! let data = &[
//!     0x00,                                    // Null entry at index 0
//!     0x0D,                                    // Length: 13 bytes total
//!     0x48, 0x00, 0x65, 0x00, 0x6C, 0x00,    // "Hel" in UTF-16
//!     0x6C, 0x00, 0x6F, 0x00,                 // "lo" in UTF-16
//!     0x00, 0x00,                             // UTF-16 null terminator
//!     0x00                                    // Terminal byte
//! ];
//!
//! let heap = UserStrings::from(data)?;
//! let string = heap.get(1)?;
//! assert_eq!(string.to_string_lossy(), "Hello");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Reference
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::utils::{read_compressed_int, read_compressed_int_at};
use crate::Result;

use widestring::U16Str;

/// The `UserStrings` object provides helper methods to access the data within the '#US' heap.
///
/// This heap contains all user-defined string literals from the source code, stored in UTF-16 encoding
/// with length prefixes. Each string is referenced by its byte offset from metadata tables like
/// the Constant table when the constant type is a string literal.
///
/// The heap format follows ECMA-335 specification with:
/// - Index 0 always contains a null byte
/// - Each string prefixed by its total byte length (including terminal byte)
/// - UTF-16 encoded string data followed by null terminator and terminal byte
///
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::streams::UserStrings;
///
/// // Create from heap data
/// let data = &[0u8, 65, 0, 0, 0];
/// let us = UserStrings::from(data)?;
/// let s = us.get(1)?;
/// assert_eq!(s.to_string_lossy(), "A");
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Iteration Example
///
/// ```rust,ignore
/// use dotscope::metadata::streams::UserStrings;
///
/// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // "Hi"
/// let heap = UserStrings::from(data)?;
///
/// for (offset, string) in heap.iter() {
///     println!("String at offset {}: {}", offset, string.to_string_lossy());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Reference
/// * [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
///
/// User strings heap data accessor
///
/// Provides safe access to UTF-16 encoded string literals stored in the `#US` metadata heap.
/// The heap data must start with a null byte at index 0, followed by length-prefixed strings.
pub struct UserStrings<'a> {
    /// Raw heap data starting with null byte at index 0
    data: &'a [u8],
}

impl<'a> UserStrings<'a> {
    /// Create a `UserStrings` object from a sequence of bytes
    ///
    /// Validates that the heap data starts with the required null byte at index 0 according to
    /// ECMA-335 specification. The heap may contain multiple UTF-16 strings with length prefixes.
    ///
    /// # Arguments
    /// * `data` - The byte slice containing the user strings heap data
    ///
    /// # Returns
    /// * `Ok(UserStrings)` - Valid heap accessor
    ///
    /// # Errors
    /// * [`crate::Error::OutOfBounds`] - If data is empty or doesn't start with null byte
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// // Valid heap data
    /// let data = &[0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // null + "Hi"
    /// let heap = UserStrings::from(data)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from(data: &'a [u8]) -> Result<UserStrings<'a>> {
        if data.is_empty() || data[0] != 0 {
            return Err(out_of_bounds_error!());
        }

        Ok(UserStrings { data })
    }

    /// Get a view into the string contained at the provided location.
    ///
    /// Retrieves a UTF-16 string reference from the heap at the specified byte offset.
    /// The method processes the length prefix and validates the string data according to
    /// the .NET runtime implementation researched from the official runtime source code.
    ///
    /// # Arguments
    /// * `index` - The byte offset within the heap (typically from metadata table references)
    ///
    /// # Returns
    /// * `Ok(&U16Str)` - Reference to the UTF-16 string at the specified offset
    ///
    /// # Errors
    /// * [`crate::Error::OutOfBounds`] - If index is out of bounds
    /// * [`crate::Error`] - If string data is malformed or has invalid UTF-16 length
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00]; // "Hi"
    /// let heap = UserStrings::from(data)?;
    /// let string = heap.get(1)?;
    /// assert_eq!(string.to_string_lossy(), "Hi");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Panics
    /// May panic if the underlying slice conversion fails due to memory alignment issues
    pub fn get(&self, index: usize) -> Result<&'a U16Str> {
        if index >= self.data.len() {
            return Err(out_of_bounds_error!());
        }

        let (total_bytes, compressed_length_size) = read_compressed_int_at(self.data, index)?;
        let data_start = index + compressed_length_size;

        if total_bytes == 0 {
            return Err(malformed_error!(
                "Invalid zero-length string at index {}",
                index
            ));
        }

        if total_bytes == 1 {
            static EMPTY_U16: [u16; 0] = [];
            return Ok(U16Str::from_slice(&EMPTY_U16));
        }

        // Total bytes includes UTF-16 data + terminator byte (1 byte)
        // So actual UTF-16 data is total_bytes - 1
        let utf16_length = total_bytes - 1;

        let total_data_end = data_start + total_bytes;
        if total_data_end > self.data.len() {
            return Err(out_of_bounds_error!());
        }

        if utf16_length % 2 != 0 {
            return Err(malformed_error!("Invalid UTF-16 length at index {}", index));
        }

        let utf16_data_end = data_start + utf16_length;
        let utf16_data = &self.data[data_start..utf16_data_end];

        let str_slice = unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            core::ptr::slice_from_raw_parts(utf16_data.as_ptr().cast::<u16>(), utf16_data.len() / 2)
                .as_ref()
                .unwrap()
        };

        Ok(U16Str::from_slice(str_slice))
    }

    /// Returns an iterator over all user strings in the heap
    ///
    /// Provides zero-copy access to all UTF-16 user strings with their byte offsets.
    /// Each iteration yields a `(usize, &U16CStr)` with the offset and string content.
    /// The iterator automatically handles length prefixes and skips the initial null entry.
    ///
    /// # Returns
    /// * [`crate::metadata::streams::userstrings::UserStringsIterator`] - Iterator over heap entries
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // "Hi" in UTF-16
    /// let user_strings = UserStrings::from(data)?;
    ///
    /// for (offset, string) in user_strings.iter() {
    ///     println!("String at {}: '{}'", offset, string.to_string_lossy());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> UserStringsIterator<'_> {
        UserStringsIterator::new(self)
    }

    /// Returns the raw underlying data of the userstring heap.
    ///
    /// This provides access to the complete heap data including the null byte at offset 0
    /// and all userstring entries in their original binary format.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> IntoIterator for &'a UserStrings<'a> {
    type Item = (usize, &'a U16Str);
    type IntoIter = UserStringsIterator<'a>;

    /// Create an iterator over the user strings heap.
    ///
    /// This allows using `for` loops directly on [`crate::metadata::streams::UserStrings`] references.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
    /// let heap = UserStrings::from(data)?;
    ///
    /// for (offset, string) in &heap {
    ///     println!("String: {}", string.to_string_lossy());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over entries in the `#US` (`UserStrings`) heap
///
/// Provides zero-copy access to UTF-16 user strings with their byte offsets.
/// Each iteration returns a `(usize, &U16Str)` containing the offset and string content.
/// The iterator automatically handles length prefixes and string format validation.
///
/// # Iteration Behavior
///
/// - Starts at offset 1 (skipping the null entry at offset 0)
/// - Reads length prefix to determine string size
/// - Advances position based on string length + overhead bytes
/// - Stops iteration on malformed string data
///
/// Create via [`crate::metadata::streams::UserStrings::iter()`] or using `&heap` in for loops.
pub struct UserStringsIterator<'a> {
    /// Reference to the user strings heap being iterated
    user_strings: &'a UserStrings<'a>,
    /// Current position within the user strings heap
    position: usize,
}

impl<'a> UserStringsIterator<'a> {
    /// Create a new iterator starting at position 1 (after the null entry)
    pub(crate) fn new(user_strings: &'a UserStrings<'a>) -> Self {
        Self {
            user_strings,
            position: 1,
        }
    }
}

impl<'a> Iterator for UserStringsIterator<'a> {
    type Item = (usize, &'a U16Str);

    /// Get the next user string from the heap
    ///
    /// Returns `(offset, string)` for valid entries, `None` when the heap is exhausted
    /// or when malformed string data is encountered.
    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.user_strings.data.len() {
            return None;
        }

        let start_position = self.position;

        // Read compressed length according to ECMA-335 II.24.2.4 and .NET runtime implementation
        let (total_bytes, compressed_length_size) = if let Ok((length, consumed)) =
            read_compressed_int(self.user_strings.data, &mut self.position)
        {
            // Reset position since read_compressed_int advanced it
            self.position -= consumed;
            (length, consumed)
        } else {
            // Try to skip over bad data by advancing one byte and trying again
            self.position += 1;
            if self.position < self.user_strings.data.len() {
                return self.next(); // Recursive call to try next position
            }
            return None;
        };

        // Handle zero-length entries (invalid according to .NET spec, but may exist in malformed data)
        if total_bytes == 0 {
            self.position += compressed_length_size;
            if self.position < self.user_strings.data.len() {
                return self.next(); // Recursive call to try next position
            }
            return None;
        }

        let Ok(string) = self.user_strings.get(start_position) else {
            // Skip over the malformed entry
            self.position += compressed_length_size + total_bytes;
            if self.position < self.user_strings.data.len() {
                return self.next(); // Recursive call to try next position
            }
            return None;
        };

        let new_position = self.position + compressed_length_size + total_bytes;
        self.position = new_position;

        Some((start_position, string))
    }
}

#[cfg(test)]
mod tests {
    use widestring::u16str;

    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data: [u8; 29] = [
            0x00, 0x1b, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x2c, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00, 0x00
        ];

        let us_str = UserStrings::from(&data).unwrap();

        assert_eq!(us_str.get(1).unwrap(), u16str!("Hello, World!"));
    }

    #[test]
    fn invalid() {
        let data_empty = [];
        if UserStrings::from(&data_empty).is_ok() {
            panic!("This should not be valid!")
        }

        let data_invalid_first = [
            0x22, 0x1b, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x2c, 0x00,
            0x20, 0x00, 0x57, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        if UserStrings::from(&data_invalid_first).is_ok() {
            panic!("This should not be valid!")
        }

        let data_invalid_first = [0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];
        let us_str = UserStrings::from(&data_invalid_first).unwrap();
        if us_str.get(1).is_ok() {
            panic!("This should not be valid!")
        }
    }

    #[test]
    fn test_userstrings_iterator_basic() {
        // Simple test case - "Hi" in UTF-16 with compressed length prefix
        // Based on .NET runtime format: [compressed_length][utf16_data][terminator_byte]
        // Length 0x05 = 5 bytes: 4 bytes UTF-16 + 1 terminator byte
        let data = [
            0x00, // Initial null byte
            0x05, // Length: 5 bytes total (4 UTF-16 + 1 terminator)
            0x48, 0x00, 0x69, 0x00, // "Hi" in UTF-16 LE
            0x00, // Terminator byte (no high chars)
        ];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "Hi");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_multiple() {
        // Two strings: "Hi" (length 5) and "Bye" (length 7)
        // Format: [compressed_length][utf16_data][terminator_byte]
        let data = [
            0x00, // Initial null byte
            0x05, // "Hi": len=5 (4 UTF-16 + 1 terminator)
            0x48, 0x00, 0x69, 0x00, // "Hi" in UTF-16 LE
            0x00, // Terminator byte
            0x07, // "Bye": len=7 (6 UTF-16 + 1 terminator)
            0x42, 0x00, 0x79, 0x00, 0x65, 0x00, // "Bye" in UTF-16 LE
            0x00, // Terminator byte
        ];

        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "Hi");

        let second = iter.next().unwrap();
        assert_eq!(second.0, 7); // Correct: 1 (start) + 1 (length byte) + 5 (data+terminator) = 7
        assert_eq!(second.1.to_string_lossy(), "Bye");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_empty_string() {
        // Empty string followed by "Hi"
        // Empty string: length 1 (0 UTF-16 + 1 terminator), then "Hi": length 5
        let data = [
            0x00, // Initial null byte
            0x01, // Empty string: len=1 (just terminator)
            0x00, // Terminator byte
            0x05, // "Hi": len=5 (4 UTF-16 + 1 terminator)
            0x48, 0x00, 0x69, 0x00, // "Hi" in UTF-16 LE
            0x00, // Terminator byte
        ];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "");

        let second = iter.next().unwrap();
        assert_eq!(second.0, 3);
        assert_eq!(second.1.to_string_lossy(), "Hi");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_long_string() {
        // Test with a longer string - 5 characters in UTF-16
        let mut data = vec![0x00]; // Initial null byte

        // "AAAAA" = 5 chars * 2 bytes + 1 terminator = 11 bytes total
        data.push(0x0B); // Length 11

        // Add 10 bytes of UTF-16 data (5 characters: "AAAAA")
        for _ in 0..5 {
            data.extend_from_slice(&[0x41, 0x00]);
        }
        data.push(0x00); // Terminator byte

        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "AAAAA");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_truncated_data() {
        // String claims length 7 but only 5 bytes available
        let data = [0x00, 0x07, 0x48, 0x00, 0x69];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        // Iterator should stop on malformed data
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_invalid_utf16_length() {
        // Odd number of bytes for UTF-16 data
        let data = [0x00, 0x04, 0x48, 0x00, 0x69]; // Length 3 but only 3 bytes (should be even)
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        // Iterator should stop on malformed data
        assert!(iter.next().is_none());
    }
}
