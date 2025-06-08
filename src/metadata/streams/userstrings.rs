//! User String Heap (`#US`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#US` heap, which stores user-defined string literals in UTF-16 encoding.
//! This module exposes the [`UserStrings`] struct for safe access and parsing of user strings referenced by metadata tables.
//!
//! # Reference
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{Error::OutOfBounds, Result};

use widestring::U16CStr;

/// The `UserStrings` object provides helper methods to access the data within the '#US' heap. That heap contains
/// all user defined Strings, and this object allows to interface with it, and parse and process it properly according
/// to the standard.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::streams::UserStrings;
/// let data = &[0u8, 65, 0, 0, 0];
/// let us = UserStrings::from(data).unwrap();
/// let s = us.get(1).unwrap();
/// assert_eq!(s.to_string_lossy(), "A");
/// ```
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.4
///
pub struct UserStrings<'a> {
    data: &'a [u8],
}

impl<'a> UserStrings<'a> {
    /// Create a `UserStrings` object from a sequence of bytes
    ///
    /// # Arguments
    /// * 'data' - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the user string heap data is empty or malformed
    pub fn from(data: &'a [u8]) -> Result<UserStrings<'a>> {
        if data.is_empty() || data[0] != 0 {
            return Err(OutOfBounds);
        }

        Ok(UserStrings { data })
    }

    /// Get a view into the string contained at the provided location. This will process the heap information,
    /// and return a string slice which represents the object located there (if any)
    ///
    /// ## Arguments
    /// * 'index' - The offset within the heap to be accessed (comes from metadata tables)
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or the string data is invalid
    ///
    /// # Panics
    /// May panic if the underlying slice conversion fails due to memory alignment issues
    pub fn get(&self, index: usize) -> Result<&'a U16CStr> {
        if index >= self.data.len() {
            return Err(OutOfBounds);
        }

        let string_length = self.data[index] as usize;
        let data_start = index + 1;

        if string_length == 0 {
            return Err(malformed_error!(
                "Invalid zero-length string at index {}",
                index
            ));
        }

        if string_length == 1 {
            let empty_slice = &[0u16];
            return Ok(U16CStr::from_slice_truncate(empty_slice).unwrap());
        }

        // The string length includes the terminal byte, so actual UTF-16 data is length - 1
        let utf16_length = string_length - 1;
        let data_end = data_start + utf16_length;
        if data_end + 2 > self.data.len() {
            return Err(OutOfBounds);
        }

        if utf16_length % 2 != 0 {
            return Err(malformed_error!("Invalid UTF-16 length at index {}", index));
        }

        let utf16_data_with_null = &self.data[data_start..data_end + 2];

        // Convert to u16 slice (unsafe but controlled)
        let str_slice = unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            core::ptr::slice_from_raw_parts(
                utf16_data_with_null.as_ptr().cast::<u16>(),
                utf16_data_with_null.len() / 2,
            )
            .as_ref()
            .unwrap()
        };

        match U16CStr::from_slice_truncate(str_slice) {
            Ok(result) => Ok(result),
            Err(_) => Err(malformed_error!("Invalid string from index - {}", index)),
        }
    }

    /// Returns an iterator over all user strings in the heap
    ///
    /// Provides zero-copy access to all UTF-16 user strings with length prefixes.
    /// Each iteration yields a `Result<(usize, &U16CStr)>` with the offset and string content.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00]; // "Hi" in UTF-16
    /// let user_strings = UserStrings::from(data).unwrap();
    ///
    /// for result in user_strings.iter() {
    ///     match result {
    ///         Ok((offset, string)) => println!("String at {}: '{}'", offset, string.to_string_lossy()),
    ///         Err(e) => eprintln!("Error: {}", e),
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn iter(&self) -> UserStringsIterator<'_> {
        UserStringsIterator::new(self)
    }
}

impl<'a> IntoIterator for &'a UserStrings<'a> {
    type Item = std::result::Result<(usize, &'a widestring::U16CStr), crate::error::Error>;
    type IntoIter = UserStringsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over entries in the `#US` (`UserStrings`) heap
///
/// Provides zero-copy access to UTF-16 user strings with length prefixes.
/// Each iteration returns the offset and string content.
pub struct UserStringsIterator<'a> {
    user_strings: &'a UserStrings<'a>,
    position: usize,
}

impl<'a> UserStringsIterator<'a> {
    pub(crate) fn new(user_strings: &'a UserStrings<'a>) -> Self {
        Self {
            user_strings,
            position: 1,
        }
    }
}

impl<'a> Iterator for UserStringsIterator<'a> {
    type Item = Result<(usize, &'a U16CStr)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.user_strings.data.len() {
            return None;
        }

        let start_position = self.position;
        let string_length = self.user_strings.data[self.position] as usize;

        let result = match self.user_strings.get(start_position) {
            Ok(string) => Ok((start_position, string)),
            Err(e) => Err(e),
        };

        if string_length == 1 {
            self.position += 1 + string_length;
        } else {
            self.position += 1 + string_length + 2;
        }

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use widestring::u16cstr;

    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data: [u8; 32] = [
            0x00, 0x1b, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x2c, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        let us_str = UserStrings::from(&data).unwrap();

        assert_eq!(us_str.get(1).unwrap(), u16cstr!("Hello, World!"));
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
        // Simple test case - "Hi" in UTF-16 with length prefix
        // Length 0x05 = 5 bytes: 4 bytes for "Hi" + 1 terminal byte (null terminator is separate)
        let data = [0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00]; // "Hi" in UTF-16 + null terminator + terminal
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "Hi");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_multiple() {
        // Two strings: "Hi" (length 5) and "Bye" (length 7)
        let data = [
            0x00, // Initial null byte
            0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00,
            0x00, // "Hi" + null terminator + terminal
            0x07, 0x42, 0x00, 0x79, 0x00, 0x65, 0x00, 0x00, 0x00,
            0x00, // "Bye" + null terminator + terminal
        ];

        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "Hi");

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.0, 9);
        assert_eq!(second.1.to_string_lossy(), "Bye");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_empty_string() {
        // Empty string followed by "Hi"
        // Empty string: length 1 (just terminal byte), then "Hi": length 5
        let data = [
            0x00, 0x01, 0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00,
        ];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "");

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.0, 3);
        assert_eq!(second.1.to_string_lossy(), "Hi");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_long_string() {
        // Test with a longer string - 5 characters in UTF-16
        let mut data = vec![0x00]; // Initial null byte

        // "AAAAA" = 5 chars * 2 bytes + 1 terminal = 11 bytes total
        data.push(0x0B); // Length 11

        // Add 10 bytes of UTF-16 data (5 characters: "AAAAA")
        for _ in 0..5 {
            data.extend_from_slice(&[0x41, 0x00]);
        }
        data.extend_from_slice(&[0x00, 0x00]); // UTF-16 null terminator
        data.push(0x00); // Terminal byte

        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap().unwrap();
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

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_userstrings_iterator_invalid_utf16_length() {
        // Odd number of bytes for UTF-16 data
        let data = [0x00, 0x04, 0x48, 0x00, 0x69]; // Length 3 but only 3 bytes (should be even)
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }
}
