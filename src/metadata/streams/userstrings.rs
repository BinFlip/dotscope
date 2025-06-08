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
        if index > self.data.len() {
            return Err(OutOfBounds);
        }

        // Safe conversion from u8 slice to u16 slice
        // Ensure the slice length is even for proper alignment
        let byte_data = &self.data[index..];
        if byte_data.len() % 2 != 0 {
            return Err(malformed_error!(
                "Invalid string data length at index - {}",
                index
            ));
        }

        let str_slice = unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            core::ptr::slice_from_raw_parts(byte_data.as_ptr().cast::<u16>(), byte_data.len() / 2)
                .as_ref()
                .unwrap()
        };

        match U16CStr::from_slice_truncate(str_slice) {
            Ok(result) => Ok(result),
            Err(_) => Err(malformed_error!("Invalid string from index - {}", index)),
        }
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

        assert_eq!(us_str.get(2).unwrap(), u16cstr!("Hello, World!"));
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
}
