//! String Heap (`#Strings`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#Strings` heap, which stores identifier strings in UTF-8 encoding.
//! This module exposes the [`Strings`] struct for safe access and parsing of identifier strings referenced by metadata tables.
//!
//! # Reference
//! - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use std::{ffi::CStr, str};

use crate::{Error::OutOfBounds, Result};

/// '#Strings' hold various identifiers which are referenced form other tables within the CIL metadata.
/// e.g. various strings for reflection: function names, 0xclass names, 0xvariables, 0x...
///
/// The `Strings` object provides helper methods to access the data within this blob, 0xand parse / process it
/// properly according to the standard.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::streams::Strings;
/// let data = &[0u8, b'H', b'e', b'l', b'l', b'o', 0u8];
/// let strings = Strings::from(data).unwrap();
/// let s = strings.get(1).unwrap();
/// assert_eq!(s, "Hello");
/// ```
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.3
///
pub struct Strings<'a> {
    data: &'a [u8],
}

impl<'a> Strings<'a> {
    /// Create a `Strings` object from a sequence of bytes
    ///
    /// # Arguments
    /// * 'data'    - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the string heap data is empty or malformed
    pub fn from(data: &[u8]) -> Result<Strings> {
        if data.is_empty() || data[0] != 0 {
            return Err(malformed_error!("Provided #String heap is empty"));
        }

        Ok(Strings { data })
    }

    /// Get a view into the string contained at the provided location. This will process the heap information,
    /// and return a string slice which represents the object located there (if any)
    ///
    /// ## Arguments
    /// * 'index' - The offset within the heap to be accessed (comes from metadata tables)
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or the string data is invalid UTF-8
    pub fn get(&self, index: usize) -> Result<&'a str> {
        if index > self.data.len() {
            return Err(OutOfBounds);
        }

        // ToDo: Potentially cache this? 'expensive' verifications performed on each lookup. If the same
        //       String is accessed repeatedly, then this could be an issue
        match CStr::from_bytes_until_nul(&self.data[index..]) {
            Ok(result) => match result.to_str() {
                Ok(result) => Ok(result),
                Err(_) => Err(malformed_error!("Invalid string at index - {}", index)),
            },
            Err(_) => Err(malformed_error!("Invalid string at index - {}", index)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data : [u8; 119] = [
            0x00,
            0x3c, 0x4d, 0x61, 0x69, 0x6e, 0x3e, 0x24, 0x00,
            0x43, 0x5f, 0x53, 0x68, 0x61, 0x72, 0x70, 0x5f, 0x50, 0x4f, 0x43, 0x5f, 0x31, 0x00,
            0x3c, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3e, 0x00,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x00,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x00,
            0x57, 0x72, 0x69, 0x74, 0x65, 0x4c, 0x69, 0x6e, 0x65, 0x00,
            0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x00,
            0x44, 0x65, 0x62, 0x75, 0x67, 0x67, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x00
        ];

        let str_view = Strings::from(&data).unwrap();

        let str_test_1 = str_view.get(1).unwrap();
        assert_eq!(str_test_1, "<Main>$");

        let str_test_2 = str_view.get(9).unwrap();
        assert_eq!(str_test_2, "C_Sharp_POC_1");

        let str_test_3 = str_view.get(23).unwrap();
        assert_eq!(str_test_3, "<Module>");

        let str_test_3 = str_view.get(32).unwrap();
        assert_eq!(str_test_3, "System.Console");
    }
}
