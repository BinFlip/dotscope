//! Stream Header for .NET Metadata Streams
//!
//! Provides parsing and access to stream headers, which describe the name, offset, and size of each metadata stream in a .NET assembly.
//! This module exposes the [`StreamHeader`] struct for reading and validating stream header information.
//!
//! # Reference
//! - [ECMA-335 II.24.2.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{file::io::read_le, Error::OutOfBounds, Result};

/// A stream header provides the names, and the position and length of a particular table or heap. Note that the
/// length of a Stream header structure is not fixed, but depends on the length of its name field (a variable
/// length null-terminated string).
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.2
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::streams::StreamHeader;
/// let data = [0u8; 16];
/// let result = StreamHeader::from(&data[..]);
/// assert!(result.is_err() || result.is_ok());
/// ```
pub struct StreamHeader {
    /// Memory offset with start of the stream
    pub offset: u32,
    /// Size of this stream in bytes, shall be a multiple of 4
    pub size: u32,
    /// Name of Stream\0 max 32char
    pub name: String,
}

impl StreamHeader {
    /// Create a `Stream` object from a sequence of bytes
    ///
    /// # Arguments
    /// * 'data' - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the data is too short or stream header format is invalid
    pub fn from(data: &[u8]) -> Result<StreamHeader> {
        if data.len() < 9 {
            return Err(OutOfBounds);
        }

        // ToDo: This can be better solved using str
        let mut name = String::with_capacity(32);
        for counter in 0..std::cmp::min(32, data.len() - 8) {
            let name_char = read_le::<u8>(&data[8 + counter..])?;
            if name_char == 0 {
                break;
            }

            name.push(char::from(name_char));
        }

        if !["#Strings", "#US", "#Blob", "#GUID", "#~"]
            .iter()
            .any(|valid_name| name == *valid_name)
        {
            return Err(malformed_error!("Invalid stream header name - {}", name));
        }

        Ok(StreamHeader {
            offset: read_le::<u32>(data)?,
            size: read_le::<u32>(&data[4..])?,
            name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let header_bytes = [
            0x6C, 0x00, 0x00, 0x00,
            0xA4, 0x45, 0x00, 0x00,
            0x23, 0x7E, 0x00,
        ];

        let parsed_header = StreamHeader::from(&header_bytes).unwrap();

        assert_eq!(parsed_header.offset, 0x6C);
        assert_eq!(parsed_header.size, 0x45A4);
        assert_eq!(parsed_header.name, "#~");
    }

    #[test]
    fn crafted_invalid() {
        #[rustfmt::skip]
        let header_bytes = [
            0x6C, 0x00, 0x00, 0x00,
            0xA4, 0x45, 0x00, 0x00,
            0x24, 0x7E, 0x00,
        ];

        if StreamHeader::from(&header_bytes).is_ok() {
            panic!("This should not be valid!")
        }
    }
}
