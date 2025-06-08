//! Blob Heap (`#Blob`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#Blob` heap, which stores binary data such as signatures and custom attributes.
//! This module exposes the [`Blob`] struct for safe access and parsing of blobs referenced by metadata tables.
//!
//! # Reference
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{file::parser::Parser, Error::OutOfBounds, Result};

/// '#Blob' points to streams of bytes. There are chunks, which may not be accessible in between of others that are.
/// Each 'valid' blob is pointed to by another table / index, and each contains their size encoded into the first byte.
///
/// * If the first one byte of the 'blob' is 0bbbbbbb, then the rest of the 'blob' contains the
///   bbbbbbb bytes of actual data.
/// * If the first two bytes of the 'blob' are 10bbbbbb and x, then the rest of the 'blob'
///   contains the (bbbbbb << 8 + x) bytes of actual data.
/// * If the first four bytes of the 'blob' are 110bbbbb, x, y, and z, then the rest of the
///   'blob' contains the (bbbbb << 24 + x << 16 + y << 8 + z) bytes of actual data.
///
/// The `Blob` object provides helper methods to access the data within this blob, and parse / process it
/// properly according to the standard.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::streams::Blob;
/// let data = &[0u8, 0x03, 0x41, 0x42, 0x43];
/// let blob = Blob::from(data).unwrap();
/// let b = blob.get(1).unwrap();
/// assert_eq!(b, &[0x41, 0x42, 0x43]);
/// ```
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.4
///
pub struct Blob<'a> {
    data: &'a [u8],
}

impl<'a> Blob<'a> {
    /// Create a `Blob` object from a sequence of bytes
    ///
    /// # Arguments
    /// * 'data'    - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the data is empty or doesn't start with a null byte (invalid blob heap format)
    pub fn from(data: &'a [u8]) -> Result<Blob<'a>> {
        if data.is_empty() || data[0] != 0 {
            return Err(malformed_error!("Invalid memory for #Blob heap"));
        }

        Ok(Blob { data })
    }

    /// Get a view into the bytes contained at the provided location. This will process the blob information,
    /// and return a slice which represents the object located there (if any)
    ///
    /// ## Arguments
    /// * 'index' - The offset within the blob to be accessed (comes from metadata tables)
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or if the blob data cannot be parsed
    pub fn get(&self, index: usize) -> Result<&'a [u8]> {
        if index > self.data.len() {
            return Err(OutOfBounds);
        }

        let mut parser = Parser::new(&self.data[index..]);
        let len = parser.read_compressed_uint()? as usize;
        let skip = parser.pos();

        let Some(data_start) = index.checked_add(skip) else {
            return Err(OutOfBounds);
        };

        let Some(data_end) = data_start.checked_add(len) else {
            return Err(OutOfBounds);
        };

        if data_start > self.data.len() || data_end > self.data.len() {
            return Err(OutOfBounds);
        }

        Ok(&self.data[data_start..data_end])
    }

    /// Returns an iterator over all blobs in the heap
    ///
    /// Provides zero-copy access to all variable-length binary blobs.
    /// Each iteration yields a `Result<(usize, &[u8])>` with the offset and blob data.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::Blob;
    ///
    /// let data = &[0u8, 0x03, 0x41, 0x42, 0x43, 0x02, 0x44, 0x45];
    /// let blob = Blob::from(data).unwrap();
    ///
    /// for result in blob.iter() {
    ///     match result {
    ///         Ok((offset, blob_data)) => println!("Blob at {}: {:02X?}", offset, blob_data),
    ///         Err(e) => eprintln!("Error: {}", e),
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn iter(&self) -> BlobIterator<'_> {
        BlobIterator::new(self)
    }
}

impl<'a> IntoIterator for &'a Blob<'a> {
    type Item = std::result::Result<(usize, &'a [u8]), crate::error::Error>;
    type IntoIter = BlobIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over entries in the `#Blob` heap
///
/// Provides zero-copy access to variable-length binary blobs.
/// Each iteration returns the offset and blob data.
pub struct BlobIterator<'a> {
    blob: &'a Blob<'a>,
    position: usize,
}

impl<'a> BlobIterator<'a> {
    pub(crate) fn new(blob: &'a Blob<'a>) -> Self {
        Self {
            blob,
            position: 1, // Skip the initial null byte at position 0
        }
    }
}

impl<'a> Iterator for BlobIterator<'a> {
    type Item = Result<(usize, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.blob.data.len() {
            return None;
        }

        let start_position = self.position;
        match self.blob.get(self.position) {
            Ok(blob_data) => {
                let mut parser = Parser::new(&self.blob.data[self.position..]);
                if parser.read_compressed_uint().is_ok() {
                    let length_bytes = parser.pos();
                    self.position += length_bytes + blob_data.len();
                    Some(Ok((start_position, blob_data)))
                } else {
                    Some(Err(malformed_error!(
                        "Failed to parse blob length at position {}",
                        start_position
                    )))
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data = { 
            let mut data = vec![0xCC; 262143];
            /* i - 0    - should always be 0    */ data[0]          = 0b_00000000_u8;

            /* i - 1    - len 10                */ data[1]          = 0b_00001010_u8;
            /* i - 1    - len 10                */ data[2..12]      .copy_from_slice(&[0x0A; 10]);
    
            /* i - 12   - len 5                 */ data[12]         = 0b_00000101_u8;
            /* i - 12   - len 5                 */ data[13..18]     .copy_from_slice(&[0xAB; 5]);

            /* i - 18   - len 0 - invalid       */ data[18]         = 0b_11111111_u8;
    
            /* i - 19   - len 256               */ data[19]         = 0b_10000001_u8;
            /* i - 19   - len 256               */ data[20]         = 0b_00000001_u8;
            /* i - 19   - len 256               */ data[21..278]    .copy_from_slice(&[0xBA; 257]);
            /* i - 2070 - len 2048              */ data[278]        = 0b_11000000_u8;
            /* i - 2070 - len 2048              */ data[279]        = 0b_00000001_u8;
            /* i - 2070 - len 2048              */ data[280]        = 0b_00000001_u8;
            /* i - 2070 - len 2048              */ data[281]        = 0b_00000001_u8;
            /* i - 2070 - len 2048              */ data[282..66075]  .copy_from_slice(&[0xBA; 65793]);

            data
        };

        let blob = Blob::from(&data).unwrap();

        {
            let indexed = blob.get(0).unwrap();
            assert_eq!(indexed.len(), 0);
        }

        {
            let indexed = blob.get(1).unwrap();
            assert_eq!(indexed.len(), 10);
            assert_eq!(indexed, &[0x0A; 10]);
        }

        {
            let indexed = blob.get(12).unwrap();
            assert_eq!(indexed.len(), 5);
            assert_eq!(indexed, &[0xAB; 5]);
        }

        {
            if blob.get(18).is_ok() {
                panic!("This should not be valid!")
            }
        }

        {
            let indexed = blob.get(19).unwrap();
            assert_eq!(indexed.len(), 257);
            assert_eq!(indexed, &[0xBA; 257]);
        }

        {
            let indexed = blob.get(278).unwrap();
            assert_eq!(indexed.len(), 65793);
            assert_eq!(indexed, &[0xBA; 65793]);
        }
    }

    #[test]
    fn test_blob_iterator_basic() {
        let data = [0x00, 0x02, 0x41, 0x42, 0x01, 0x43];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1, &[0x41, 0x42]);

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.0, 4);
        assert_eq!(second.1, &[0x43]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_empty_blob() {
        let data = [0x00, 0x00, 0x02, 0x41, 0x42];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1, &[]);

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.0, 2);
        assert_eq!(second.1, &[0x41, 0x42]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_large_blob() {
        // Test with two-byte length encoding
        let mut data = vec![0x00, 0x81, 0x02]; // Length 258 (two-byte encoding)
        data.extend(vec![0xFF; 258]);
        data.push(0x01); // Single byte blob
        data.push(0xAA);

        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.len(), 258);
        assert_eq!(first.1, &vec![0xFF; 258]);

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.0, 261);
        assert_eq!(second.1, &[0xAA]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_truncated_data() {
        // Blob claims length 5 but only 3 bytes available
        let data = [0x00, 0x05, 0x41, 0x42, 0x43];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let result = iter.next().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_blob_iterator_single_item() {
        let data = [0x00, 0x03, 0x41, 0x42, 0x43];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1, &[0x41, 0x42, 0x43]);

        assert!(iter.next().is_none());
    }
}
