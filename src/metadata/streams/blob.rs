//! Blob Heap (`#Blob`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#Blob` heap, which stores binary data such as signatures and custom attributes.
//! This module exposes the [`Blob`] struct for safe access and parsing of blobs referenced by metadata tables.
//!
//! # Reference
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{Error::OutOfBounds, Result};

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

        let (skip, len) = if (self.data[index] >> 7) & 1 == 0 {
            if index > self.data.len() {
                return Err(OutOfBounds);
            }

            (1, (self.data[index]) as usize)
        } else if (self.data[index] >> 7) & 1 > 0 && (self.data[index] >> 6) & 1 == 0 {
            if index + 1 > self.data.len() {
                return Err(OutOfBounds);
            }

            let size_p_1 = (self.data[index] & 0b_01111111_u8) as usize;
            let size_p_2 = self.data[index + 1] as usize;

            (2, (size_p_1 << 8) + size_p_2)
        } else if (self.data[index] >> 7) & 1 > 0
            && (self.data[index] >> 6) & 1 > 0
            && (self.data[index] >> 5) & 1 == 0
        {
            if index + 3 > self.data.len() {
                return Err(OutOfBounds);
            }

            let size_p_1 = (self.data[index] & 0b_00111111_u8) as usize;
            let size_p_2 = self.data[index + 1] as usize;
            let size_p_3 = self.data[index + 2] as usize;
            let size_p_4 = self.data[index + 3] as usize;

            (
                4,
                (size_p_1 << 24) + (size_p_2 << 16) + (size_p_3 << 8) + size_p_4,
            )
        } else {
            return Err(malformed_error!("Invalid blob index - {}", index));
        };

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
}
