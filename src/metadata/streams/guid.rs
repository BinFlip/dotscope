//! GUID Heap (`#GUID`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#GUID` heap, which stores 128-bit GUIDs for assembly identity and references.
//! This module exposes the [`Guid`] struct for safe access and parsing of GUIDs referenced by metadata tables.
//!
//! # Reference
//! - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use crate::{Error::OutOfBounds, Result};

/// '#GUID' is a heap, which contains a sequence of 128-bit GUIDs
///
/// The `Guid` object provides helper methods to access the data within this blob, and parse / process it
/// properly according to the standard.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::streams::Guid;
/// let data = &[0u8; 32];
/// let guid_heap = Guid::from(data).unwrap();
/// // Accessing GUIDs would require valid data and index
/// ```
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.5
///
pub struct Guid<'a> {
    data: &'a [u8],
}

impl<'a> Guid<'a> {
    /// Create a `Guid` object from a sequence of bytes
    ///
    /// # Arguments
    /// * 'data'    - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the data is too small to contain a valid GUID (less than 16 bytes)
    pub fn from(data: &'a [u8]) -> Result<Guid<'a>> {
        if data.len() < 16 {
            return Err(malformed_error!("Data for #Guid heap is too small"));
        }

        Ok(Guid { data })
    }

    /// Returns the GUID at the specified index
    ///
    /// GUID has to be build, hence no 'view' possible
    ///
    /// ## Arguments
    /// * 'index' - The index of the GUID to be accessed within the blob (comes from metadata tables)
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or if the GUID data cannot be parsed
    pub fn get(&self, index: usize) -> Result<uguid::Guid> {
        if index < 1 || index * 15 > self.data.len() {
            return Err(OutOfBounds);
        }

        let offset_start = ((index - 1) * 15) + (index - 1);
        let offset_end = (index * 15) + 1 + (index - 1);

        let mut buffer = [0u8; 16];
        buffer.copy_from_slice(&self.data[offset_start..offset_end]);

        Ok(uguid::Guid::from_bytes(buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data : [u8; 48] = [
            /* 0 - 0;16   */  0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48, 0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
            /* 1 - 16;33  */  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            /* 2 - 33;49  */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let guids = Guid::from(&data).unwrap();

        assert_eq!(
            guids.get(1).unwrap(),
            uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5")
        );
        assert_eq!(
            guids.get(2).unwrap(),
            uguid::guid!("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
        );
        assert_eq!(
            guids.get(3).unwrap(),
            uguid::guid!("00000000-0000-0000-0000-000000000000")
        );
    }
}
