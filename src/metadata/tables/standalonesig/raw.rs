//! # StandAloneSig Raw Implementation
//!
//! This module provides the raw variant of StandAloneSig table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::Blob,
        tables::{RowDefinition, StandAloneSigRc, TableInfoRef},
        token::Token,
    },
    Result,
};

/// Raw representation of a StandAloneSig table entry from the .NET metadata.
///
/// The StandAloneSig table contains standalone signatures that are not directly associated
/// with specific methods, fields, or properties but are referenced from CIL instructions
/// or used in complex signature scenarios. Each entry points to a signature blob that
/// contains the actual signature data.
///
/// ## Metadata Table Information
/// - **Table ID**: `0x11` (17 decimal)
/// - **Token Type**: `0x11000000` + RID
/// - **Purpose**: Stores standalone signatures for various metadata scenarios
///
/// ## Structure Layout
/// The table entry contains a single field that references the signature blob
/// in the metadata blob heap. This indirection enables:
/// - **Signature Reuse**: Multiple references to the same signature blob
/// - **Complex Signatures**: Support for method pointers and local variable signatures
/// - **Dynamic Signatures**: Runtime signature generation and manipulation
///
/// ## Signature Types
/// StandAloneSig entries can contain various signature types:
/// - **Method Signatures**: Function pointer signatures with calling conventions
/// - **Local Variable Signatures**: Method local variable type declarations
/// - **Field Signatures**: Standalone field type specifications
/// - **Generic Signatures**: Generic type and method instantiation signatures
///
/// ## See Also
/// - [`StandAloneSig`](crate::metadata::tables::StandAloneSig) - Resolved owned variant
/// - [ECMA-335 §II.22.39](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) - StandAloneSig table specification
#[derive(Clone, Debug)]
pub struct StandAloneSigRaw {
    /// The 1-based row identifier within the StandAloneSig table.
    pub rid: u32,

    /// The metadata token for this StandAloneSig entry.
    pub token: Token,

    /// The byte offset of this entry within the metadata stream.
    pub offset: usize,

    /// Index into the Blob heap containing the signature data.
    ///
    /// This field points to the signature blob that contains the actual signature
    /// information including calling conventions, parameter types, return types,
    /// and other signature-specific data. The blob format depends on the signature type.
    pub signature: u32,
}

impl StandAloneSigRaw {
    /// Converts this raw StandAloneSig entry into an owned representation.
    ///
    /// Creates a fully-owned [`crate::metadata::tables::StandAloneSig`] instance from this raw entry,
    /// parsing the signature blob and resolving all type references within
    /// the signature data.
    ///
    /// ## Arguments
    ///
    /// * `blob` - The blob heap containing the signature data
    ///
    /// ## Returns
    ///
    /// * `Ok(StandAloneSigRc)` - Successfully converted owned entry
    /// * `Err(_)` - Conversion failed due to invalid signature or missing blob data
    pub fn to_owned(&self, _blob: &Blob) -> Result<StandAloneSigRc> {
        todo!("Implement StandAloneSig::from - solve storage / resolution of signature types")
    }

    /// Applies this StandAloneSig entry to update related metadata structures.
    ///
    /// StandAloneSig entries define standalone signatures that can be referenced
    /// by other metadata elements, but they do not directly modify other metadata
    /// structures during the loading process. The signatures serve as reference
    /// targets for CIL instructions and method definitions.
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - Entry application completed (always succeeds)
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for StandAloneSigRaw {
    /// Calculates the byte size of a StandAloneSig table row.
    ///
    /// The row size depends on the blob heap size:
    /// - 2 bytes if blob heap has ≤ 65535 entries
    /// - 4 bytes if blob heap has > 65535 entries
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information for index size calculation
    ///
    /// ## Returns
    ///
    /// The size in bytes required for a single StandAloneSig table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* signature */ sizes.blob_bytes()
        )
    }

    /// Reads a StandAloneSig table row from the metadata stream.
    ///
    /// Parses a single StandAloneSig entry from the raw metadata bytes,
    /// extracting the signature blob index and constructing the complete
    /// table entry with metadata token and offset information.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw metadata bytes containing the table
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for proper index parsing
    ///
    /// ## Returns
    ///
    /// * `Ok(StandAloneSigRaw)` - Successfully parsed table entry
    /// * `Err(_)` - Parsing failed due to insufficient data or corruption
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let signature = read_le_at_dyn(data, offset, sizes.is_large_blob())?;

        Ok(StandAloneSigRaw {
            rid,
            token: Token::new(0x1100_0000 + rid),
            offset: offset_org,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));
        let table = MetadataTable::<StandAloneSigRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StandAloneSigRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x11000001);
            assert_eq!(row.signature, 0x0101);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(&[], true, true, true));
        let table =
            MetadataTable::<StandAloneSigRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: StandAloneSigRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x11000001);
            assert_eq!(row.signature, 0x01010101);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
