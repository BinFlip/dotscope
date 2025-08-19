//! Implementation of `RowReadable` for `StandAloneSigRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `StandAloneSig` table (ID 0x11),
//! enabling reading of standalone signature information from .NET PE files. The StandAloneSig
//! table stores signatures that are not directly associated with specific methods, fields, or
//! properties but are referenced from CIL instructions or used in complex signature scenarios.
//!
//! ## Table Structure (ECMA-335 §II.22.39)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Signature` | Blob heap index | Signature data stored in blob heap |
//!
//! ## Usage Context
//!
//! StandAloneSig entries are used for:
//! - **Method Signatures**: Function pointer signatures with specific calling conventions
//! - **Local Variable Signatures**: Method local variable type declarations
//! - **Field Signatures**: Standalone field type specifications
//! - **Generic Signatures**: Generic type and method instantiation signatures
//! - **CIL Instruction References**: Signatures referenced by call/calli instructions
//! - **P/Invoke Signatures**: Unmanaged method call signatures
//!
//! ## Signature Types
//!
//! The signature blob can contain various signature formats:
//! - **Method Signatures**: Complete method signatures with return type and parameters
//! - **Local Signatures**: Local variable type lists for method bodies
//! - **Field Signatures**: Field type specifications
//! - **Property Signatures**: Property type and accessor information
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::standalonesig::writer`] - Binary serialization support
//! - [`crate::metadata::tables::standalonesig`] - High-level StandAloneSig interface
//! - [`crate::metadata::tables::standalonesig::raw`] - Raw structure definition

use crate::{
    metadata::{
        tables::{RowReadable, StandAloneSigRaw, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for StandAloneSigRaw {
    /// Reads a `StandAloneSig` table row from the metadata stream.
    ///
    /// Parses a single `StandAloneSig` entry from the raw metadata bytes,
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
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
