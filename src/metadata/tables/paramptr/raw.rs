//! # `ParamPtr` Raw Implementation
//!
//! This module provides the raw variant of `ParamPtr` table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{ParamPtr, ParamPtrRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a `ParamPtr` table entry with unresolved indexes.
///
/// This structure represents the unprocessed entry from the `ParamPtr` metadata table
/// (ID 0x04), which provides indirection for parameter table access in optimized
/// metadata layouts. It contains raw index values that require resolution to actual
/// metadata objects.
///
/// ## Purpose
///
/// The `ParamPtr` table provides parameter indirection:
/// - **Logical to Physical Mapping**: Maps logical parameter positions to physical table entries
/// - **Metadata Optimization**: Enables parameter table compression and reordering
/// - **Access Abstraction**: Maintains consistent parameter access in optimized assemblies
/// - **Stream Format Support**: Required for assemblies using uncompressed metadata streams
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved parameter table indexes requiring lookup
/// - Minimal memory footprint for storage during parsing
/// - Direct representation of on-disk table structure
/// - Basic field access without metadata resolution capabilities
///
/// ## Indirection Mechanism
///
/// When `ParamPtr` table is present, parameter resolution follows this pattern:
/// - **Logical**: Logical parameter index → `ParamPtr[Logical]` → `Param[Physical]`
/// - **Resolution**: Logical → `ParamPtr[Logical]` → `Param[Physical]`
/// - **Access**: Use `ParamPtr.param` field to find actual parameter entry
/// - **Fallback**: If `ParamPtr` absent, use direct `Param` table indexing
///
/// ## ECMA-335 Specification
///
/// From ECMA-335, Partition II, §22.26:
/// > The `ParamPtr` table provides a level of indirection for accessing parameters.
/// > Each entry contains an index into the `Param` table. This indirection enables
/// > metadata optimization and flexible parameter ordering in optimized assemblies.
///
/// ## References
///
/// - ECMA-335, Partition II, §22.26 - `ParamPtr` table specification
/// - [`crate::metadata::tables::Param`] - Target parameter table entries
/// - [`crate::metadata::tables::ParamPtr`] - Owned variant for comparison
pub struct ParamPtrRaw {
    /// Row identifier within the `ParamPtr` table (1-based indexing).
    ///
    /// This field provides the logical position of this entry within the `ParamPtr` table,
    /// following the standard 1-based indexing convention used throughout .NET metadata.
    pub rid: u32,

    /// Metadata token uniquely identifying this `ParamPtr` entry.
    ///
    /// The token combines the table identifier (`ParamPtr` = 0x04) with the row ID,
    /// providing a unique reference for this parameter pointer across the entire
    /// metadata system.
    pub token: Token,

    /// Byte offset of this entry within the metadata stream.
    ///
    /// This offset indicates the exact position of this `ParamPtr` entry within the
    /// metadata stream, enabling direct access to the raw table data and supporting
    /// metadata analysis and debugging operations.
    pub offset: usize,

    /// One-based index into the `Param` table (target parameter).
    ///
    /// This field provides the indirection mapping from logical parameter positions
    /// to physical parameter table entries. When `ParamPtr` table is present, all
    /// parameter references should be resolved through this indirection mechanism
    /// rather than direct `Param` table indexing.
    pub param: u32,
}

impl ParamPtrRaw {
    /// Converts this raw `ParamPtr` entry to its owned representation.
    ///
    /// This method transforms the raw table entry into a fully owned `ParamPtr` instance
    /// with the same field values but with proper lifecycle management for use in
    /// application logic and metadata analysis.
    ///
    /// ## Returns
    ///
    /// * `Ok(ParamPtrRc)` - Successfully converted to owned representation
    /// * `Err(Error)` - Conversion error (currently unused but reserved for future validation)
    ///
    /// # Errors
    /// This function does not return an error under normal circumstances.
    pub fn to_owned(&self) -> Result<ParamPtrRc> {
        Ok(Arc::new(ParamPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            param: self.param,
        }))
    }

    /// Applies this `ParamPtr` entry to the metadata loading process.
    ///
    /// `ParamPtr` entries provide indirection mappings but do not directly modify
    /// other metadata structures during the loading process. The indirection logic
    /// is handled at the table resolution and lookup level rather than during
    /// initial table processing.
    ///
    /// This method is provided for consistency with the table loading framework
    /// but performs no operations for `ParamPtr` entries.
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - Always succeeds as no processing is required
    ///
    /// # Errors
    /// This function does not return an error under normal circumstances.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ParamPtrRaw {
    /// Calculates the byte size of a single `ParamPtr` table row.
    ///
    /// The size depends on the metadata table size configuration:
    /// - **param**: Index size into `Param` table (2 or 4 bytes)
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size configuration information
    ///
    /// ## Returns
    ///
    /// * `u32` - Total row size in bytes (2-4 bytes typically)
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* param */ sizes.table_index_bytes(TableId::Param)
        )
    }

    /// Reads a single `ParamPtr` table row from metadata bytes.
    ///
    /// This method parses a `ParamPtr` entry from the metadata stream, extracting
    /// the parameter table index and constructing the complete row structure
    /// with metadata context.
    ///
    /// ## Arguments
    ///
    /// * `data` - The metadata bytes to read from
    /// * `offset` - Current position in the data (updated after reading)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size configuration for index resolution
    ///
    /// ## Returns
    ///
    /// * `Ok(ParamPtrRaw)` - Successfully parsed `ParamPtr` entry
    /// * `Err(Error)` - Failed to read or parse the entry
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ParamPtrRaw {
            rid,
            token: Token::new(0x0700_0000 + rid),
            offset: *offset,
            param: read_le_at_dyn(data, offset, sizes.is_large(TableId::Param))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // param (index into Param table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x07000001);
            assert_eq!(row.param, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // param (index into Param table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x07000001);
            assert_eq!(row.param, 0x01010101);
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
