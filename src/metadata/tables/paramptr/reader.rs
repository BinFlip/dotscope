//! Implementation of `RowReadable` for `ParamPtrRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `ParamPtr` table (ID 0x07),
//! enabling reading of parameter pointer information from .NET PE files. The ParamPtr
//! table provides an indirection mechanism for parameter definitions when optimized
//! metadata layouts require non-contiguous parameter table access patterns.
//!
//! ## Table Structure (ECMA-335 §II.22.26)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Param` | Param table index | Index into Param table |
//!
//! ## Usage Context
//!
//! ParamPtr entries are used when:
//! - **Parameter Indirection**: Param table requires indirect addressing
//! - **Optimized Layouts**: Assembly uses optimized metadata stream layouts
//! - **Non-contiguous Access**: Parameter definitions are not stored contiguously
//! - **Assembly Modification**: Parameter table reorganization during editing
//!
//! ## Indirection Architecture
//!
//! The ParamPtr table enables:
//! - **Flexible Addressing**: Methods can reference non-contiguous Param entries
//! - **Dynamic Reordering**: Parameter definitions can be reordered without affecting method signatures
//! - **Incremental Updates**: Parameter additions without method signature restructuring
//! - **Memory Efficiency**: Sparse parameter collections with minimal memory overhead
//!
//! ## Optimization Benefits
//!
//! ParamPtr tables provide several optimization benefits:
//! - **Reduced Metadata Size**: Eliminates gaps in parameter table layout
//! - **Improved Access Patterns**: Enables better cache locality for parameter access
//! - **Flexible Organization**: Supports various parameter organization strategies
//! - **Assembly Merging**: Facilitates combining multiple assemblies efficiently
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::paramptr::writer`] - Binary serialization support
//! - [`crate::metadata::tables::paramptr`] - High-level ParamPtr interface
//! - [`crate::metadata::tables::paramptr::raw`] - Raw structure definition
//! - [`crate::metadata::tables::param`] - Target Param table definitions

use crate::{
    metadata::{
        tables::{ParamPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for ParamPtrRaw {
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
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
    use std::sync::Arc;

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
