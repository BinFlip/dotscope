//! Implementation of `RowReadable` for `PropertyPtrRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `PropertyPtr` table (ID 0x16),
//! enabling reading of property pointer information from .NET PE files. The PropertyPtr
//! table provides an indirection mechanism for property definitions when the PropertyMap
//! table uses pointer-based addressing instead of direct indexing.
//!
//! ## Table Structure (ECMA-335 §II.22.32)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Property` | Property table index | Index into Property table |
//!
//! ## Usage Context
//!
//! PropertyPtr entries are used when:
//! - **Property Indirection**: Property table requires indirect addressing
//! - **Sparse Property Maps**: PropertyMap entries point to PropertyPtr instead of direct Property indexes
//! - **Assembly Modification**: Property table reorganization during assembly editing
//! - **Optimization**: Memory layout optimization for large property collections
//!
//! ## Indirection Architecture
//!
//! The PropertyPtr table enables:
//! - **Flexible Addressing**: PropertyMap can reference non-contiguous Property entries
//! - **Dynamic Reordering**: Property definitions can be reordered without affecting PropertyMap
//! - **Incremental Updates**: Property additions without PropertyMap restructuring
//! - **Memory Efficiency**: Sparse property collections with minimal memory overhead
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::propertyptr::writer`] - Binary serialization support
//! - [`crate::metadata::tables::propertyptr`] - High-level PropertyPtr interface
//! - [`crate::metadata::tables::propertyptr::raw`] - Raw structure definition
//! - [`crate::metadata::tables::property`] - Target Property table definitions

use crate::{
    metadata::{
        tables::{PropertyPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for PropertyPtrRaw {
    /// Reads a `PropertyPtr` table row from the metadata stream.
    ///
    /// Parses a single `PropertyPtr` entry from the raw metadata bytes,
    /// extracting the property index and constructing the complete
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
    /// * `Ok(PropertyPtrRaw)` - Successfully parsed table entry
    /// * `Err(_)` - Parsing failed due to insufficient data or corruption
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(PropertyPtrRaw {
            rid,
            token: Token::new(0x1600_0000 + rid),
            offset: *offset,
            property: read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?,
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
            0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x01010101);
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
