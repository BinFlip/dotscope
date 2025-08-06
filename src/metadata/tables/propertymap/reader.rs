//! Implementation of `RowReadable` for `PropertyMapRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `PropertyMap` table (ID 0x15),
//! enabling reading of property ownership mapping from .NET PE files. The PropertyMap table
//! establishes ownership relationships between types and their properties by defining contiguous
//! ranges in the Property table, enabling efficient enumeration of all properties declared by
//! a particular type.
//!
//! ## Table Structure (ECMA-335 §II.22.35)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Parent` | TypeDef table index | Type that owns the properties |
//! | `PropertyList` | Property table index | First property owned by the parent type |
//!
//! ## Range Resolution Architecture
//!
//! PropertyMap entries define property ranges implicitly through the following mechanism:
//! - Properties from `PropertyList\[i\]` to `PropertyList\[i+1\]`-1 belong to Parent\[i\]
//! - The final entry's range extends to the end of the Property table
//! - Empty ranges are valid and indicate types with no properties
//! - PropertyPtr indirection may be used for non-contiguous property layouts
//!
//! ## Usage Context
//!
//! PropertyMap entries are used for:
//! - **Type-Property Mapping**: Determining which properties belong to which types
//! - **Property Enumeration**: Iterating over all properties declared by a type
//! - **Inheritance Analysis**: Understanding property inheritance hierarchies
//! - **Reflection Operations**: Runtime property discovery and access
//!
//! ## Property Ownership Model
//!
//! The PropertyMap table implements an efficient property ownership model:
//! - **Contiguous Ranges**: Properties are grouped in contiguous table segments
//! - **Sorted Order**: PropertyMap entries are sorted by Parent (TypeDef) index
//! - **Range Calculation**: Property ownership determined by range boundaries
//! - **Efficient Lookup**: Binary search enables fast property enumeration
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::propertymap::writer`] - Binary serialization support
//! - [`crate::metadata::tables::propertymap`] - High-level PropertyMap interface
//! - [`crate::metadata::tables::propertymap::raw`] - Raw structure definition
//! - [`crate::metadata::tables::property`] - Target Property table definitions
//! - [`crate::metadata::tables::propertyptr`] - Property indirection support

use crate::{
    metadata::{
        tables::{PropertyMapRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for PropertyMapRaw {
    /// Reads a `PropertyMap` entry from the metadata byte stream.
    ///
    /// This method parses the binary representation of a `PropertyMap` table row and creates
    /// a [`PropertyMapRaw`] instance with the appropriate metadata token.
    ///
    /// ## Binary Format
    /// The data is read in little-endian format:
    /// 1. **parent** - Index into `TypeDef` table (2 or 4 bytes)
    /// 2. **`property_list`** - Index into Property table (2 or 4 bytes)
    ///
    /// ## Arguments
    /// * `data` - The metadata byte stream
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// ## Returns
    /// A new [`PropertyMapRaw`] instance with the parsed data and generated metadata token.
    ///
    /// ## Errors
    /// Returns an error if the data cannot be read or is malformed.
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let parent = read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?;
        let property_list = read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?;

        Ok(PropertyMapRaw {
            rid,
            token: Token::new(0x1500_0000 + rid),
            offset: offset_org,
            parent,
            property_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // parent
            0x02, 0x02, // property_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x15000001);
            assert_eq!(row.parent, 0x0101);
            assert_eq!(row.property_list, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // parent
            0x02, 0x02, 0x02, 0x02, // property_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::Property, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<PropertyMapRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: PropertyMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x15000001);
            assert_eq!(row.parent, 0x01010101);
            assert_eq!(row.property_list, 0x02020202);
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
