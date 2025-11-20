//! Implementation of `RowReadable` for `PropertyRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `Property` table (ID 0x17),
//! enabling reading of property definition metadata from .NET PE files. The Property table
//! defines properties exposed by types, including their names, signatures, attributes, and
//! accessor methods, forming a crucial part of the .NET type system.
//!
//! ## Table Structure (ECMA-335 §II.22.34)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u16` | Property attributes bitmask |
//! | `Name` | String heap index | Property name identifier |
//! | `Type` | Blob heap index | Property signature (type, parameters for indexers) |
//!
//! ## Property Attributes
//!
//! The `Flags` field contains property attributes with common values:
//! - `0x0200` - `SpecialName` (property has special naming conventions)
//! - `0x0400` - `RTSpecialName` (runtime should verify name encoding)
//! - `0x1000` - `HasDefault` (property has a default value defined)
//!
//! ## Usage Context
//!
//! Property entries are used for:
//! - **Type Definition**: Defining properties exposed by classes, interfaces, and value types
//! - **Accessor Methods**: Linking to getter/setter methods through MethodSemantics table
//! - **Reflection Operations**: Runtime property discovery and invocation
//! - **Property Inheritance**: Supporting property override and inheritance relationships
//! - **Indexer Support**: Defining indexed properties with parameters
//!
//! ## Property System Architecture
//!
//! Properties in .NET follow a specific architecture:
//! - **Property Declaration**: Defines the property name, type, and attributes
//! - **Accessor Methods**: Getter and setter methods linked via MethodSemantics
//! - **Default Values**: Optional default values stored in Constant table
//! - **Custom Attributes**: Additional metadata stored in CustomAttribute table
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::property::writer`] - Binary serialization support
//! - [`crate::metadata::tables::property`] - High-level Property interface
//! - [`crate::metadata::tables::property::raw`] - Raw structure definition
//! - [`crate::metadata::tables::methodsemantics`] - Property accessor method mapping
//! - [`crate::metadata::tables::propertymap`] - Type-property ownership mapping

use crate::{
    metadata::{
        tables::{PropertyRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for PropertyRaw {
    /// Reads a single Property table row from metadata bytes.
    ///
    /// This method parses a Property entry from the metadata stream, extracting
    /// the property flags, name index, and signature index to construct the
    /// complete row structure with metadata context.
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
    /// * `Ok(PropertyRaw)` - Successfully parsed Property entry
    /// * `Err(Error)` - Failed to read or parse the entry
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(PropertyRaw {
            rid,
            token: Token::new(0x1700_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.signature, 0x0303);
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.signature, 0x03030303);
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
