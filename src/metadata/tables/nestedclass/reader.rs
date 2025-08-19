//! Implementation of `RowReadable` for `NestedClassRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `NestedClass` table (ID 0x29),
//! enabling reading of nested class relationships from .NET PE files. The NestedClass table
//! defines hierarchical relationships between nested types and their enclosing types, specifying
//! type containment and scoping information essential for proper type resolution.
//!
//! ## Table Structure (ECMA-335 §II.22.32)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `NestedClass` | TypeDef table index | Type that is nested within enclosing type |
//! | `EnclosingClass` | TypeDef table index | Type that contains the nested type |
//!
//! ## Usage Context
//!
//! NestedClass entries are used for:
//! - **Type Hierarchy**: Defining containment relationships between types
//! - **Scoping Resolution**: Resolving nested type names within their container context
//! - **Accessibility Control**: Nested types inherit accessibility from their container
//! - **Name Resolution**: Qualified type names include the enclosing type path
//! - **Reflection Operations**: Runtime nested type discovery and access
//!
//! ## Type Relationships
//!
//! NestedClass entries establish containment relationships:
//! - **Containment**: The nested type is contained within the enclosing type
//! - **Scoping**: Nested types inherit accessibility from their container
//! - **Resolution**: Type names are resolved relative to the enclosing context
//! - **Hierarchy**: Multiple levels of nesting are supported through chaining
//!
//! ## Nested Type Architecture
//!
//! .NET supports complex nested type hierarchies:
//! - **Direct Nesting**: Classes, interfaces, structs, and enums can be nested
//! - **Multiple Levels**: Nested types can themselves contain other nested types
//! - **Access Modifiers**: Nested types can have different accessibility than their containers
//! - **Generic Types**: Generic types can be nested and can contain generic nested types
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::nestedclass::writer`] - Binary serialization support
//! - [`crate::metadata::tables::nestedclass`] - High-level NestedClass interface
//! - [`crate::metadata::tables::nestedclass::raw`] - Raw structure definition
//! - [`crate::metadata::tables::typedef`] - Type definition entries for nested and enclosing types

use crate::{
    metadata::{
        tables::{NestedClassRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for NestedClassRaw {
    /// Reads a single `NestedClass` table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.32:
    /// 1. **`NestedClass`** (2-4 bytes): Index into `TypeDef` table for nested type
    /// 2. **`EnclosingClass`** (2-4 bytes): Index into `TypeDef` table for enclosing type
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`NestedClassRaw`] instance with populated fields
    ///
    /// ## Errors
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid `TypeDef` index values
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(NestedClassRaw {
            rid,
            token: Token::new(0x2900_0000 + rid),
            offset: *offset,
            nested_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            enclosing_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
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
            0x01, 0x01, // nested_class
            0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::NestedClass, 1), (TableId::TypeDef, 10)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x0101);
            assert_eq!(row.enclosing_class, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // nested_class
            0x02, 0x02, 0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::NestedClass, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x01010101);
            assert_eq!(row.enclosing_class, 0x02020202);
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
