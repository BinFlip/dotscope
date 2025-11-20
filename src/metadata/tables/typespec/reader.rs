//! Implementation of `RowReadable` for `TypeSpecRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `TypeSpec` table (ID 0x1B),
//! enabling reading of type specification information from .NET PE files. The TypeSpec
//! table defines complex type specifications through signatures stored in the blob heap,
//! supporting generic type instantiation, array definitions, pointer types, and complex
//! type composition.
//!
//! ## Table Structure (ECMA-335 §II.22.39)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Signature` | Blob heap index | Type specification signature data |
//!
//! ## Usage Context
//!
//! TypeSpec entries are used for:
//! - **Generic Instantiations**: `List<T>`, `Dictionary<K,V>`, custom generic types
//! - **Array Types**: Single and multi-dimensional arrays with bounds
//! - **Pointer Types**: Managed and unmanaged pointers, reference types  
//! - **Modified Types**: Types with `const`, `volatile`, and other modifiers
//! - **Constructed Types**: Complex compositions of primitive and defined types
//! - **Function Pointers**: Method signatures as type specifications
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::typespec::writer`] - Binary serialization support
//! - [`crate::metadata::tables::typespec`] - High-level TypeSpec table interface
//! - [`crate::metadata::signatures`] - Type signature parsing and representation

use crate::{
    metadata::{
        tables::{RowReadable, TableInfoRef, TypeSpecRaw},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for TypeSpecRaw {
    /// Reads a single `TypeSpec` table row from binary data.
    ///
    /// Parses the binary representation of a `TypeSpec` table entry, extracting
    /// the signature blob index and constructing the appropriate metadata token.
    /// The token format is 0x1B000000 + RID where 0x1B identifies the `TypeSpec` table.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw table data to read from
    /// * `offset` - Current reading position, updated after reading
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for determining field sizes
    ///
    /// ## Returns
    ///
    /// A fully constructed [`TypeSpecRaw`] instance with all fields populated.
    ///
    /// ## Errors
    ///
    /// May return an error if:
    /// - The data buffer is too short for a complete table entry
    /// - Invalid data structure encountered during parsing
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(TypeSpecRaw {
            rid,
            token: Token::new(0x1B00_0000 + rid),
            offset: *offset,
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
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
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

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
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
