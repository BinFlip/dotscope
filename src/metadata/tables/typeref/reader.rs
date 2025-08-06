//! Implementation of `RowReadable` for `TypeRefRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `TypeRef` table (ID 0x01),
//! enabling reading of external type reference information from .NET PE files. The TypeRef
//! table contains references to types defined in external assemblies or modules, which is
//! essential for resolving cross-assembly dependencies.
//!
//! ## Table Structure (ECMA-335 §II.22.38)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `ResolutionScope` | Coded index (`ResolutionScope`) | Parent scope containing the type |
//! | `TypeName` | String heap index | Simple name of the referenced type |
//! | `TypeNamespace` | String heap index | Namespace containing the referenced type |
//!
//! ## Resolution Scope Context
//!
//! The `ResolutionScope` coded index can reference:
//! - **Module** (tag 0) - Type defined in the global module
//! - **ModuleRef** (tag 1) - Type defined in an external module (same assembly)
//! - **AssemblyRef** (tag 2) - Type defined in an external assembly (most common)
//! - **TypeRef** (tag 3) - Nested type where the parent is also external
//!
//! ## Usage Context
//!
//! TypeRef entries are used for:
//! - **External Dependencies**: References to types in other assemblies
//! - **Nested Types**: References to types nested within external types
//! - **Module Boundaries**: References across module boundaries within assemblies
//! - **Framework Types**: References to system types like `System.Object`
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::typeref::writer`] - Binary serialization support
//! - [`crate::metadata::tables::typeref`] - High-level TypeRef table interface
//! - [`crate::metadata::tables::typeref::raw`] - Raw TypeRef structure definition

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, RowReadable, TableInfoRef, TypeRefRaw},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for TypeRefRaw {
    /// Reads a `TypeRef` table row from binary metadata.
    ///
    /// Parses the binary representation of a `TypeRef` table row according to the
    /// ECMA-335 specification, handling variable-width indexes based on heap and
    /// table sizes.
    ///
    /// ## Arguments
    /// * `data` - Binary metadata containing the `TypeRef` table
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for parsing variable-width fields
    ///
    /// ## Returns
    /// Returns a [`crate::metadata::tables::typeref::raw::TypeRefRaw`] instance with all fields populated from the binary data.
    ///
    /// ## Errors
    /// Returns an error if the binary data is insufficient or malformed.
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(TypeRefRaw {
            rid,
            token: Token::new(0x0100_0000 + rid),
            offset: *offset,
            resolution_scope: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::ResolutionScope,
            )?,
            type_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            type_namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // resolution_scope
            0x02, 0x02, // type_name
            0x03, 0x03, // type_namespace
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex::new(TableId::ModuleRef, 64, CodedIndexType::ResolutionScope)
            );
            assert_eq!(row.type_name, 0x0202);
            assert_eq!(row.type_namespace, 0x0303);
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
            0x01, 0x01, 0x01, 0x01, // resolution_scope
            0x02, 0x02, 0x02, 0x02, // type_name
            0x03, 0x03, 0x03, 0x03, // type_namespace
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeRef, 1),
                (TableId::AssemblyRef, u16::MAX as u32 + 2),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex::new(
                    TableId::ModuleRef,
                    0x404040,
                    CodedIndexType::ResolutionScope
                )
            );
            assert_eq!(row.type_name, 0x02020202);
            assert_eq!(row.type_namespace, 0x03030303);
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
