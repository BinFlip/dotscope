//! Implementation of `RowReadable` for `TypeDefRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `TypeDef` table (ID 0x02),
//! enabling reading of type definition metadata from .NET PE files. The TypeDef table
//! defines all types (classes, interfaces, value types, enums, delegates) within the
//! current module, serving as the core of the type system.
//!
//! ## Table Structure (ECMA-335 §II.22.37)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u32` | Type attributes bitmask (visibility, layout, semantics) |
//! | `TypeName` | String heap index | Simple name of the type |
//! | `TypeNamespace` | String heap index | Namespace containing the type |
//! | `Extends` | Coded index (`TypeDefOrRef`) | Base type reference |
//! | `FieldList` | Field table index | First field belonging to this type |
//! | `MethodList` | MethodDef table index | First method belonging to this type |
//!
//! ## Type Attributes (Flags)
//!
//! The flags field encodes various type characteristics:
//! - **Visibility**: Public, nested public, nested private, etc.
//! - **Layout**: Auto, sequential, explicit field layout
//! - **Semantics**: Class, interface, abstract, sealed
//! - **String Format**: ANSI, Unicode, auto string marshalling
//! - **Initialization**: Before field init requirements
//!
//! ## Coded Index Context
//!
//! The `Extends` field uses a `TypeDefOrRef` coded index that can reference:
//! - **TypeDef** (tag 0) - Base type defined in current module
//! - **TypeRef** (tag 1) - Base type from external assembly
//! - **TypeSpec** (tag 2) - Generic or complex base type
//!
//! ## Member Lists
//!
//! The `FieldList` and `MethodList` fields point to the first field and method
//! belonging to this type. Members are organized as contiguous ranges, with
//! the next type's list marking the end of the current type's members.
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::typedef::writer`] - Binary serialization support
//! - [`crate::metadata::tables::typedef`] - High-level TypeDef table interface
//! - [`crate::metadata::tables::typedef::raw`] - Raw TypeDef structure definition

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, RowReadable, TableId, TableInfoRef, TypeDefRaw},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for TypeDefRaw {
    /// Reads a `TypeDef` table row from binary metadata.
    ///
    /// Parses the binary representation of a `TypeDef` table row according to the
    /// ECMA-335 specification, handling variable-width indexes based on heap and
    /// table sizes.
    ///
    /// ## Arguments
    /// * `data` - Binary metadata containing the `TypeDef` table
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for parsing variable-width fields
    ///
    /// ## Returns
    /// Returns a [`TypeDefRaw`] instance with all fields populated from the binary data.
    ///
    /// ## Errors
    /// Returns an error if the binary data is insufficient or malformed.
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(TypeDefRaw {
            rid,
            token: Token::new(0x0200_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            type_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            type_namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            extends: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
            field_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::Field))?,
            method_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
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
            0x00, 0x00, 0x00, 0x01, // flags
            0x42, 0x00, // type_name
            0x43, 0x00, // type_namespace
            0x00, 0x02, // extends
            0x00, 0x03, // field_list
            0x00, 0x04, // method_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeDefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x02000001);
            assert_eq!(row.flags, 0x01000000);
            assert_eq!(row.type_name, 0x42);
            assert_eq!(row.type_namespace, 0x43);
            assert_eq!(
                row.extends,
                CodedIndex::new(TableId::TypeDef, 0x80, CodedIndexType::TypeDefOrRef)
            );
            assert_eq!(row.field_list, 0x0300);
            assert_eq!(row.method_list, 0x0400);
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
            0x00, 0x00, 0x00, 0x01, // flags
            0x00, 0x00, 0x00, 0x02, // type_name
            0x00, 0x00, 0x00, 0x03, // type_namespace
            0x00, 0x00, 0x00, 0x04, // extends
            0x00, 0x00, 0x00, 0x05, // field_list
            0x00, 0x00, 0x00, 0x06, // method_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, u16::MAX as u32 + 2),
                (TableId::MethodDef, u16::MAX as u32 + 2),
                (TableId::TypeDef, u16::MAX as u32 + 2),
                (TableId::TypeRef, u16::MAX as u32 + 2),
                (TableId::TypeSpec, u16::MAX as u32 + 2),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeDefRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: TypeDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x02000001);
            assert_eq!(row.flags, 0x01000000);
            assert_eq!(row.type_name, 0x02000000);
            assert_eq!(row.type_namespace, 0x03000000);
            assert_eq!(
                row.extends,
                CodedIndex::new(TableId::TypeDef, 0x1000000, CodedIndexType::TypeDefOrRef)
            );
            assert_eq!(row.field_list, 0x05000000);
            assert_eq!(row.method_list, 0x06000000);
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
