//! Raw TypeRef table implementation for .NET metadata.
//!
//! This module provides the [`crate::metadata::tables::typeref::raw::TypeRefRaw`] structure for representing rows in the TypeRef table,
//! which contains references to types defined in external assemblies or modules. TypeRef entries
//! are essential for cross-assembly type resolution and dependency tracking.
//!
//! ## Table Structure
//! The TypeRef table (`TableId` 0x01) contains the following columns:
//! - **ResolutionScope** (coded index): Parent scope (Module, ModuleRef, AssemblyRef, or TypeRef)
//! - **TypeName** (string heap index): Simple name of the referenced type
//! - **TypeNamespace** (string heap index): Namespace containing the referenced type
//!
//! ## Resolution Scope Types
//! The ResolutionScope coded index can reference:
//! - **AssemblyRef**: Type defined in an external assembly (most common)
//! - **ModuleRef**: Type defined in an external module of the same assembly
//! - **TypeRef**: Nested type where the parent is also external
//! - **Module**: Type defined in the global module (rare)
//!
//! ## ECMA-335 Reference
//! See ECMA-335, Partition II, Section 22.38 for the complete TypeRef table specification.

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::Strings,
        tables::{CodedIndex, CodedIndexType, RowDefinition, TableInfoRef},
        token::Token,
        typesystem::{CilType, CilTypeRc, CilTypeReference},
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a row in the TypeRef metadata table.
///
/// The TypeRef table contains references to types defined in external assemblies or modules.
/// Each row represents a complete type reference including its resolution scope (where the type
/// is defined), type name, and namespace. These references are essential for cross-assembly
/// type resolution and dependency tracking.
///
/// ## Fields Overview
/// - **rid**: Row identifier within the TypeRef table
/// - **token**: Metadata token with table ID 0x01 and row ID
/// - **resolution_scope**: Coded index to parent scope (Module, ModuleRef, AssemblyRef, or TypeRef)
/// - **type_name/type_namespace**: String heap indices for the type's name and namespace
///
/// ## Resolution Scope Patterns
/// - **AssemblyRef**: Most common - type defined in external assembly
/// - **ModuleRef**: Type defined in external module of same assembly
/// - **TypeRef**: Nested type where parent is also external
/// - **Module**: Type defined in global module (rare)
///
/// ## ECMA-335 Compliance
/// This structure directly corresponds to the TypeRef table format specified in
/// ECMA-335, Partition II, Section 22.38.
///
/// **Table ID**: `0x01`
pub struct TypeRefRaw {
    /// Row identifier within the TypeRef table.
    ///
    /// This 1-based index uniquely identifies this type reference within the table.
    pub rid: u32,

    /// Metadata token for this type reference.
    ///
    /// Constructed as `0x01000000 | rid`, providing a unique identifier
    /// across all metadata tables in the assembly.
    pub token: Token,

    /// Byte offset of this row within the TypeRef table data.
    ///
    /// Used for debugging and low-level table operations.
    pub offset: usize,

    /// Coded index to the resolution scope defining where this type is located.
    ///
    /// Points to a Module, ModuleRef, AssemblyRef, or TypeRef table entry that
    /// indicates where the referenced type is defined. The specific table
    /// determines the scope type (external assembly, external module, etc.).
    pub resolution_scope: CodedIndex,

    /// Index into the String heap for the type name.
    ///
    /// Points to the simple name of the referenced type (without namespace).
    pub type_name: u32,

    /// Index into the String heap for the type namespace.
    ///
    /// Points to the namespace containing the referenced type, or 0 for the global namespace.
    pub type_namespace: u32,
}

impl TypeRefRaw {
    /// Applies this TypeRef entry to update related metadata structures.
    ///
    /// TypeRef entries represent references to external types and serve as passive
    /// references that don't modify other metadata structures during loading.
    /// Unlike some other table types, TypeRef entries don't require cross-table
    /// updates or modifications during the metadata resolution phase.
    ///
    /// ## Returns
    /// Always returns [`Ok(())`] as TypeRef entries don't modify other tables directly.
    ///
    /// ## ECMA-335 Reference
    /// See ECMA-335, Partition II, Section 22.38 for TypeRef table semantics.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }

    /// Converts this raw TypeRef entry into a fully resolved [`crate::metadata::typesystem::CilType`].
    ///
    /// This method resolves the type reference into a complete type representation
    /// by resolving the resolution scope and type names. The resulting type serves
    /// as a reference to an external type defined in another assembly or module.
    ///
    /// ## Arguments
    /// * `get_ref` - Closure to resolve coded indexes to scope references
    /// * `strings` - The #String heap for resolving type names and namespaces
    ///
    /// ## Returns
    /// Returns a reference-counted [`crate::metadata::typesystem::CilType`] representing the external type reference.
    ///
    /// ## Errors
    /// - Type name or namespace cannot be resolved from the strings heap
    /// - Resolution scope coded index cannot be resolved to a valid scope
    /// - String heap indices are invalid or point to non-existent data
    pub fn to_owned<F>(&self, get_ref: F, strings: &Strings) -> Result<CilTypeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let resolution_scope = match get_ref(&self.resolution_scope) {
            CilTypeReference::None => {
                return Err(malformed_error!(
                    "Failed to resolve resolution scope - {}",
                    self.resolution_scope.token.value()
                ))
            }
            resolved => Some(resolved),
        };

        Ok(Arc::new(CilType::new(
            self.token,
            strings.get(self.type_namespace as usize)?.to_string(),
            strings.get(self.type_name as usize)?.to_string(),
            resolution_scope,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            None,
        )))
    }
}

impl<'a> RowDefinition<'a> for TypeRefRaw {
    /// Calculates the byte size of a TypeRef table row.
    ///
    /// The row size depends on the size configuration of heaps and tables:
    /// - ResolutionScope: 2 or 4 bytes depending on ResolutionScope coded index size
    /// - TypeName/TypeNamespace: 2 or 4 bytes depending on string heap size
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// The total byte size required for one TypeRef table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* resolution_scope */  sizes.coded_index_bytes(CodedIndexType::ResolutionScope) +
            /* type_namespace */    sizes.str_bytes() +
            /* type_name */         sizes.str_bytes()
        )
    }

    /// Reads a TypeRef table row from binary metadata.
    ///
    /// Parses the binary representation of a TypeRef table row according to the
    /// ECMA-335 specification, handling variable-width indexes based on heap and
    /// table sizes.
    ///
    /// ## Arguments
    /// * `data` - Binary metadata containing the TypeRef table
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for parsing variable-width fields
    ///
    /// ## Returns
    /// Returns a [`crate::metadata::tables::typeref::raw::TypeRefRaw`] instance with all fields populated from the binary data.
    ///
    /// ## Errors
    /// Returns an error if the binary data is insufficient or malformed.
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
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
                CodedIndex {
                    tag: TableId::ModuleRef,
                    row: 64,
                    token: Token::new(64 | 0x1A000000),
                }
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
                CodedIndex {
                    tag: TableId::ModuleRef,
                    row: 0x404040,
                    token: Token::new(0x404040 | 0x1A000000),
                }
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
