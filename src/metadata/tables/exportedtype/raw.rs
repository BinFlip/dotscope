//! Raw `ExportedType` table representation.
//!
//! This module provides the [`crate::metadata::tables::exportedtype::raw::ExportedTypeRaw`] struct
//! for low-level access to `ExportedType` metadata table data with unresolved indexes and coded indices.
//! This represents the binary format of `ExportedType` records as they appear in the metadata tables
//! stream, requiring resolution to create usable data structures.
//!
//! # `ExportedType` Table Format
//!
//! The `ExportedType` table (0x27) defines cross-assembly type exports with these fields:
//! - **Flags** (4 bytes): Type attributes bitmask controlling visibility and behavior
//! - **`TypeDefId`** (4 bytes): Optional hint for `TypeDef` resolution (may be 0)
//! - **`TypeName`** (2/4 bytes): String heap index for the type name
//! - **`TypeNamespace`** (2/4 bytes): String heap index for the type namespace
//! - **Implementation** (2/4 bytes): Implementation coded index (File or `AssemblyRef`)
//!
//! `ExportedType` entries enable cross-assembly type access by defining which types
//! are exported from this assembly and where they are actually implemented.
//!
//! # Export Scenarios
//!
//! `ExportedType` tables support several assembly composition patterns:
//! - **Type Forwarding**: Redirecting type references to different assemblies during refactoring
//! - **Multi-Module Assemblies**: Exposing types from different files within the same assembly
//! - **Assembly Facades**: Creating simplified public interfaces over complex implementations
//!
//! # Implementation Coded Index
//!
//! The Implementation field can point to:
//! - **`File`**: Type defined in another file within this assembly (multi-module scenario)
//! - **`AssemblyRef`**: Type forwarded to a different assembly (type forwarding scenario)
//! - **`ExportedType`**: Nested export reference (rare but possible for complex scenarios)
//!
//! # Usage
//!
//! This type is used internally for metadata parsing and should typically be converted
//! to [`crate::metadata::tables::exportedtype::owned::ExportedType`] via [`crate::metadata::tables::exportedtype::raw::ExportedTypeRaw::to_owned`] for practical use.
//! The [`crate::metadata::tables::exportedtype::raw::ExportedTypeRaw::apply`] method provides a consistent interface but performs
//! no operations since `ExportedType` doesn't modify other metadata structures.
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ExportedType` table specification

use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, ExportedType, ExportedTypeRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `ExportedType` table row with unresolved indexes and coded indices
///
/// Represents the binary format of an `ExportedType` metadata table entry (table ID 0x27) as stored
/// in the metadata tables stream. All string references and implementation references are stored as
/// indexes that must be resolved using the appropriate heaps and cross-reference functions.
///
/// `ExportedType` entries define types that are exported from this assembly for access by other
/// assemblies, with the actual implementation potentially located in different files or assemblies.
/// This enables complex assembly composition scenarios including type forwarding and multi-module
/// assemblies.
///
/// # Type Export Mechanism
///
/// `ExportedType` entries establish the public interface of assemblies:
/// - **Type Identity**: Name and namespace define the exported type signature
/// - **Implementation Location**: Coded index points to where the type is actually defined
/// - **Resolution Hints**: Optional `TypeDef` ID assists in efficient type resolution
/// - **Visibility Control**: Flags determine how the type can be accessed externally
///
/// # Assembly Composition Support
///
/// The flexible Implementation field enables various composition patterns:
/// - **File References**: Multi-module assemblies with types in different files
/// - **`AssemblyRef` References**: Type forwarding to entirely different assemblies
/// - **Nested References**: Complex export chains for sophisticated scenarios
///
/// # Reference
/// - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ExportedType` table specification
pub struct ExportedTypeRaw {
    /// Row identifier within the `ExportedType` metadata table
    ///
    /// The 1-based index of this `ExportedType` row. Used for metadata token generation
    /// and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this `ExportedType` row
    ///
    /// Combines the table identifier (0x27 for `ExportedType`) with the row ID to create
    /// a unique token. Format: `0x27000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `ExportedType` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Type attributes bitmask (unresolved)
    ///
    /// 4-byte bitmask using [`crate::metadata::tables::TypeAttributes`] constants
    /// that control type visibility, inheritance, and runtime behavior.
    /// See [ECMA-335 II.23.1.15] for attribute definitions.
    pub flags: u32,

    /// Optional `TypeDef` identifier hint (unresolved)
    ///
    /// 4-byte hint into the target `TypeDef` table for optimization during type resolution.
    /// This is a hint only; primary resolution uses name and namespace. May be 0 if
    /// no hint is available or when the type is forwarded to another assembly.
    pub type_def_id: u32,

    /// Type name string heap index (unresolved)
    ///
    /// Index into the String heap containing the simple type name. Must be resolved
    /// using the String heap to obtain the actual type name string.
    pub name: u32,

    /// Type namespace string heap index (unresolved)
    ///
    /// Index into the String heap containing the type namespace, or 0 for types in
    /// the global namespace. Must be resolved using the String heap when non-zero.
    pub namespace: u32,

    /// Implementation coded index (unresolved)
    ///
    /// Implementation coded index that can point to File, `AssemblyRef`, or `ExportedType`
    /// tables to indicate where the type is actually implemented. Must be resolved
    /// using the appropriate cross-reference function.
    pub implementation: CodedIndex,
}

impl ExportedTypeRaw {
    /// Convert to owned `ExportedType` with resolved references and owned data
    ///
    /// This method converts the raw `ExportedType` entry into a fully resolved [`ExportedType`]
    /// structure with owned data and resolved cross-references. The resulting structure provides
    /// immediate access to type export information without requiring additional heap lookups
    /// or cross-reference resolution.
    ///
    /// # Arguments
    ///
    /// * `get_ref` - Closure for resolving Implementation coded index to type references
    /// * `string` - The String heap for resolving type name and namespace
    ///
    /// # Returns
    ///
    /// Returns [`ExportedTypeRc`] (Arc-wrapped [`ExportedType`]) on success, providing
    /// shared ownership of the resolved `ExportedType` data.
    ///
    /// # Errors
    ///
    /// - The Implementation coded index cannot be resolved to a valid reference
    /// - The String heap lookup fails for the type name
    /// - The String heap lookup fails for the namespace (when non-zero)
    /// - The resolved Implementation reference is invalid or None
    pub fn to_owned<F>(&self, get_ref: F, string: &Strings) -> Result<ExportedTypeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let implementation = match get_ref(&self.implementation) {
            CilTypeReference::None => {
                return Err(malformed_error!(
                    "Failed to resolve implementation token - {}",
                    self.implementation.token.value()
                ))
            }
            resolved => resolved,
        };

        Ok(Arc::new(ExportedType {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            type_def_id: self.type_def_id | 0x0200_0000,
            name: string.get(self.name as usize)?.to_string(),
            namespace: if self.namespace == 0 {
                None
            } else {
                Some(string.get(self.namespace as usize)?.to_string())
            },
            implementation,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply this `ExportedType` entry during metadata loading
    ///
    /// Processes the raw `ExportedType` entry as part of the metadata loading framework.
    /// Unlike tables that establish relationships between entities, `ExportedType` entries
    /// serve primarily as metadata descriptors for cross-assembly type access and don't
    /// require cross-table modifications during the loading phase.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` since `ExportedType` entries don't perform cross-table
    /// modifications during the initial loading phase.
    ///
    /// # Errors
    ///
    /// This function never returns an error but maintains the standard `apply()` signature
    /// for consistency with other metadata table implementations.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ExportedTypeRaw {
    /// Calculate the byte size of an `ExportedType` table row
    ///
    /// Computes the total size in bytes required to store one `ExportedType` table row
    /// based on the table size information. The size depends on whether large string
    /// indexes and Implementation coded indexes are required.
    ///
    /// # Row Structure
    ///
    /// - **flags**: 4 bytes (type attributes bitmask)
    /// - **`type_def_id`**: 4 bytes (`TypeDef` hint)
    /// - **`type_name`**: 2 or 4 bytes (String heap index)
    /// - **`type_namespace`**: 2 or 4 bytes (String heap index)
    /// - **implementation**: 2, 3, or 4 bytes (Implementation coded index)
    ///
    /// # Arguments
    ///
    /// * `sizes` - Table size information determining index byte sizes
    ///
    /// # Returns
    ///
    /// Returns the total byte size required for one `ExportedType` table row.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */          4 +
            /* type_def_id */    4 +
            /* type_name */      sizes.str_bytes() +
            /* type_namespace */ sizes.str_bytes() +
            /* implementation */ sizes.coded_index_bytes(CodedIndexType::Implementation)
        )
    }

    /// Read an `ExportedType` row from the metadata tables stream
    ///
    /// Parses one `ExportedType` table row from the binary metadata stream, handling
    /// variable-size indexes based on table size information. Advances the offset
    /// to point to the next row after successful parsing.
    ///
    /// # Arguments
    ///
    /// * `data` - The metadata tables stream binary data
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - Row identifier for this `ExportedType` entry (1-based)
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// # Returns
    ///
    /// Returns a parsed [`ExportedTypeRaw`] instance with all fields populated
    /// from the binary data.
    ///
    /// # Errors
    ///
    /// - The data stream is truncated or corrupted
    /// - Index values exceed expected ranges
    /// - Implementation coded index reading fails
    /// - Binary parsing encounters invalid data
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ExportedTypeRaw {
            rid,
            token: Token::new(0x2700_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            type_def_id: read_le_at::<u32>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            implementation: CodedIndex::read(data, offset, sizes, CodedIndexType::Implementation)?,
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, // type_name
            0x04, 0x04, // type_namespace
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, 1),
                (TableId::File, 10),        // Add File table
                (TableId::AssemblyRef, 10), // Add AssemblyRef table
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ExportedTypeRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ExportedTypeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x27000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.type_def_id, 0x02020202);
            assert_eq!(row.name, 0x0303);
            assert_eq!(row.namespace, 0x0404);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
                }
            );
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, 0x03, 0x03, // type_name
            0x04, 0x04, 0x04, 0x04, // type_namespace
            0x04, 0x00, 0x00, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ExportedTypeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ExportedTypeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x27000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.type_def_id, 0x02020202);
            assert_eq!(row.name, 0x03030303);
            assert_eq!(row.namespace, 0x04040404);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
                }
            );
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
