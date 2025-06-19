//! # `ModuleRef` Raw Implementation
//!
//! This module provides the raw variant of `ModuleRef` table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::Strings,
        tables::{ModuleRef, ModuleRefRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a `ModuleRef` table entry with unresolved indexes.
///
/// This structure represents the unprocessed entry from the `ModuleRef` metadata table
/// (ID 0x1A), which contains references to external modules required by the current assembly.
/// It contains raw index values that require resolution to actual metadata objects.
///
/// ## Purpose
///
/// The `ModuleRef` table provides references to external modules:
/// - Identifies external modules by name
/// - Enables cross-module type and method references
/// - Supports multi-module assembly structures
/// - Serves as foundation for import resolution
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved heap indexes requiring lookup
/// - Minimal memory footprint for storage
/// - Direct representation of file format
///
/// Use [`ModuleRef`] for resolved references and runtime access.
///
///
/// ## Cross-Module Support
///
/// `ModuleRef` entries enable various cross-module scenarios:
/// - `TypeRef` entries that reference types in external modules
/// - `MemberRef` entries that reference methods in external modules
/// - Multi-module assemblies with distributed components
/// - Import tracking and dependency resolution
///
/// ## ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.31 `ModuleRef` table structure.
pub struct ModuleRefRaw {
    /// Row identifier within the `ModuleRef` table.
    ///
    /// Unique identifier for this `ModuleRef` entry within the table.
    /// Combined with table ID 0x1A, forms the metadata token 0x1A??????.
    pub rid: u32,

    /// Metadata token for this `ModuleRef` entry.
    ///
    /// Token in the format 0x1A??????, where the high byte 0x1A identifies
    /// the `ModuleRef` table and the low 3 bytes contain the row ID.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Raw index into the string heap containing the module name.
    ///
    /// This unresolved index identifies the module name string in the #Strings heap.
    /// Must be resolved using the string heap to get the actual module name.
    /// Index size depends on string heap size (2 or 4 bytes).
    pub name: u32,
}

impl ModuleRefRaw {
    /// Converts this raw entry to an owned [`ModuleRef`] with resolved references.
    ///
    /// This method resolves the raw string heap index to actual module name data,
    /// creating a fully usable [`ModuleRef`] instance for runtime access. The module
    /// reference enables cross-module type and method resolution.
    ///
    /// ## Arguments
    ///
    /// * `strings` - The string heap for resolving the module name
    ///
    /// ## Returns
    ///
    /// A reference-counted [`Arc<ModuleRef>`] containing the resolved module reference.
    ///
    /// ## Errors
    ///
    /// - String heap entry cannot be resolved or is malformed
    /// - Heap index is out of bounds
    /// - Data corruption is detected
    pub fn to_owned(&self, strings: &Strings) -> Result<ModuleRefRc> {
        Ok(Arc::new(ModuleRef {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            name: strings.get(self.name as usize)?.to_string(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Applies a `ModuleRef` entry to update related metadata structures.
    ///
    /// `ModuleRef` entries represent external module references and are primarily used
    /// as targets by other tables (`TypeRef`, `MemberRef`) but don't themselves modify
    /// other metadata during the dual variant resolution phase. They serve as
    /// dependency anchors rather than active modification agents.
    ///
    /// This method is provided for consistency with the metadata loading architecture
    /// but performs no operations since `ModuleRef` entries are reference targets.
    ///
    /// ## Returns
    ///
    /// Always returns `Ok(())` as `ModuleRef` entries don't modify other tables.
    ///
    /// # Errors
    ///
    /// This function does not return an error.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ModuleRefRaw {
    /// Calculates the byte size of a `ModuleRef` table row.
    ///
    /// The row size depends on the metadata heap sizes and is calculated as:
    /// - `name`: 2 or 4 bytes (depends on string heap size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating heap index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* name */ sizes.str_bytes()
        )
    }

    /// Reads a single `ModuleRef` table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.31:
    /// 1. **Name** (2-4 bytes): Index into string heap containing module name
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ModuleRefRaw`] instance with populated fields
    ///
    /// ## Errors
    ///
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid heap index values
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ModuleRefRaw {
            rid,
            token: Token::new(0x1A00_0000 + rid),
            offset: *offset,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ModuleRef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ModuleRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1A000001);
            assert_eq!(row.name, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ModuleRef, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ModuleRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1A000001);
            assert_eq!(row.name, 0x01010101);
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
