//! Implementation of `RowReadable` for `ModuleRefRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `ModuleRef` table (ID 0x1A),
//! enabling reading of module reference information from .NET PE files. The ModuleRef table
//! contains references to external modules that are imported by the current assembly, providing
//! the metadata necessary for module resolution and cross-module type access.
//!
//! ## Table Structure (ECMA-335 §II.22.31)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Name` | String heap index | Name of the referenced module |
//!
//! ## Usage Context
//!
//! ModuleRef entries are used for:
//! - **External Module References**: Identifying modules imported by the current assembly
//! - **Multi-Module Assemblies**: Supporting assemblies composed of multiple modules
//! - **Type Resolution**: Resolving types defined in external modules
//! - **Module Loading**: Providing information needed for dynamic module loading
//! - **Cross-Module Access**: Enabling access to types and members in other modules
//!
//! ## Module Reference Architecture
//!
//! .NET supports multi-module assemblies where types can be distributed across modules:
//! - **Module Names**: Each module has a unique name within the assembly
//! - **File References**: ModuleRef entries reference physical module files
//! - **Type Distribution**: Types can be defined in different modules of the same assembly
//! - **Runtime Loading**: Modules are loaded on-demand during execution
//!
//! ## Integration with Assembly Structure
//!
//! ModuleRef entries integrate with the broader assembly metadata:
//! - **File Table**: Links to actual module files on disk
//! - **ExportedType Table**: Types exported from referenced modules
//! - **ManifestResource Table**: Resources contained in referenced modules
//! - **Assembly Metadata**: Module references are scoped to the containing assembly
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::moduleref::writer`] - Binary serialization support
//! - [`crate::metadata::tables::moduleref`] - High-level ModuleRef interface
//! - [`crate::metadata::tables::moduleref::raw`] - Raw structure definition
//! - [`crate::metadata::tables::file`] - File table entries for module file references

use crate::{
    metadata::{
        tables::{ModuleRefRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for ModuleRefRaw {
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
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
    use std::sync::Arc;

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
