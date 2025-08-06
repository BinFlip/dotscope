//! Implementation of `RowReadable` for `ModuleRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `Module` table (ID 0x00),
//! enabling reading of module information from .NET PE files. The Module table contains
//! essential information about the current module including its name, version identifier,
//! and debugging support fields for Edit and Continue operations.
//!
//! ## Table Structure (ECMA-335 §II.22.30)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Generation` | u16 | Reserved field (always 0) |
//! | `Name` | String heap index | Name of the module |
//! | `Mvid` | GUID heap index | Module version identifier (unique) |
//! | `EncId` | GUID heap index | Edit and Continue identifier |
//! | `EncBaseId` | GUID heap index | Edit and Continue base identifier |
//!
//! ## Usage Context
//!
//! Module entries are used for:
//! - **Module Identification**: Providing unique identification through MVID
//! - **Assembly Composition**: Defining the primary module of an assembly
//! - **Edit and Continue**: Supporting debugging features with ENC identifiers
//! - **Version Tracking**: Maintaining module version information across builds
//! - **Metadata Binding**: Serving as the root context for all other metadata tables
//!
//! ## Module Architecture
//!
//! .NET assemblies always contain exactly one Module table entry:
//! - **Primary Module**: The Module table contains exactly one row representing the primary module
//! - **Multi-Module Assemblies**: Additional modules are referenced via ModuleRef table
//! - **Unique Identity**: Each module has a unique MVID (Module Version Identifier)
//! - **Debugging Support**: ENC fields support Edit and Continue debugging scenarios
//!
//! ## Integration with Assembly Structure
//!
//! The Module table serves as the foundation for assembly metadata:
//! - **Assembly Manifest**: Contains the primary module information
//! - **Type Definitions**: All TypeDef entries belong to this module
//! - **Metadata Root**: Provides the context for all other metadata tables
//! - **Cross-References**: Other tables reference this module's types and members
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::module::writer`] - Binary serialization support
//! - [`crate::metadata::tables::module`] - High-level Module interface
//! - [`crate::metadata::tables::module::raw`] - Raw structure definition
//! - [`crate::metadata::tables::moduleref`] - External module references

use crate::{
    metadata::{
        tables::{ModuleRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for ModuleRaw {
    /// Reads a single Module table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.30:
    /// 1. **Generation** (2 bytes): Reserved field, always zero
    /// 2. **Name** (2-4 bytes): Index into string heap containing module name
    /// 3. **Mvid** (2-4 bytes): Index into GUID heap containing module version identifier
    /// 4. **`EncId`** (2-4 bytes): Index into GUID heap for Edit and Continue
    /// 5. **`EncBaseId`** (2-4 bytes): Index into GUID heap for ENC base
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry (always 1 for Module table)
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ModuleRaw`] instance with populated fields
    ///
    /// ## Errors
    ///
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid heap index values
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ModuleRaw {
            rid,
            token: Token::new(rid),
            offset: *offset,
            generation: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            mvid: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
            encid: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
            encbaseid: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
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
            0x01, 0x01, // generation
            0x02, 0x02, // name
            0x03, 0x03, // mvid
            0x04, 0x04, // encid
            0x05, 0x05, // encbaseid
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Module, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ModuleRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x00000001);
            assert_eq!(row.generation, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.mvid, 0x0303);
            assert_eq!(row.encid, 0x0404);
            assert_eq!(row.encbaseid, 0x0505);
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
            0x01, 0x01, // generation
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // mvid
            0x04, 0x04, 0x04, 0x04, // encid
            0x05, 0x05, 0x05, 0x05, // encbaseid
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Module, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ModuleRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x00000001);
            assert_eq!(row.generation, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.mvid, 0x03030303);
            assert_eq!(row.encid, 0x04040404);
            assert_eq!(row.encbaseid, 0x05050505);
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
