//! Implementation of `RowReadable` for `ParamRaw` metadata table entries.
//!
//! This module provides binary deserialization support for the `Param` table (ID 0x08),
//! enabling reading of method parameter metadata from .NET PE files. The Param table
//! contains information about method parameters including their names, attributes,
//! sequence numbers, and marshalling details, forming a crucial part of method signatures.
//!
//! ## Table Structure (ECMA-335 §II.22.33)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u16` | Parameter attributes bitmask |
//! | `Sequence` | `u16` | Parameter sequence number (0 = return type, 1+ = parameters) |
//! | `Name` | String heap index | Parameter name identifier |
//!
//! ## Parameter Attributes
//!
//! The `Flags` field contains parameter attributes with common values:
//! - `0x0001` - `In` (input parameter)
//! - `0x0002` - `Out` (output parameter)
//! - `0x0010` - `Optional` (optional parameter with default value)
//! - `0x1000` - `HasDefault` (parameter has default value)
//! - `0x2000` - `HasFieldMarshal` (parameter has marshalling information)
//!
//! ## Usage Context
//!
//! Param entries are used for:
//! - **Method Signatures**: Defining parameter information for method definitions
//! - **Parameter Attributes**: Specifying parameter direction, optionality, and marshalling
//! - **Default Values**: Linking to default parameter values in Constant table
//! - **Reflection Operations**: Runtime parameter discovery and invocation
//! - **Interop Support**: P/Invoke parameter marshalling and type conversion
//!
//! ## Sequence Numbers
//!
//! Parameter sequence numbers follow a specific convention:
//! - **Sequence 0**: Return type parameter (when return type has attributes)
//! - **Sequence 1+**: Method parameters in declaration order
//! - **Contiguous**: Sequence numbers must be contiguous for proper resolution
//! - **Method Scope**: Sequence numbers are relative to the containing method
//!
//! ## Parameter Resolution
//!
//! Parameters are associated with methods through several mechanisms:
//! - **Direct Range**: Method parameter lists define contiguous Param table ranges
//! - **ParamPtr Indirection**: Optional indirection through ParamPtr table
//! - **Sequence Ordering**: Parameters ordered by sequence number within method scope
//! - **Attribute Resolution**: Parameter attributes resolved from various tables
//!
//! ## Thread Safety
//!
//! The `RowReadable` implementation is stateless and safe for concurrent use across
//! multiple threads during metadata loading operations.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::param::writer`] - Binary serialization support
//! - [`crate::metadata::tables::param`] - High-level Param interface
//! - [`crate::metadata::tables::param::raw`] - Raw structure definition
//! - [`crate::metadata::tables::methoddef`] - Method parameter associations
//! - [`crate::metadata::tables::paramptr`] - Parameter indirection support

use crate::{
    metadata::{
        tables::{ParamRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for ParamRaw {
    /// Reads a single Param table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.33:
    /// 1. **Flags** (2 bytes): Parameter attributes bitmask
    /// 2. **Sequence** (2 bytes): Parameter sequence number
    /// 3. **Name** (2-4 bytes): Index into string heap containing parameter name
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ParamRaw`] instance with populated fields
    ///
    /// ## Errors
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid string heap index values
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ParamRaw {
            rid,
            token: Token::new(0x0800_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            sequence: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // sequences
            0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x0303);
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
            0x02, 0x02, // sequence
            0x03, 0x03, 0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x03030303);
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
