//! Raw `EncLog` table representation.
//!
//! This module provides low-level access to `EncLog` metadata table data through the
//! [`crate::metadata::tables::enclog::raw::EncLogRaw`] structure. The `EncLog` table
//! contains Edit-and-Continue log entries that track metadata modifications made during
//! debugging sessions.
//!
//! # Architecture
//!
//! Like `AssemblyOS`, `EncLog` contains only primitive integer values (metadata tokens and
//! operation codes), making the "raw" and "owned" representations functionally identical.
//! This simplifies the dual variant pattern used throughout the metadata system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::enclog::raw::EncLogRaw`] - Raw table row structure
//! - [`crate::metadata::tables::enclog::EncLogRc`] - Reference-counted owned representation
//! - [`crate::metadata::tables::RowDefinition`] - Table parsing interface implementation
//!
//! # `EncLog` Table Format
//!
//! The `EncLog` table (0x1E) contains Edit-and-Continue operation records:
//! - **Token** (4 bytes): Metadata token identifying the affected element
//! - **`FuncCode`** (4 bytes): Operation code (create=0, update=1, delete=2)
//!
//! # Edit-and-Continue Context
//!
//! This table is used by .NET's Edit-and-Continue debugging feature to track all metadata
//! changes made during debugging sessions. When developers modify code while debugging,
//! the compiler generates new metadata and records the changes in this table, allowing
//! the runtime to understand what has been modified.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token representation for metadata references
//! - [`crate::file::io`] - Binary data reading utilities
//!
//! # References
//!
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification

use std::sync::Arc;

use crate::{
    file::io::read_le_at,
    metadata::{
        tables::{EncLogRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `EncLog` table row representing Edit-and-Continue operation log entries
///
/// Contains metadata change tracking information for debugging sessions that use
/// Edit-and-Continue functionality. Unlike most metadata tables, `EncLog` contains only
/// primitive integer values and requires no heap resolution, making this structure
/// immediately usable without further processing.
///
/// The `EncLog` table (0x1E) is optional and only present in assemblies that have been
/// modified during debugging sessions using Edit-and-Continue.
///
/// # Data Model
///
/// All fields contain direct integer values rather than heap indexes:
/// - No string heap references
/// - No blob heap references  
/// - All data is self-contained within the table row
///
/// # Reference
/// - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification
pub struct EncLogRaw {
    /// Row identifier within the `EncLog` metadata table
    ///
    /// The 1-based index of this `EncLog` row. Multiple edit operations can be recorded,
    /// typically in chronological order of the debugging session.
    pub rid: u32,

    /// Metadata token for this `EncLog` row
    ///
    /// Combines the table identifier (0x1E for `EncLog`) with the row ID to create
    /// a unique token. Format: `0x1E000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `EncLog` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Metadata token identifying the affected element
    ///
    /// 4-byte metadata token that identifies which metadata element (type, method, field, etc.)
    /// was affected by this Edit-and-Continue operation. The token format follows the standard
    /// metadata token structure: `table_id` (upper byte) + `row_id` (lower 3 bytes).
    pub token_value: u32,

    /// Operation code indicating the type of edit performed
    ///
    /// 4-byte value specifying what type of Edit-and-Continue operation was performed:
    /// - 0: Create - New metadata item added during edit session
    /// - 1: Update - Existing metadata item modified during edit session  
    /// - 2: Delete - Metadata item marked for deletion during edit session
    pub func_code: u32,
}

impl EncLogRaw {
    /// Convert raw `EncLog` data to owned representation
    ///
    /// Since the `EncLog` table contains only primitive values with no heap references,
    /// this method simply clones the data and wraps it in an [`Arc`] for consistency
    /// with the dual variant pattern used across all metadata tables.
    ///
    /// # Returns
    /// * `Ok(`[`crate::metadata::tables::EncLogRc`]`)` - Reference-counted `EncLog` data
    ///
    /// # Errors
    /// This method currently never returns an error but maintains the `Result` type for
    /// consistency with other table conversion methods.
    pub fn to_owned(&self) -> Result<EncLogRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Apply `EncLog` row data to update related metadata structures
    ///
    /// `EncLog` entries specify Edit-and-Continue operations and are self-contained.
    /// Unlike other metadata tables that may have cross-references, `EncLog` entries don't
    /// require updates to other tables during the dual variant resolution phase.
    ///
    /// This method exists to satisfy the metadata processing interface but performs
    /// no actual operations since `EncLog` data is purely tracking information.
    ///
    /// # Returns
    /// Always returns `Ok(())` since `EncLog` entries don't modify other tables
    ///
    /// # Errors
    /// This function never returns an error.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for EncLogRaw {
    /// Calculate the byte size of an `EncLog` table row
    ///
    /// Returns the fixed size since `EncLog` contains only primitive integer fields
    /// with no variable-size heap indexes. Total size is always 8 bytes (2 × 4-byte integers).
    ///
    /// # Row Layout
    /// - `token_value`: 4 bytes (metadata token)
    /// - `func_code`: 4 bytes (operation code)
    ///
    /// # Arguments
    /// * `_sizes` - Unused for `EncLog` since no heap indexes are present
    ///
    /// # Returns
    /// Fixed size of 8 bytes for all `EncLog` rows
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* token_value */ 4_u32 +
        /* func_code */   4_u32
    }

    /// Read and parse an `EncLog` table row from binary data
    ///
    /// Deserializes one `EncLog` table entry from the metadata tables stream.
    /// `EncLog` has a fixed 8-byte layout with two 4-byte integer fields.
    ///
    /// # Arguments
    /// * `data` - Binary metadata tables stream data
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - Row identifier for this `EncLog` entry
    /// * `_sizes` - Unused since `EncLog` has no heap indexes
    ///
    /// # Returns
    /// * `Ok(EncLogRaw)` - Successfully parsed `EncLog` row
    /// * `Err(`[`crate::Error`]`)` - If data is malformed or insufficient
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(EncLogRaw {
            rid,
            token: Token::new(0x1E00_0000 + rid),
            offset: *offset,
            token_value: read_le_at::<u32>(data, offset)?,
            func_code: read_le_at::<u32>(data, offset)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn enclog_basic_parsing() {
        let data = vec![
            0x01, 0x00, 0x02, 0x06, // token_value (0x06020001 - MethodDef table, row 1)
            0x00, 0x00, 0x00, 0x00, // func_code (0 = Create)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::EncLog, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EncLogRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EncLogRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1E000001);
            assert_eq!(row.token_value, 0x06020001);
            assert_eq!(row.func_code, 0);
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
