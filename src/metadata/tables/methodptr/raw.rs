//! Raw `MethodPtr` table structure with unresolved indexes and indirection mappings.
//!
//! This module provides the [`MethodPtrRaw`] struct, which represents method pointer entries
//! as stored in the metadata stream. The structure contains method indexes that provide
//! an additional level of indirection for accessing `MethodDef` table entries in specialized
//! scenarios requiring method table reorganization or runtime modification.
//!
//! # Purpose
//! [`MethodPtrRaw`] serves as the direct representation of `MethodPtr` table entries from the
//! binary metadata stream, providing stable logical-to-physical method mappings. This raw
//! format is processed during metadata loading to create [`MethodPtr`] instances with
//! complete indirection mapping information.
//!
//! [`MethodPtr`]: crate::metadata::tables::MethodPtr

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{MethodPtr, MethodPtrRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

/// Raw `MethodPtr` table entry with unresolved indexes and indirection mapping.
///
/// This structure represents a method pointer entry as stored directly in the metadata stream.
/// It provides an additional level of indirection for accessing `MethodDef` table entries,
/// enabling stable method references during scenarios requiring method table reorganization
/// or runtime method modification.
///
/// # Table Structure (ECMA-335 §22.28)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Method | `MethodDef` index | Physical method definition reference |
///
/// # Indirection Mechanism
/// The `MethodPtr` table establishes logical-to-physical method mappings:
/// - **Logical reference**: This entry's RID serves as the stable logical method identifier
/// - **Physical reference**: The `method` field points to the actual `MethodDef` table entry
/// - **Stable mapping**: Logical identifiers remain constant during method table changes
/// - **Transparent resolution**: Higher-level systems use logical tokens without awareness
///
/// # Usage Context
/// `MethodPtr` tables appear in specialized development and runtime scenarios:
/// - **Edit-and-continue**: Development environments supporting runtime method modification
/// - **Hot-reload systems**: Runtime environments enabling dynamic method updates
/// - **Debugging support**: Debuggers requiring method interception capabilities
/// - **Incremental compilation**: Build systems performing partial assembly updates
/// - **Method versioning**: Systems supporting method replacement without reference updates
///
/// # Stream Format Relationship
/// The `MethodPtr` table is associated with uncompressed metadata streams:
/// - **#~ streams**: Compressed metadata typically uses direct `MethodDef` references
/// - **#- streams**: Uncompressed metadata may include `MethodPtr` for indirection
/// - **Optimization**: Direct references when indirection is unnecessary
/// - **Flexibility**: Indirection enables complex method organization patterns
#[derive(Clone, Debug)]
pub struct MethodPtrRaw {
    /// Row identifier within the `MethodPtr` table.
    ///
    /// Unique identifier for this method pointer entry, used for internal
    /// table management and logical method token generation.
    pub rid: u32,

    /// Metadata token for this `MethodPtr` entry (`TableId` 0x05).
    ///
    /// Computed as `0x05000000 | rid` to create the logical method token
    /// that serves as a stable reference during method table reorganization.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// 1-based index into the `MethodDef` table.
    ///
    /// References the actual method definition that this pointer entry represents.
    /// This physical reference can be updated during method table reorganization
    /// while maintaining stable logical token references.
    pub method: u32,
}

impl MethodPtrRaw {
    /// Converts a `MethodPtrRaw` entry into a `MethodPtr` with resolved indirection mapping.
    ///
    /// This method performs a straightforward conversion from raw to owned structure,
    /// as `MethodPtr` entries contain only simple index references that don't require
    /// complex resolution. The resulting owned structure provides direct access
    /// to indirection mapping information.
    ///
    /// # Returns
    /// * `Ok(MethodPtrRc)` - Successfully converted method pointer with mapping information
    /// * `Err(_)` - Reserved for future error conditions (currently infallible)
    ///
    /// # Errors
    ///
    /// This function is infallible and always returns `Ok(())`. Reserved for future error conditions.
    pub fn to_owned(&self) -> Result<MethodPtrRc> {
        Ok(Arc::new(MethodPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            method: self.method,
        }))
    }

    /// Applies a `MethodPtrRaw` entry to update related metadata structures.
    ///
    /// `MethodPtr` entries provide indirection mappings but don't directly modify other
    /// metadata structures during the dual variant resolution phase. The indirection
    /// logic is handled at the table resolution level where logical tokens are
    /// translated to physical method references.
    ///
    /// # Design Rationale
    /// Method pointer entries are structural metadata that define mapping relationships
    /// rather than active definitions that need to update type systems or establish
    /// cross-table relationships like other metadata tables.
    ///
    /// # Returns
    /// * `Ok(())` - Always succeeds as `MethodPtr` entries don't modify other tables
    /// * `Err(_)` - Reserved for future error conditions (currently infallible)
    ///
    /// # Errors
    ///
    /// This function is infallible and always returns `Ok(())`. Reserved for future error conditions.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for MethodPtrRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* method */ sizes.table_index_bytes(TableId::MethodDef)
        )
    }

    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodPtrRaw {
            rid,
            token: Token::new(0x0500_0000 + rid),
            offset: *offset,
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
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
            0x01, 0x01, // method (index into MethodDef table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x05000001);
            assert_eq!(row.method, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // method (index into MethodDef table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x05000001);
            assert_eq!(row.method, 0x01010101);
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
