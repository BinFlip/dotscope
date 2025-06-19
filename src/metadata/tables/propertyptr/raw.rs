//! # `PropertyPtr` Raw Implementation
//!
//! This module provides the raw variant of `PropertyPtr` table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{PropertyPtr, PropertyPtrRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

/// Raw representation of a `PropertyPtr` table entry from the .NET metadata.
///
/// The `PropertyPtr` table provides indirection for property table access in optimized
/// metadata layouts, enabling property table compression and efficient property access
/// patterns. Each entry contains a single property index that maps logical property
/// positions to physical property table locations.
///
/// ## Metadata Table Information
/// - **Table ID**: `0x16` (22 decimal)
/// - **Token Type**: `0x16000000` + RID
/// - **Purpose**: Provides property table indirection for optimization
///
/// ## Structure Layout
/// The table entry contains a single field that references the actual property
/// entry in the Property table. This indirection enables:
/// - **Property Reordering**: Physical property order can differ from logical order
/// - **Table Compression**: Enables property table optimization strategies
/// - **Access Efficiency**: Supports efficient property lookup patterns
///
/// ## Optimization Context
/// `PropertyPtr` tables are present when the assembly uses optimized metadata layouts:
/// - **Uncompressed Streams**: Present in assemblies using `#-` stream format
/// - **Property Compression**: When property table ordering has been optimized
/// - **Runtime Efficiency**: When property access patterns require indirection
///
/// ## See Also
/// - [`crate::metadata::tables::PropertyPtr`] - Resolved owned variant
/// - [ECMA-335 §II.22.38](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) - `PropertyPtr` table specification
#[derive(Clone, Debug)]
pub struct PropertyPtrRaw {
    /// The 1-based row identifier within the `PropertyPtr` table.
    pub rid: u32,

    /// The metadata token for this `PropertyPtr` entry.
    pub token: Token,

    /// The byte offset of this entry within the metadata stream.
    pub offset: usize,

    /// The 1-based index into the Property table.
    ///
    /// This field provides the actual property index that this property pointer
    /// entry maps to. When property indirection is active, this value should be
    /// used instead of direct Property table indexing to access the correct property.
    pub property: u32,
}

impl PropertyPtrRaw {
    /// Converts this raw `PropertyPtr` entry into an owned representation.
    ///
    /// Creates a fully-owned [`PropertyPtr`] instance from this raw entry,
    /// transferring all field values and enabling high-level property
    /// indirection operations.
    ///
    /// ## Returns
    ///
    /// * `Ok(PropertyPtrRc)` - Successfully converted owned entry
    /// * `Err(_)` - Conversion failed (currently no failure cases)
    ///
    /// # Errors
    ///
    /// This function currently does not fail, but the `Result` type is used for
    /// future-proofing and consistency with other conversion methods.
    pub fn to_owned(&self) -> Result<PropertyPtrRc> {
        Ok(Arc::new(PropertyPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            property: self.property,
        }))
    }

    /// Applies this `PropertyPtr` entry to update related metadata structures.
    ///
    /// `PropertyPtr` entries provide indirection mappings but do not directly
    /// modify other metadata structures during the loading process. The
    /// indirection logic is handled at the table resolution and access level.
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - Entry application completed (always succeeds)
    ///
    /// ## Note
    ///
    /// This method exists for consistency with other table types but performs
    /// no operations as `PropertyPtr` entries do not modify external state.
    /// # Errors
    ///
    /// This method always returns `Ok(())` and does not produce errors, but the `Result` type is used for consistency.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for PropertyPtrRaw {
    /// Calculates the byte size of a `PropertyPtr` table row.
    ///
    /// The row size depends on the Property table size:
    /// - 2 bytes if Property table has ≤ 65535 rows
    /// - 4 bytes if Property table has > 65535 rows
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information for index size calculation
    ///
    /// ## Returns
    ///
    /// The size in bytes required for a single `PropertyPtr` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* property */ sizes.table_index_bytes(TableId::Property)
        )
    }

    /// Reads a `PropertyPtr` table row from the metadata stream.
    ///
    /// Parses a single `PropertyPtr` entry from the raw metadata bytes,
    /// extracting the property index and constructing the complete
    /// table entry with metadata token and offset information.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw metadata bytes containing the table
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for proper index parsing
    ///
    /// ## Returns
    ///
    /// * `Ok(PropertyPtrRaw)` - Successfully parsed table entry
    /// * `Err(_)` - Parsing failed due to insufficient data or corruption
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(PropertyPtrRaw {
            rid,
            token: Token::new(0x1600_0000 + rid),
            offset: *offset,
            property: read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?,
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
            0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x01010101);
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
