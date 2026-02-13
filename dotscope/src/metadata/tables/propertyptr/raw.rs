//! # `PropertyPtr` Raw Implementation
//!
//! This module provides the raw variant of `PropertyPtr` table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{PropertyPtr, PropertyPtrRc, TableId, TableInfoRef, TableRow},
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

impl TableRow for PropertyPtrRaw {
    /// Calculate the binary size of one `PropertyPtr` table row
    ///
    /// Computes the total byte size required for one `PropertyPtr` row based on the
    /// current metadata table sizes. The row size depends on whether the Property
    /// table uses 2-byte or 4-byte indices.
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for calculating variable-width fields
    ///
    /// # Returns
    /// Total byte size of one `PropertyPtr` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* property */ sizes.table_index_bytes(TableId::Property)
        )
    }
}
