//! # Property Raw Implementation
//!
//! This module provides the raw variant of Property table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        signatures::parse_property_signature,
        streams::{Blob, Strings},
        tables::{Property, PropertyRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a Property table entry with unresolved indexes.
///
/// This structure represents the unprocessed entry from the Property metadata table
/// (ID 0x17), which defines properties exposed by types in .NET assemblies. It contains
/// raw index values that require resolution to actual metadata objects.
///
/// ## Purpose
///
/// The Property table provides the foundation for .NET property system:
/// - **Property Definition**: Defines property names, types, and characteristics
/// - **Type Integration**: Associates properties with their declaring types
/// - **Method Binding**: Links properties to getter/setter methods via MethodSemantics
/// - **Reflection Foundation**: Enables property-based reflection and metadata queries
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved string heap indexes requiring name lookup
/// - Unresolved blob heap indexes requiring signature parsing
/// - Minimal memory footprint for storage during parsing
/// - Direct representation of on-disk table structure
///
/// ## Property Attributes
///
/// Properties can have various attributes that control their behavior:
/// - **SpecialName**: Property has special naming conventions (0x0200)
/// - **RTSpecialName**: Runtime should verify name encoding (0x0400)
/// - **HasDefault**: Property has a default value defined (0x1000)
///
/// ## References
///
/// - ECMA-335, Partition II, §22.34 - Property table specification
/// - [`crate::metadata::tables::Property`] - Owned variant for comparison
/// - [`crate::metadata::tables::PropertyMap`] - Property to type mapping
/// - [`crate::metadata::signatures::SignatureProperty`] - Property signature details
pub struct PropertyRaw {
    /// Row identifier within the Property table (1-based indexing).
    ///
    /// This field provides the logical position of this entry within the Property table,
    /// following the standard 1-based indexing convention used throughout .NET metadata.
    pub rid: u32,

    /// Metadata token uniquely identifying this Property entry.
    ///
    /// The token combines the table identifier (Property = 0x17) with the row ID,
    /// providing a unique reference for this property across the entire metadata system.
    pub token: Token,

    /// Byte offset of this entry within the metadata stream.
    ///
    /// This offset indicates the exact position of this Property entry within the
    /// metadata stream, enabling direct access to the raw table data and supporting
    /// metadata analysis and debugging operations.
    pub offset: usize,

    /// Property attribute flags defining characteristics and behavior.
    ///
    /// A 2-byte bitmask of PropertyAttributes (ECMA-335 §II.23.1.14) that controls
    /// various aspects of the property including special naming, default values,
    /// and runtime behavior. See [`super::PropertyAttributes`] for flag definitions.
    pub flags: u32,

    /// Index into the string heap for the property name.
    ///
    /// This field contains the heap index that must be resolved to obtain the
    /// actual property name string. The name provides the identifier used for
    /// property access and reflection operations.
    pub name: u32,

    /// Index into the blob heap for the property signature.
    ///
    /// This field contains the heap index that must be resolved and parsed to
    /// obtain the complete property signature, including property type, parameter
    /// types for indexers, and calling conventions.
    pub signature: u32,
}

impl PropertyRaw {
    /// Converts this raw Property entry to its owned representation.
    ///
    /// This method transforms the raw table entry into a fully owned Property instance
    /// with resolved names and parsed signatures. The conversion involves string heap
    /// lookup for the property name and blob heap parsing for the property signature.
    ///
    /// ## Arguments
    ///
    /// * `strings` - The string heap for name resolution
    /// * `blob` - The blob heap for signature parsing
    ///
    /// ## Returns
    ///
    /// * `Ok(PropertyRc)` - Successfully converted to owned representation
    /// * `Err(Error)` - String resolution or signature parsing error
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Invalid string or blob heap index
    /// * [`crate::error::Error::Malformed`] - Malformed property signature
    pub fn to_owned(&self, strings: &Strings, blob: &Blob) -> Result<PropertyRc> {
        Ok(Arc::new(Property {
            token: self.token,
            flags: self.flags,
            name: strings.get(self.name as usize)?.to_string(),
            signature: parse_property_signature(blob.get(self.signature as usize)?)?,
            default: OnceLock::new(),
            fn_setter: OnceLock::new(),
            fn_getter: OnceLock::new(),
            fn_other: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Applies this Property entry to the metadata loading process.
    ///
    /// Property entries define properties that types can expose but do not directly
    /// modify other metadata structures during the loading process. Property method
    /// associations (getter, setter, other) are resolved separately through the
    /// MethodSemantics table during higher-level metadata resolution.
    ///
    /// This method is provided for consistency with the table loading framework
    /// but performs no operations for Property entries.
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - Always succeeds as no processing is required
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for PropertyRaw {
    /// Calculates the byte size of a single Property table row.
    ///
    /// The size depends on the metadata heap size configuration:
    /// - **flags**: 2 bytes (PropertyAttributes bitmask)
    /// - **name**: String heap index size (2 or 4 bytes)
    /// - **signature**: Blob heap index size (2 or 4 bytes)
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size configuration information
    ///
    /// ## Returns
    ///
    /// * `u32` - Total row size in bytes (6-10 bytes typically)
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */          2 +
            /* name */           sizes.str_bytes() +
            /* type_signature */ sizes.blob_bytes()
        )
    }

    /// Reads a single Property table row from metadata bytes.
    ///
    /// This method parses a Property entry from the metadata stream, extracting
    /// the property flags, name index, and signature index to construct the
    /// complete row structure with metadata context.
    ///
    /// ## Arguments
    ///
    /// * `data` - The metadata bytes to read from
    /// * `offset` - Current position in the data (updated after reading)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size configuration for index resolution
    ///
    /// ## Returns
    ///
    /// * `Ok(PropertyRaw)` - Successfully parsed Property entry
    /// * `Err(Error)` - Failed to read or parse the entry
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(PropertyRaw {
            rid,
            token: Token::new(0x1700_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.signature, 0x0303);
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
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.signature, 0x03030303);
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
