//! Raw Constant table representation.
//!
//! This module provides the [`crate::metadata::tables::constant::raw::ConstantRaw`] struct
//! for low-level access to Constant metadata table data with unresolved table indexes.
//! This represents the binary format of Constant records as they appear in the metadata
//! tables stream, requiring resolution to create usable data structures.
//!
//! # Constant Table Format
//!
//! The Constant table (0x0B) contains zero or more rows with these fields:
//! - **Type** (1 byte): Element type of the constant (ELEMENT_TYPE_* enumeration)
//! - **Padding** (1 byte): Reserved padding byte (must be zero)
//! - **Parent** (2/4 bytes): HasConstant coded index into Field, Property, or Param tables  
//! - **Value** (2/4 bytes): Blob heap index containing the constant's binary data
//!
//! # Reference
//! - [ECMA-335 II.22.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Constant table specification

use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Blob,
        tables::{CodedIndex, CodedIndexType, ConstantRc, RowDefinition, TableInfoRef},
        token::Token,
        typesystem::{CilPrimitive, CilTypeReference},
    },
    Result,
};

use super::owned::Constant;

/// Raw representation of a Constant metadata table entry
///
/// Represents a constant value from the Constant table (0x0B) with unresolved references
/// to other metadata tables and heaps. This structure contains the binary layout as it
/// appears in the metadata stream, requiring resolution before practical use.
///
/// # Table Structure
///
/// Each Constant row contains:
/// - **Element type**: Primitive type identifier (ELEMENT_TYPE_*)
/// - **Parent relationship**: Coded index to Field, Property, or Param table
/// - **Value data**: Binary representation stored in the blob heap
/// - **Type validation**: Ensures constant types match their containers
#[derive(Clone, Debug)]
///   The Constant table stores constant values for fields, parameters, and properties. `TableId` = 0x0B
pub struct ConstantRaw {
    /// Row identifier in the Constant metadata table
    ///
    /// This is the 1-based row index where this constant was defined in the metadata table.
    pub rid: u32,

    /// Metadata token uniquely identifying this constant
    ///
    /// The token provides a unique identifier for this constant entry within the assembly,
    /// constructed from the table ID (0x0B) and row number.
    pub token: Token,

    /// File offset where this constant's data begins
    ///
    /// The byte offset in the metadata file where this constant's binary representation starts.
    pub offset: usize,

    /// Element type of the constant value
    ///
    /// Specifies the primitive type of the constant using ELEMENT_TYPE_* enumeration values
    /// (see ECMA-335 II.23.1.16). This determines how the blob value data should be interpreted.
    /// Common values include ELEMENT_TYPE_I4 for integers, ELEMENT_TYPE_STRING for strings, etc.
    /// For null reference constants, this is ELEMENT_TYPE_CLASS with a 4-byte zero value.
    pub base: u8,

    /// HasConstant coded index to the parent metadata element
    ///
    /// Points to the field, property, or parameter that owns this constant. This is a coded
    /// index that must be decoded to determine the target table and row. The coding scheme
    /// uses the lower 2 bits to identify the table type (Field=0, Param=1, Property=2).
    pub parent: CodedIndex,

    /// Blob heap index containing the constant value data
    ///
    /// Index into the blob heap where the binary representation of the constant value is stored.
    /// The interpretation of this blob data depends on the element type specified in `base`.
    pub value: u32,
}

impl ConstantRaw {
    /// Apply this constant value directly to its parent metadata element
    ///
    /// Associates this constant with its parent field, property, or parameter by resolving
    /// the coded index and extracting the constant value from the blob heap. This method
    /// performs immediate type validation and default value assignment.
    ///
    /// ## Arguments
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * `blob` - The blob heap containing constant value data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the constant is successfully applied, or [`crate::Error`] if:
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    /// - The constant type is incompatible with the parent type
    /// - A default value is already set for the parent entity
    ///
    /// # Errors
    ///
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    /// - The default value is already set for the parent entity
    pub fn apply<F>(&self, get_ref: F, blob: &Blob) -> Result<()>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let parent = get_ref(&self.parent);
        let default = CilPrimitive::from_blob(self.base, blob.get(self.value as usize)?)?;

        match &parent {
            CilTypeReference::Field(field) => {
                if !field.signature.base.accepts_constant(&default) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with field type: {:?} (token: {})",
                        default.kind,
                        field.signature.base,
                        self.token.value()
                    ));
                }

                field
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for field"))
            }
            CilTypeReference::Param(param) => {
                if let Some(param_type) = param.base.get() {
                    if let Some(param_type_strong) = param_type.upgrade() {
                        if !param_type_strong.accepts_constant(&default) {
                            return Err(malformed_error!(
                                "Constant type {:?} is not compatible with parameter type {} (token: {})",
                                default.kind,
                                param_type_strong.fullname(),
                                self.token.value()
                            ));
                        }
                    }
                }

                param
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for param"))
            }
            CilTypeReference::Property(property) => {
                if !property.signature.base.accepts_constant(&default) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with property type: {:?} (token: {})",
                        default.kind,
                        property.signature.base,
                        self.token.value()
                    ));
                }

                property
                    .default
                    .set(default)
                    .map_err(|_| malformed_error!("Default value already set for property"))
            }
            _ => Err(malformed_error!(
                "Invalid parent type for constant - {}",
                self.parent.token.value()
            )),
        }
    }

    /// Convert this raw constant to an owned constant with resolved references
    ///
    /// Transforms this raw constant table entry into a fully resolved [`Constant`] instance
    /// by resolving coded indices and extracting constant value data from the blob heap.
    /// The resulting owned constant contains all necessary data for direct use.
    ///
    /// ## Arguments
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * `blob` - The blob heap containing constant value data
    ///
    /// # Returns
    ///
    /// Returns a reference-counted [`ConstantRc`] containing the owned constant data,
    /// or [`crate::Error`] if the conversion fails.
    ///
    /// # Errors
    ///
    /// - The blob heap lookup fails for the constant value
    /// - The primitive value cannot be constructed from the blob data
    /// - The parent reference cannot be resolved to a valid type reference
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<ConstantRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let parent = get_ref(&self.parent);
        if matches!(parent, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent.token.value()
            ));
        }

        Ok(Arc::new(Constant {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            c_type: self.base,
            parent,
            value: Arc::new(CilPrimitive::from_blob(
                self.base,
                blob.get(self.value as usize)?,
            )?),
        }))
    }
}

impl<'a> RowDefinition<'a> for ConstantRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* c_type */    1 +
            /* padding */   1 +
            /* parent */    sizes.coded_index_bytes(CodedIndexType::HasConstant) +
            /* value */     sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let c_type = read_le_at::<u8>(data, offset)?;
        *offset += 1; // Padding

        Ok(ConstantRaw {
            rid,
            token: Token::new(0x0B00_0000 + rid),
            offset: offset_org,
            base: c_type,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasConstant)?,
            value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;
    use crate::metadata::token::Token;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, // type
            0x00, // padding
            0x02, 0x02, // parent
            0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x01);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Property,
                    row: 128,
                    token: Token::new(128 | 0x17000000),
                }
            );
            assert_eq!(row.value, 0x303);
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
            0x01, // type
            0x00, // padding
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ConstantRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: ConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0B000001);
            assert_eq!(row.base, 0x1);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::Property,
                    row: 0x808080,
                    token: Token::new(0x808080 | 0x17000000),
                }
            );
            assert_eq!(row.value, 0x3030303);
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
