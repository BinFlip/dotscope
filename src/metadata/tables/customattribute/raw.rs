//! Raw CustomAttribute table representation.
//!
//! This module provides the [`crate::metadata::tables::customattribute::raw::CustomAttributeRaw`] struct
//! for low-level access to CustomAttribute metadata table data with unresolved coded indexes and blob references.
//! This represents the binary format of custom attribute records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # CustomAttribute Table Format
//!
//! The CustomAttribute table (0x0C) contains rows with these fields:
//! - **Parent** (2/4 bytes): HasCustomAttribute coded index to the target metadata element
//! - **Type** (2/4 bytes): CustomAttributeType coded index to the constructor method
//! - **Value** (2/4 bytes): Blob heap index for the serialized attribute arguments
//!
//! # Reference
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - CustomAttribute table specification
//! - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding

use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        customattributes::{parse_custom_attribute_blob, CustomAttributeValue},
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, CustomAttribute, CustomAttributeRc, MemberRefSignature,
            RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw CustomAttribute table row with unresolved coded indexes and blob references
///
/// Represents the binary format of a CustomAttribute metadata table entry (table ID 0x0C) as stored
/// in the metadata tables stream. All coded indexes and blob references are stored as raw values
/// that must be resolved using the appropriate context and heaps to access the actual data.
///
/// The CustomAttribute table associates custom attributes with metadata elements throughout the
/// assembly, providing a mechanism for storing declarative information about types, methods,
/// fields, and other metadata entities.
///
/// # Reference
/// - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - CustomAttribute table specification
/// - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding
pub struct CustomAttributeRaw {
    /// Row identifier within the CustomAttribute metadata table
    ///
    /// The 1-based index of this custom attribute row within the table.
    /// Used to generate the metadata token and for table iteration.
    pub rid: u32,

    /// Metadata token for this custom attribute row
    ///
    /// Combines the table identifier (0x0C for CustomAttribute) with the row ID to create
    /// a unique token. Format: `0x0C000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw custom attribute data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// HasCustomAttribute coded index to the target metadata element (unresolved)
    ///
    /// Identifies the metadata element to which this custom attribute is applied.
    /// This can reference types, methods, fields, assemblies, modules, parameters,
    /// and many other metadata entities. Must be resolved using coded index lookup.
    pub parent: CodedIndex,

    /// CustomAttributeType coded index to the constructor method (unresolved)
    ///
    /// References the constructor method (MethodDef or MemberRef) used to instantiate
    /// this custom attribute. The constructor's signature determines how to interpret
    /// the attribute's value blob. Must be resolved using coded index lookup.
    pub constructor: CodedIndex,

    /// Blob heap index for the serialized attribute arguments (unresolved)
    ///
    /// Index into the blob heap containing the custom attribute's serialized value,
    /// including fixed constructor arguments and named field/property values.
    /// A value of 0 indicates an empty attribute with no arguments.
    pub value: u32,
}

impl CustomAttributeRaw {
    /// Convert a raw CustomAttribute to an owned CustomAttribute with resolved indexes and parsed value data
    ///
    /// This method transforms the raw table entry into a fully usable custom attribute by:
    /// 1. Resolving the parent and constructor coded indexes to concrete type references
    /// 2. Validating that the constructor is indeed a constructor method (.ctor or .cctor)
    /// 3. Parsing the binary attribute blob using the constructor's parameter signature
    /// 4. Creating an owned CustomAttribute with all resolved data
    ///
    /// The method performs comprehensive validation to ensure metadata integrity, including
    /// constructor name validation and type checking to prevent malformed custom attributes.
    ///
    /// # Arguments
    ///
    /// * `get_ref` - A closure that resolves coded indexes to [`CilTypeReference`] objects.
    ///   This function should handle all coded index types used by custom attributes.
    /// * `blob` - The blob heap containing the serialized custom attribute value data
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Coded index resolution fails for parent or constructor references
    /// - The constructor reference is not a MethodDef or MemberRef
    /// - The constructor is not actually a constructor method (.ctor or .cctor)
    /// - The constructor name is empty (indicating malformed metadata)
    /// - Binary blob parsing fails due to corrupted or invalid data
    /// - Constructor method references become invalid during processing
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<CustomAttributeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let constructor_ref = get_ref(&self.constructor);
        match &constructor_ref {
            CilTypeReference::MethodDef(method_ref) => {
                if let Some(constructor) = method_ref.upgrade() {
                    if !constructor.is_constructor() {
                        return Err(malformed_error!(
                            "CustomAttribute constructor must be a .ctor or .cctor method, found '{}' (token: {})",
                            constructor.name,
                            self.token.value()
                        ));
                    }

                    if constructor.name.is_empty() {
                        return Err(malformed_error!(
                            "Constructor name cannot be empty for CustomAttribute token {}",
                            self.token.value()
                        ));
                    }
                } else {
                    return Err(malformed_error!(
                        "CustomAttribute constructor method reference is no longer valid (token: {})",
                        self.token.value()
                    ));
                }
            }
            CilTypeReference::MemberRef(member_ref) => {
                if !member_ref.is_constructor() {
                    return Err(malformed_error!(
                        "CustomAttribute constructor must be a .ctor or .cctor method, found '{}' (token: {})",
                        member_ref.name,
                        self.token.value()
                    ));
                }

                if member_ref.name.is_empty() {
                    return Err(malformed_error!(
                        "Constructor name cannot be empty for CustomAttribute token {}",
                        self.token.value()
                    ));
                }
            }
            CilTypeReference::None => {
                return Err(malformed_error!(
                    "CustomAttribute constructor reference cannot be None (token: {})",
                    self.token.value()
                ));
            }
            _ => {
                return Err(malformed_error!(
                    "CustomAttribute constructor must be MethodDef or MemberRef (token: {})",
                    self.token.value()
                ));
            }
        }

        let value = if self.value == 0 {
            CustomAttributeValue {
                fixed_args: vec![],
                named_args: vec![],
            }
        } else {
            match &constructor_ref {
                CilTypeReference::MethodDef(method_ref) => match method_ref.upgrade() {
                    Some(constructor) => {
                        parse_custom_attribute_blob(blob, self.value, &constructor.params)?
                    }
                    None => CustomAttributeValue {
                        fixed_args: vec![],
                        named_args: vec![],
                    },
                },
                CilTypeReference::MemberRef(member_ref) => match &member_ref.signature {
                    MemberRefSignature::Method(_method_sig) => {
                        parse_custom_attribute_blob(blob, self.value, &member_ref.params)?
                    }
                    MemberRefSignature::Field(_) => CustomAttributeValue {
                        fixed_args: vec![],
                        named_args: vec![],
                    },
                },
                _ => CustomAttributeValue {
                    fixed_args: vec![],
                    named_args: vec![],
                },
            }
        };

        Ok(Arc::new(CustomAttribute {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent: get_ref(&self.parent),
            constructor: constructor_ref,
            value,
        }))
    }
}

impl<'a> RowDefinition<'a> for CustomAttributeRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */    sizes.coded_index_bytes(CodedIndexType::HasCustomAttribute) +
            /* type */     sizes.coded_index_bytes(CodedIndexType::CustomAttributeType) +
            /* value */     sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(CustomAttributeRaw {
            rid,
            token: Token::new(0x0C00_0000 + rid),
            offset: *offset,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasCustomAttribute)?,
            constructor: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::CustomAttributeType,
            )?,
            value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x02, 0x02, // parent
            0x03, 0x03, // type
            0x04, 0x04, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<CustomAttributeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: CustomAttributeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0C000001);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::TypeRef,
                    row: 16,
                    token: Token::new(16 | 0x01000000),
                }
            );
            assert_eq!(
                row.constructor,
                CodedIndex {
                    tag: TableId::MemberRef,
                    row: 96,
                    token: Token::new(96 | 0x0A000000),
                }
            );
            assert_eq!(row.value, 0x404);
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
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // type
            0x04, 0x04, 0x04, 0x04, // value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<CustomAttributeRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: CustomAttributeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0C000001);
            assert_eq!(
                row.parent,
                CodedIndex {
                    tag: TableId::TypeRef,
                    row: 0x101010,
                    token: Token::new(0x101010 | 0x01000000),
                }
            );
            assert_eq!(
                row.constructor,
                CodedIndex {
                    tag: TableId::MemberRef,
                    row: 0x606060,
                    token: Token::new(0x606060 | 0x0A000000),
                }
            );
            assert_eq!(row.value, 0x4040404);
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
