use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        customattributes::{parse_custom_attribute_blob, CustomAttributeValue},
        streams::{
            Blob, CodedIndex, CodedIndexType, MemberRefSignature, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `CustomAttribute`
pub type CustomAttributeMap = SkipMap<Token, CustomAttributeRc>;
/// A vector that holds a list of `CustomAttribute`
pub type CustomAttributeList = Arc<boxcar::Vec<Arc<CustomAttributeRc>>>;
/// A reference to a `CustomAttribute`
pub type CustomAttributeRc = Arc<CustomAttribute>;

/// The `CustomAttribute` table associates attributes with elements in various metadata tables. Similar to `CustomAttributeRaw` but
/// with resolved indexes and owned data
pub struct CustomAttribute {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// Resolved parent object that has this custom attribute attached
    pub parent: CilTypeReference,
    /// Resolved constructor (`MethodDef` or `MemberRef`) for this custom attribute
    pub constructor: CilTypeReference,
    /// Parsed custom attribute value
    pub value: CustomAttributeValue,
}

impl CustomAttribute {
    /// Apply a `CustomAttribute` to attach it to its parent metadata element
    ///
    /// This method attaches the custom attribute value to its resolved parent object by adding it
    /// to the parent's custom attribute collection. The custom attribute value is stored as an
    /// `Arc<CustomAttributeValue>` for efficient memory usage and sharing.
    ///
    /// # Errors
    /// Returns an error if the parent type is not supported for custom attributes
    /// or if custom attribute storage is not implemented for the parent type.
    pub fn apply(&self) -> Result<()> {
        let attribute_value = Arc::new(self.value.clone());

        match &self.parent {
            CilTypeReference::TypeDef(entry)
            | CilTypeReference::TypeSpec(entry)
            | CilTypeReference::TypeRef(entry) => {
                if let Some(type_ref) = entry.upgrade() {
                    type_ref.custom_attributes.push(attribute_value);
                    Ok(())
                } else {
                    Err(malformed_error!("Type reference is no longer valid"))
                }
            }
            CilTypeReference::MethodDef(entry) => {
                if let Some(method) = entry.upgrade() {
                    method.custom_attributes.push(attribute_value);
                    Ok(())
                } else {
                    Err(malformed_error!("Method reference is no longer valid"))
                }
            }
            CilTypeReference::Field(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Param(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Property(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Event(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Assembly(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::Module(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::InterfaceImpl(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::MemberRef(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::DeclSecurity(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::StandAloneSig(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::ModuleRef(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::AssemblyRef(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::File(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::ExportedType(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::GenericParam(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::GenericParamConstraint(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            CilTypeReference::MethodSpec(entry) => {
                entry.custom_attributes.push(attribute_value);
                Ok(())
            }
            //CilTypeReference::ManifestResource(entry) => {},
            CilTypeReference::None => {
                // For now, just return Ok() for unsupported parent types
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug)]
/// The `CustomAttribute` table associates attributes with elements in various metadata tables, `TableId` = 0x0C
pub struct CustomAttributeRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into a metadata table that has an associated `HasCustomAttribute` (§II.24.2.6) coded index
    pub parent: CodedIndex,
    /// an index into the `MethodDef` or `MemberRef` table; more precisely, a `CustomAttributeType` (§II.24.2.6) coded index
    pub constructor: CodedIndex,
    /// an index into the Blob heap
    pub value: u32,
}

impl CustomAttributeRaw {
    /// Convert a `CustomAttributeRaw` into a `CustomAttribute` which has indexes resolved and owns the referenced data
    ///
    /// This method uses the unified coded index resolution system from `LoaderContext`,
    /// providing proper resolution of parent and constructor references to concrete objects.
    /// In Phase 4, it extracts constructor parameter information from the resolved Method reference to enable
    /// type-aware blob parsing using the already-parsed parameter types.
    ///
    /// ## Arguments
    /// * `get_ref` - A closure that resolves coded indices to `CilTypeReference`
    /// * `blob` - The blob heap for parsing custom attribute value data
    ///
    /// # Errors
    /// Returns an error if coded index resolution fails for parent or constructor references,
    /// or if blob parsing fails.
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
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

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
