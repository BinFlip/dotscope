use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        method::MethodMap,
        signatures::{
            parse_field_signature, parse_method_signature, SignatureField, SignatureMethod,
        },
        streams::{
            Blob, CodedIndex, CodedIndexType, ModuleRefMap, RowDefinition, Strings, TableId,
            TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `MemberRef`
pub type MemberRefMap = SkipMap<Token, MemberRefRc>;
/// A vector that holds a list of `MemberRef`
pub type MemberRefList = Arc<boxcar::Vec<MemberRefRc>>;
/// A reference to a `MemberRef`
pub type MemberRefRc = Arc<MemberRef>;

/// Describes the signature of a `MemberRef`
pub enum MemberRefSignature {
    /// A `MethodSignature`
    Method(SignatureMethod),
    /// A `FieldSignature`
    Field(SignatureField),
}

/// The `MemberRef` table references members (fields or methods) of types defined in other modules. Similar to `MemberRefRaw` but
/// with resolved indexes and owned data
pub struct MemberRef {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parent type/module this reference belongs to
    pub declaredby: CilTypeReference,
    /// Member name
    pub name: String,
    /// The signature (could be method signature or field signature)
    pub signature: MemberRefSignature,
}

#[derive(Clone, Debug)]
/// The `MemberRef` table references members (fields or methods) of types defined in other modules. `TableId` = 0x0A
pub struct MemberRefRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `MethodDef`, `ModuleRef`, `TypeDef`, `TypeRef`, or `TypeSpec` tables; more precisely, a `MemberRefParent` (§II.24.2.6) coded index
    pub class: CodedIndex,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Blob heap
    pub signature: u32,
}

impl MemberRefRaw {
    /// Apply a `MemberRefRaw` - no-op for `MemberRef` as member references don't modify other table entries
    ///
    /// `MemberRef` entries represent references to members (fields, methods) defined in other types
    /// and don't require cross-table application during loading.
    ///
    /// # Errors
    /// This method currently returns Ok(()) as `MemberRef` entries don't require cross-table updates.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }

    /// Convert an `MemberRefRaw`, into a `MemberRef` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings'     - The #String heap
    /// * 'blob'        - The #Blob heap
    /// * 'types'       - All parsed `CilType` entries
    /// * 'modules'     - All parsed `ModuleRef` entries
    /// * 'methods'     - All parsed `MethodDef` entries
    ///
    /// # Errors
    /// Returns an error if the signature data is invalid, if the type cannot be resolved,
    /// or if the signature cannot be parsed correctly.
    pub fn to_owned(
        &self,
        strings: &Strings,
        blob: &Blob,
        types: &TypeRegistry,
        modules: &ModuleRefMap,
        methods: &MethodMap,
    ) -> Result<MemberRefRc> {
        let signature_data = blob.get(self.signature as usize)?;
        if signature_data.is_empty() {
            return Err(malformed_error!("Invalid signature data"));
        }

        Ok(Arc::new(MemberRef {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            declaredby: match self.class.tag {
                TableId::MethodDef => match methods.get(&self.class.token) {
                    Some(method) => CilTypeReference::MethodDef(method.value().clone().into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve methoddef class token - {}",
                            self.class.token.value()
                        ))
                    }
                },
                TableId::ModuleRef => match modules.get(&self.class.token) {
                    Some(module_ref) => CilTypeReference::ModuleRef(module_ref.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve moduleref class token - {}",
                            self.class.token.value()
                        ))
                    }
                },
                TableId::TypeDef => match types.get(&self.class.token) {
                    Some(cil_type) => CilTypeReference::TypeDef(cil_type.into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve typedef class token - {}",
                            self.class.token.value()
                        ))
                    }
                },
                TableId::TypeRef => match types.get(&self.class.token) {
                    Some(cil_type) => CilTypeReference::TypeRef(cil_type.into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve typeref class token - {}",
                            self.class.token.value()
                        ))
                    }
                },
                TableId::TypeSpec => match types.get(&self.class.token) {
                    Some(cil_type) => CilTypeReference::TypeSpec(cil_type.into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve typespec class token - {}",
                            self.class.token.value()
                        ))
                    }
                },
                _ => {
                    return Err(malformed_error!(
                        "Invalid class token - {}",
                        self.class.token.value()
                    ))
                }
            },
            name: strings.get(self.name as usize)?.to_string(),
            signature: if signature_data[0] == 0x6 {
                MemberRefSignature::Field(parse_field_signature(signature_data)?)
            } else {
                MemberRefSignature::Method(parse_method_signature(signature_data)?)
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for MemberRefRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */     sizes.coded_index_bytes(CodedIndexType::MemberRefParent) +
            /* name */      sizes.str_bytes() +
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MemberRefRaw {
            rid,
            token: Token::new(0x0A00_0000 + rid),
            offset: *offset,
            class: CodedIndex::read(data, offset, sizes, CodedIndexType::MemberRefParent)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // class
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MemberRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MemberRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0A000001);
            assert_eq!(
                row.class,
                CodedIndex {
                    tag: TableId::TypeRef,
                    row: 32,
                    token: Token::new(32 | 0x01000000),
                }
            );
            assert_eq!(row.name, 0x202);
            assert_eq!(row.signature, 0x303);
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
            0x01, 0x01, 0x01, 0x01, // class
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MemberRefRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: MemberRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0A000001);
            assert_eq!(
                row.class,
                CodedIndex {
                    tag: TableId::TypeRef,
                    row: 0x202020,
                    token: Token::new(0x202020 | 0x01000000),
                }
            );
            assert_eq!(row.name, 0x2020202);
            assert_eq!(row.signature, 0x3030303);
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
