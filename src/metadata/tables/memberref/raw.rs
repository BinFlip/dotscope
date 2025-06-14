use std::sync::{atomic::AtomicBool, Arc, OnceLock};

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::{
            parse_field_signature, parse_method_signature, SignatureMethod, TypeSignature,
        },
        streams::{Blob, Strings},
        tables::{
            CodedIndex, CodedIndexType, MemberRef, MemberRefRc, MemberRefSignature, Param, ParamRc,
            RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

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
    /// Create Param structures from a method signature
    ///
    /// This creates parameter objects similar to how `MethodDef` entries work,
    /// enabling unified parameter handling across `MethodDef` and `MemberRef` constructors.
    ///
    /// # Arguments
    /// * `method_sig` - The parsed method signature
    /// * `strings` - The strings heap for parameter names (will be None for `MemberRef` params)
    ///
    /// # Errors
    /// Returns an error if parameter creation fails
    fn create_params_from_signature(
        method_sig: &SignatureMethod,
        _strings: &Strings,
    ) -> Arc<boxcar::Vec<ParamRc>> {
        let params = Arc::new(boxcar::Vec::with_capacity(method_sig.params.len() + 1));

        // Create return parameter (sequence 0)
        let return_param = Arc::new(Param {
            rid: 0,               // No actual row ID for MemberRef params
            token: Token::new(0), // Placeholder token
            offset: 0,
            flags: 0,
            sequence: 0, // Return parameter
            name: None,  // MemberRef parameters don't have names from metadata
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(method_sig.return_type.by_ref),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });
        params.push(return_param);

        // Create parameters for each method parameter
        for (index, param_sig) in method_sig.params.iter().enumerate() {
            let param = Arc::new(Param {
                rid: 0,               // No actual row ID for MemberRef params
                token: Token::new(0), // Placeholder token
                offset: 0,
                flags: 0,
                #[allow(clippy::cast_possible_truncation)]
                sequence: (index + 1) as u32, // Parameter sequence starts at 1
                name: None, // MemberRef parameters don't have names from metadata
                default: OnceLock::new(),
                marshal: OnceLock::new(),
                modifiers: Arc::new(boxcar::Vec::new()),
                base: OnceLock::new(),
                is_by_ref: AtomicBool::new(param_sig.by_ref),
                custom_attributes: Arc::new(boxcar::Vec::new()),
            });
            params.push(param);
        }

        params
    }

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
    /// * `get_ref`     - Closure for resolving coded indexes to type references
    ///
    /// # Errors
    /// Returns an error if the signature data is invalid, if the type cannot be resolved,
    /// or if the signature cannot be parsed correctly.
    pub fn to_owned<F>(
        &self,
        strings: &Strings,
        blob: &Blob,
        types: &Arc<TypeRegistry>,
        get_ref: F,
    ) -> Result<MemberRefRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let signature_data = blob.get(self.signature as usize)?;
        if signature_data.is_empty() {
            return Err(malformed_error!("Invalid signature data"));
        }

        let (signature, params) = if signature_data[0] == 0x6 {
            (
                MemberRefSignature::Field(parse_field_signature(signature_data)?),
                Arc::new(boxcar::Vec::new()),
            )
        } else {
            let method_sig = parse_method_signature(signature_data)?;
            let params = Self::create_params_from_signature(&method_sig, strings);

            let method_param_count = Some(method_sig.params.len());
            for (_, param) in params.iter() {
                if param.sequence == 0 {
                    // Return parameter
                    param.apply_signature(
                        &method_sig.return_type,
                        types.clone(),
                        method_param_count,
                    )?;
                } else {
                    // Regular parameter
                    let index = (param.sequence - 1) as usize;
                    if let Some(param_signature) = method_sig.params.get(index) {
                        param.apply_signature(
                            param_signature,
                            types.clone(),
                            method_param_count,
                        )?;
                    }
                }
            }

            (MemberRefSignature::Method(method_sig), params)
        };

        let declaredby = get_ref(&self.class);
        if matches!(declaredby, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve class token - {}",
                self.class.token.value()
            ));
        }

        match (&signature, &declaredby) {
            (
                MemberRefSignature::Method(method_sig),
                CilTypeReference::TypeDef(_parent_type) | CilTypeReference::TypeRef(_parent_type),
            ) => {
                if strings.get(self.name as usize)?.is_empty() {
                    return Err(malformed_error!(
                        "Method name cannot be empty for MemberRef token {}",
                        self.token.value()
                    ));
                }

                if method_sig.params.len() > 255 {
                    return Err(malformed_error!(
                        "Method signature has too many parameters ({}) for MemberRef token {}",
                        method_sig.params.len(),
                        self.token.value()
                    ));
                }
            }
            (
                MemberRefSignature::Field(field_sig),
                CilTypeReference::TypeDef(_parent_type) | CilTypeReference::TypeRef(_parent_type),
            ) => {
                if strings.get(self.name as usize)?.is_empty() {
                    return Err(malformed_error!(
                        "Field name cannot be empty for MemberRef token {}",
                        self.token.value()
                    ));
                }

                if matches!(field_sig.base, TypeSignature::Unknown) {
                    return Err(malformed_error!(
                        "Field signature has unknown type for MemberRef token {}",
                        self.token.value()
                    ));
                }
            }
            // For module references and other parent types, we allow more flexibility
            // as these might reference external or special members
            _ => {}
        }

        let member_ref = Arc::new(MemberRef {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            declaredby,
            name: strings.get(self.name as usize)?.to_string(),
            signature,
            params,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        Ok(member_ref)
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
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

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
