use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::parse_method_spec_signature,
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, MethodSpec, MethodSpecRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry, TypeResolver},
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `MethodSpec` table represents instantiations of generic methods. `TableId` = 0x2B
pub struct MethodSpecRaw {
    /// `RowID`
    pub rid: u32,
    /// `Token`
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `MethodDefOrRef` coding index
    pub method: CodedIndex,
    /// an index into the Blob heap
    pub instantiation: u32,
}

impl MethodSpecRaw {
    /// Convert an `MethodSpecRaw` into a `MethodSpec` and apply it to the target method
    ///
    /// This method combines the functionality of resolving indexes, parsing the signature,
    /// resolving generic arguments, and applying them to the target method all in one step.
    ///
    /// # Errors
    ///
    /// Returns an error if the method token is invalid, if the referenced method or member reference
    /// cannot be resolved, or if there are issues parsing the method specification signature.
    ///
    /// ## Arguments
    /// * `get_ref`     - Function to resolve coded index to type reference
    /// * 'blob'        - The #Blob heap
    /// * `types`       - The `TypeRegistry` for resolving generic argument types
    /// * 'methods'     - All parsed `MethodDef` entries  
    /// * 'memberrefs'  - All parsed `MemberRef` entries
    pub fn to_owned_and_apply<F>(
        &self,
        get_ref: F,
        blob: &Blob,
        types: &Arc<TypeRegistry>,
    ) -> Result<MethodSpecRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let method = get_ref(&self.method);
        if matches!(method, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve method token - {}",
                self.method.token.value()
            ));
        }

        let instantiation = parse_method_spec_signature(blob.get(self.instantiation as usize)?)?;
        let generic_args = Arc::new(boxcar::Vec::with_capacity(instantiation.generic_args.len()));

        let mut resolver = TypeResolver::new(types.clone());
        for type_sig in &instantiation.generic_args {
            let resolved_type = resolver.resolve(type_sig)?;
            generic_args.push(resolved_type.into());
        }

        let method_spec = Arc::new(MethodSpec {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            method: method.clone(),
            instantiation,
            custom_attributes: Arc::new(boxcar::Vec::new()),
            generic_args,
        });

        match &method {
            CilTypeReference::MethodDef(method_ref) => {
                if let Some(method_def) = method_ref.upgrade() {
                    method_def.generic_args.push(method_spec.clone());
                } else {
                    return Err(malformed_error!(
                        "Failed to resolve method - {}",
                        self.method.token.value()
                    ));
                }
            }
            CilTypeReference::MemberRef(member_ref) => {
                match &member_ref.declaredby {
                    CilTypeReference::TypeRef(ciltype)
                    | CilTypeReference::TypeDef(ciltype)
                    | CilTypeReference::TypeSpec(ciltype) => {
                        if let Some(args) = ciltype.generic_args() {
                            args.push(method_spec.clone());
                        }
                    }
                    CilTypeReference::MethodDef(target_method) => {
                        if let Some(target_method) = target_method.upgrade() {
                            target_method.generic_args.push(method_spec.clone());
                        }
                    }
                    CilTypeReference::ModuleRef(_module) => {
                        // ToDo: ModuleRef case is not yet implemented
                    }
                    _ => {
                        return Err(malformed_error!("Invalid memberref type reference"));
                    }
                }
            }
            _ => {
                return Err(malformed_error!("Invalid method type reference"));
            }
        }

        Ok(method_spec)
    }
}

impl<'a> RowDefinition<'a> for MethodSpecRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* method */        sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef) +
            /* instantiation */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodSpecRaw {
            rid,
            token: Token::new(0x2B00_0000 + rid),
            offset: *offset,
            method: CodedIndex::read(data, offset, sizes, CodedIndexType::MethodDefOrRef)?,
            instantiation: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x00, // method
            0x02, 0x02, // instantiation
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSpec, 1),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2B000001);
            assert_eq!(
                row.method,
                CodedIndex {
                    tag: TableId::MemberRef,
                    row: 0,
                    token: Token::new(0x0A000000),
                }
            );
            assert_eq!(row.instantiation, 0x0202);
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
            0x01, 0x00, 0x00, 0x00, // method
            0x02, 0x02, 0x02, 0x02, // instantiation
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSpec, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::MemberRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2B000001);
            assert_eq!(
                row.method,
                CodedIndex {
                    tag: TableId::MemberRef,
                    row: 0,
                    token: Token::new(0x0A000000),
                }
            );
            assert_eq!(row.instantiation, 0x02020202);
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
