use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        customattributes::CustomAttributeValueList,
        method::MethodMap,
        signatures::{parse_method_spec_signature, SignatureMethodSpec},
        streams::{
            Blob, CodedIndex, CodedIndexType, GenericParamRc, MemberRefMap, RowDefinition, TableId,
            TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, GenericArgument, TypeRegistry, TypeResolver},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `MethodSpec`
pub type MethodSpecMap = SkipMap<Token, MethodSpecRc>;
/// A vector that holds a list of `MethodSpec`
pub type MethodSpecList = Arc<boxcar::Vec<MethodSpecRc>>;
/// A reference to a `MethodSpec`
pub type MethodSpecRc = Arc<MethodSpec>;

/// The `MethodSpec` table represents instantiations of generic methods. Similar to `MethodSpecRaw` but
/// with resolved indexes and owned data
pub struct MethodSpec {
    /// `RowID`
    pub rid: u32,
    /// `Token`
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `MethodDefOrRef` coding index
    pub method: CilTypeReference,
    /// an index into the Blob heap
    pub instantiation: SignatureMethodSpec,
    /// Custom attributes applied to this `MethodSpec`
    pub custom_attributes: CustomAttributeValueList,
}

impl MethodSpec {
    /// Apply a `MethodSemantics` entry - The associated type fill be updated to have it's getter/setter set
    ///
    /// # Errors
    ///
    /// Returns an error if the method type reference is invalid or if handling is not yet implemented.
    pub fn apply(&self) -> Result<()> {
        match &self.method {
            CilTypeReference::MethodDef(_method) => {
                todo!("Implement handling of MethodDef updates for MethodSpec");
            }
            CilTypeReference::MemberRef(_memberref) => {
                todo!("Implement handling of MemberRef updates for MethodSpec");
            }
            _ => Err(malformed_error!("Invalid method type reference")),
        }
    }
}

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
    /// Convert an `MethodSpecRaw`, into a `MethodSpec` which has indexes resolved and owns the referenced data
    ///
    /// # Errors
    ///
    /// Returns an error if the method token is invalid, if the referenced method cannot be resolved,
    /// or if there are issues parsing the method specification signature.
    ///
    /// ## Arguments
    /// * 'value'       - The value to be converted
    /// * 'blob'        - The #Blob heap
    /// * 'methods'     - All parsed `MethodDef` entries
    /// * 'memberrefs'  - All parsed `MemberRef` entries
    pub fn apply(
        &self,
        blob: &Blob,
        types: &Arc<TypeRegistry>,
        methods: &MethodMap,
        memberrefs: &MemberRefMap,
    ) -> Result<()> {
        // ToDo: Fix implementation
        //          - Don't update existing types, these are the underlaying Def/Ref/.
        //          - Create new Method, that uses existing type as base
        //          - Update new method, to contain information

        let mut resolver = TypeResolver::new(types.clone());
        let sig = parse_method_spec_signature(blob.get(self.instantiation as usize)?)?;

        let generic_arg_types = boxcar::Vec::with_capacity(sig.generic_args.len());
        for generic_arg in sig.generic_args {
            generic_arg_types.push(resolver.resolve(&generic_arg)?);
        }

        let generate_arguments =
            |params: &boxcar::Vec<GenericParamRc>, args: &boxcar::Vec<GenericArgument>| {
                for (i, arg_type) in &generic_arg_types {
                    let param = params
                        .iter()
                        .find(|(_, e)| e.number as usize == i)
                        .map(|entry| entry.1.clone());

                    args.push(GenericArgument {
                        parameter: param,
                        argument_type: arg_type.clone().into(),
                    });
                }
            };

        match self.method.tag {
            TableId::MethodDef => match methods.get(&self.method.token) {
                Some(method) => {
                    generate_arguments(
                        &method.value().generic_params,
                        &method.value().generic_args,
                    );
                    Ok(())
                }
                None => Err(malformed_error!(
                    "Failed to resolve method - {}",
                    self.method.token.value()
                )),
            },
            TableId::MemberRef => match memberrefs.get(&self.method.token) {
                Some(memberref) => match &memberref.value().declaredby {
                    CilTypeReference::TypeRef(typeref)
                    | CilTypeReference::TypeDef(typeref)
                    | CilTypeReference::TypeSpec(typeref) => {
                        if let (Some(generic_params), Some(generic_args)) =
                            (typeref.generic_params(), typeref.generic_args())
                        {
                            generate_arguments(&generic_params, &generic_args);
                        }
                        Ok(())
                    }
                    CilTypeReference::MethodDef(method) => {
                        if let Some(method) = method.upgrade() {
                            generate_arguments(&method.generic_params, &method.generic_args);
                        }

                        Ok(())
                    }
                    CilTypeReference::ModuleRef(_module) => {
                        unimplemented!()
                    }
                    _ => Err(malformed_error!("Invalid type reference")),
                },
                None => Err(malformed_error!(
                    "Failed to resolve memberref reference - {}",
                    self.method.token.value()
                )),
            },
            _ => Err(malformed_error!(
                "Invalid method token - {}",
                self.method.token.value()
            )),
        }
    }

    /// Convert an `MethodSpecRaw`, into a `MethodSpec` which has indexes resolved and owns the referenced data
    ///
    /// # Errors
    ///
    /// Returns an error if the method token is invalid, if the referenced method or member reference
    /// cannot be resolved, or if there are issues parsing the method specification signature.
    ///
    /// ## Arguments
    /// * 'value'       - The value to be converted
    /// * 'blob'        - The #Blob heap
    /// * 'methods'     - All parsed `MethodDef` entries
    /// * 'memberrefs'  - All parsed `MemberRef` entries
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<MethodSpecRc>
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

        Ok(Arc::new(MethodSpec {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            method,
            instantiation: parse_method_spec_signature(blob.get(self.instantiation as usize)?)?,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
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
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

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
