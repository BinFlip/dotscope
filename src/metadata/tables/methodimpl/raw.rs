use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        method::MethodMap,
        tables::{
            CodedIndex, CodedIndexType, MemberRefMap, MethodImpl, MethodImplRc, RowDefinition,
            TableId, TableInfoRef,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `MethodImpl` table specifies which methods implement which methods for a class. `TableId` = 0x19
pub struct MethodImplRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index to the `CilType` which implements the Interface
    pub class: u32,
    /// an index to the `Method` owned by 'class' that is implementing the interface functionality
    pub method_body: CodedIndex,
    /// an index to the 'Interface' definition
    pub method_declaration: CodedIndex,
}

impl MethodImplRaw {
    /// Apply an `MethodImplRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'types'       - All parsed `CilType` entries
    /// * 'memberrefs'  - All parsed `MemberRef` entries
    /// * 'methods'     - All parsed `MethodDef` entries
    ///
    /// # Errors
    /// Returns an error if method tokens cannot be resolved or if the method body
    /// or declaration references are invalid.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        memberrefs: &MemberRefMap,
        methods: &MethodMap,
    ) -> Result<()> {
        // ToDo: Implement resolving of MemberRefs, accross multiple binaries (if present and loaded)
        let interface_implementation = match self.method_body.tag {
            TableId::MethodDef => match methods.get(&self.method_body.token) {
                Some(parent) => CilTypeReference::MethodDef(parent.value().clone().into()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve methoddef method_body token - {}",
                        self.method_body.token.value()
                    ))
                }
            },
            TableId::MemberRef => match memberrefs.get(&self.method_body.token) {
                Some(parent) => CilTypeReference::MemberRef(parent.value().clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve memberref method_body token - {}",
                        self.method_body.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid method_body token - {}",
                    self.method_body.token.value()
                ))
            }
        };

        match types.get(&Token::new(self.class | 0x0200_0000)) {
            Some(cil_type) => {
                cil_type.overwrites.push(interface_implementation.clone());

                match self.method_declaration.tag {
                    TableId::MethodDef => match methods.get(&self.method_declaration.token) {
                        Some(parent) => {
                            if let CilTypeReference::MethodDef(method_ref) =
                                &interface_implementation
                            {
                                parent.value().interface_impls.push(method_ref.clone());
                            }
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve methoddef method_declaration token - {}",
                                self.method_declaration.token.value()
                            ))
                        }
                    },
                    TableId::MemberRef => match memberrefs.get(&self.method_declaration.token) {
                        Some(_parent) => {
                            // ToDo: Handle MemberRef interface declarations
                            // MemberRef declarations need special handling for cross-assembly references
                            // For now, we only track bidirectional relationships for MethodDef declarations
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve memberref method_declaration token - {}",
                                self.method_declaration.token.value()
                            ))
                        }
                    },
                    _ => {
                        return Err(malformed_error!(
                            "Invalid method_declaration token - {}",
                            self.method_declaration.token.value()
                        ))
                    }
                }

                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class type token - {}",
                self.class | 0x0200_0000
            )),
        }
    }

    /// Convert an `MethodImplRaw`, into a `MethodImpl` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * `get_ref`  - Closure to resolve coded indexes to type references
    /// * `types`    - The type registry containing all parsed `CilType` entries
    ///
    /// # Errors
    /// Returns an error if method tokens cannot be resolved, if the class type cannot be found,
    /// or if the method body or declaration references are invalid.
    pub fn to_owned<F>(&self, get_ref: F, types: &TypeRegistry) -> Result<MethodImplRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        Ok(Arc::new(MethodImpl {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            class: match types.get(&Token::new(self.class | 0x0200_0000)) {
                Some(cil_type) => cil_type.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve class type token - {}",
                        self.class | 0x0200_0000
                    ))
                }
            },
            method_body: {
                let result = get_ref(&self.method_body);
                if matches!(result, CilTypeReference::None) {
                    return Err(malformed_error!(
                        "Failed to resolve method_body token - {}",
                        self.method_body.token.value()
                    ));
                }
                result
            },
            method_declaration: {
                let result = get_ref(&self.method_declaration);
                if matches!(result, CilTypeReference::None) {
                    return Err(malformed_error!(
                        "Failed to resolve method_declaration token - {}",
                        self.method_declaration.token.value()
                    ));
                }
                result
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for MethodImplRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */               sizes.table_index_bytes(TableId::TypeDef) +
            /* method_body */         sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef) +
            /* method_declaration */  sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodImplRaw {
            rid,
            token: Token::new(0x1900_0000 + rid),
            offset: *offset,
            class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            method_body: CodedIndex::read(data, offset, sizes, CodedIndexType::MethodDefOrRef)?,
            method_declaration: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::MethodDefOrRef,
            )?,
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
            0x01, 0x01, // class
            0x02, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x19000001);
            assert_eq!(row.class, 0x0101);
            assert_eq!(
                row.method_body,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
                }
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
                }
            );
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
            0x02, 0x00, 0x00, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, 0x00, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::MemberRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x19000001);
            assert_eq!(row.class, 0x01010101);
            assert_eq!(
                row.method_body,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
                }
            );
            assert_eq!(
                row.method_declaration,
                CodedIndex {
                    tag: TableId::MethodDef,
                    row: 1,
                    token: Token::new(1 | 0x06000000),
                }
            );
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
