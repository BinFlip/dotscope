use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        method::MethodMap,
        streams::{CodedIndex, CodedIndexType, MemberRefMap, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference, TypeRegistry},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `MethodImpl`
pub type MethodImplMap = SkipMap<Token, MethodImplRc>;
/// A vector that holds a list of `MethodImpl`
pub type MethodImplList = Arc<boxcar::Vec<MethodImplRc>>;
/// A reference to a `MethodImpl`
pub type MethodImplRc = Arc<MethodImpl>;

/// The `MethodImpl` table specifies which methods implement which methods for a class. Similar to `MethodImplRaw` but
/// with resolved indexes and owned data
pub struct MethodImpl {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The `CilType` which implements the Interface
    pub class: CilTypeRc,
    /// The `Method` owned by 'class' that is implementing the interface functionality
    pub method_body: CilTypeReference,
    /// The 'Interface' definition
    pub method_declaration: CilTypeReference,
}

impl MethodImpl {
    /// Apply a `MethodImpl` to update the class with interface implementation information.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the class without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if updating the class overwrite information fails.
    pub fn apply(&self) -> Result<()> {
        self.class.overwrites.push(self.method_body.clone());
        Ok(())
    }
}

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
    /// * 'value'       - The value to be converted
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
                cil_type.overwrites.push(interface_implementation);
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class type token - {}",
                self.class | 0x0200_0000
            )),
        }

        // ToDo: Implement resolving and updating of the type that implements the interface definition
        // let interface_definition = match self.method_declaration.tag {
        //     TableId::MethodDef => match methods.get(&self.method_declaration.token) {
        //         Some(parent) => CilTypeReference::MethodDef(parent.clone()),
        //         None => return Err(Malformed),
        //     },
        //     TableId::MemberRef => match memberrefs.get(&self.method_declaration.token) {
        //         Some(parent) => CilTypeReference::MemberRef(parent.clone()),
        //         None => return Err(Malformed),
        //     },
        //     _ => return Err(Malformed),
        // };
    }

    /// Convert an `MethodImplRaw`, into a `MethodImpl` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'types'       - All parsed `CilType` entries
    /// * 'memberrefs'  - All parsed `MemberRef` entries
    /// * 'methods'     - All parsed `MethodDef` entries
    ///
    /// # Errors
    /// Returns an error if method tokens cannot be resolved, if the class type cannot be found,
    /// or if the method body or declaration references are invalid.
    pub fn to_owned(
        &self,
        types: &TypeRegistry,
        memberrefs: &MemberRefMap,
        methods: &MethodMap,
    ) -> Result<MethodImplRc> {
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
            method_body: match self.method_body.tag {
                TableId::MethodDef => match methods.get(&self.method_body.token) {
                    Some(method) => CilTypeReference::MethodDef(method.value().clone().into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve methoddef method_body token - {}",
                            self.method_body.token.value()
                        ))
                    }
                },
                TableId::MemberRef => match memberrefs.get(&self.method_body.token) {
                    Some(memberref) => CilTypeReference::MemberRef(memberref.value().clone()),
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
            },
            method_declaration: match self.method_declaration.tag {
                TableId::MethodDef => match methods.get(&self.method_declaration.token) {
                    Some(method) => CilTypeReference::MethodDef(method.value().clone().into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve methoddef method_declaration token - {}",
                            self.method_declaration.token.value()
                        ))
                    }
                },
                TableId::MemberRef => match memberrefs.get(&self.method_declaration.token) {
                    Some(memberref) => CilTypeReference::MemberRef(memberref.value().clone()),
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
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

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
