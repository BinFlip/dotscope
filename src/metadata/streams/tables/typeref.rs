use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{
            AssemblyRefMap, CodedIndex, CodedIndexType, ModuleRc, ModuleRefMap, RowDefinition,
            Strings, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeReference, TypeRegistry},
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `TypeRef` table contains references to types defined in other modules or assemblies. `TableId` = 0x01
pub struct TypeRefRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into a `Module`, `ModuleRef`, `AssemblyRef` or `TypeRef` table, or null; more precisely, a `ResolutionScope` (§II.24.2.6) coded index
    pub resolution_scope: CodedIndex,
    /// an index into the String heap
    pub type_name: u32,
    /// an index into the String heap
    pub type_namespace: u32,
}

impl TypeRefRaw {
    /// Convert an `TypeRefRaw`, into a `CilType` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings'     - The #String heap
    /// * 'module'      - All parsed `Module` entries
    /// * 'modules'     - All parsed `ModuleRef` entries
    /// * 'assemblies'  - All parsed `AssemblyRef` entries
    /// * 'types'       - All parsed `CilType` entries
    ///
    /// # Errors
    /// Returns an error if string data cannot be retrieved from heaps or if resolution scope references are invalid
    pub fn to_owned(
        &self,
        strings: &Strings,
        module: &ModuleRc,
        modules: &ModuleRefMap,
        assemblies: &AssemblyRefMap,
        types: &TypeRegistry,
    ) -> Result<CilTypeRc> {
        Ok(Arc::new(CilType::new(
            self.token,
            CilFlavor::Unknown,
            strings.get(self.type_namespace as usize)?.to_string(),
            strings.get(self.type_name as usize)?.to_string(),
            Some(match self.resolution_scope.tag {
                TableId::Module => CilTypeReference::Module(module.clone()),
                TableId::ModuleRef => match modules.get(&self.resolution_scope.token) {
                    Some(module_ref) => CilTypeReference::ModuleRef(module_ref.value().clone()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve ModuleRef - {}",
                            self.resolution_scope.token.value()
                        ))
                    }
                },
                TableId::AssemblyRef => match assemblies.get(&self.resolution_scope.token) {
                    Some(assembly_ref) => {
                        CilTypeReference::AssemblyRef(assembly_ref.value().clone())
                    }
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve AssemblyRef - {}",
                            self.resolution_scope.token.value()
                        ))
                    }
                },
                TableId::TypeRef => match types.get(&self.resolution_scope.token) {
                    Some(cil_type) => CilTypeReference::TypeRef(cil_type.into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve TypeRef - {}",
                            self.resolution_scope.token.value()
                        ))
                    }
                },
                _ => {
                    return Err(malformed_error!(
                        "Invalid resolution scope - {}",
                        self.resolution_scope.token
                    ))
                }
            }),
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        )))
    }
}

impl<'a> RowDefinition<'a> for TypeRefRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* resolution_scope */  sizes.coded_index_bytes(CodedIndexType::ResolutionScope) +
            /* type_namespace */    sizes.str_bytes() +
            /* type_name */         sizes.str_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(TypeRefRaw {
            rid,
            token: Token::new(0x0100_0000 + rid),
            offset: *offset,
            resolution_scope: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::ResolutionScope,
            )?,
            type_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            type_namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // resolution_scope
            0x02, 0x02, // type_name
            0x03, 0x03, // type_namespace
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex {
                    tag: TableId::ModuleRef,
                    row: 64,
                    token: Token::new(64 | 0x1A000000),
                }
            );
            assert_eq!(row.type_name, 0x0202);
            assert_eq!(row.type_namespace, 0x0303);
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
            0x01, 0x01, 0x01, 0x01, // resolution_scope
            0x02, 0x02, 0x02, 0x02, // type_name
            0x03, 0x03, 0x03, 0x03, // type_namespace
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeRef, 1),
                (TableId::AssemblyRef, u16::MAX as u32 + 2),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex {
                    tag: TableId::ModuleRef,
                    row: 0x404040,
                    token: Token::new(0x404040 | 0x1A000000),
                }
            );
            assert_eq!(row.type_name, 0x02020202);
            assert_eq!(row.type_namespace, 0x03030303);
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
