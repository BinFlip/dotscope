use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, InterfaceImpl, InterfaceImplRc, RowDefinition, TableId,
            TableInfoRef, TypeAttributes,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `InterfaceImpl` table defines interface implementations for types in the `TypeDef` table. `TableId` = 0x09
pub struct InterfaceImplRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `TypeDef` table
    pub class: u32,
    /// an index into the `TypeDef`, `TypeRef`, or `TypeSpec` table; more precisely, a `TypeDefOrRef` (§II.24.2.6) coded index
    pub interface: CodedIndex,
}

impl InterfaceImplRaw {
    /// Apply an `InterfaceImpl` - Resolves indexes and then updates 'Class' to have the new interface method
    ///     
    /// ## Arguments
    /// * 'types'   - All parsed `CilType` entries
    ///
    /// # Errors
    /// Returns an error if the interface token cannot be resolved or if the class token is invalid.
    pub fn apply(&self, types: &TypeRegistry) -> Result<()> {
        let Some(interface) = types.get(&self.interface.token) else {
            return Err(malformed_error!(
                "Failed to resolve interface token - {}",
                self.interface.token.value()
            ));
        };

        match types.get(&Token::new(self.class | 0x0200_0000)) {
            Some(class) => {
                // Check if this is interface inheritance (both class and interface are interfaces)
                // The .NET compiler incorrectly puts interface inheritance in InterfaceImpl table
                let class_is_interface = class.flags & TypeAttributes::INTERFACE != 0;
                let interface_is_interface = interface.flags & TypeAttributes::INTERFACE != 0;

                if class_is_interface && interface_is_interface {
                    if class.base().is_none() {
                        let _ = class.set_base(interface.clone().into());
                    }
                } else {
                    class.interfaces.push(interface.into());
                }
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class token - {}",
                self.class | 0x0200_0000
            )),
        }
    }

    /// Convert an `InterfaceImplRaw`, into a `InterfaceImpl` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'types'   - All parsed `CilType` entries
    ///
    /// # Errors
    /// Returns an error if the interface or class tokens cannot be resolved.
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<InterfaceImplRc> {
        Ok(Arc::new(InterfaceImpl {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            class: match types.get(&Token::new(self.class | 0x0200_0000)) {
                Some(class) => class,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve class token - {}",
                        self.class | 0x0200_0000
                    ))
                }
            },
            interface: match types.get(&self.interface.token) {
                Some(interface) => interface,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve interface token - {}",
                        self.interface.token.value()
                    ))
                }
            },
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for InterfaceImplRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */        sizes.table_index_bytes(TableId::TypeDef) +
            /* interface */    sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(InterfaceImplRaw {
            rid,
            token: Token::new(0x0900_0000 + rid),
            offset: *offset,
            class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            interface: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // class
            0x02, 0x02, // interface
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::InterfaceImpl, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<InterfaceImplRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: InterfaceImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x09000001);
            assert_eq!(row.class, 0x0101);
            assert_eq!(
                row.interface,
                CodedIndex {
                    tag: TableId::TypeSpec,
                    row: 0x80,
                    token: Token::new(0x80 | 0x1B000000),
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
            0x02, 0x02, 0x02, 0x02, // interface
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<InterfaceImplRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: InterfaceImplRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x09000001);
            assert_eq!(row.class, 0x01010101);
            assert_eq!(
                row.interface,
                CodedIndex {
                    tag: TableId::TypeSpec,
                    row: 0x808080,
                    token: Token::new(0x808080 | 0x1B000000),
                }
            );
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
