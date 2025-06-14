use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{ClassLayout, ClassLayoutRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::TypeRegistry,
        validation::LayoutValidator,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `ClassLayout` table specifies the layout of fields within a class (explicit layout), `TableId` = 0x0F
pub struct ClassLayoutRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value, specifying the alignment of fields
    pub packing_size: u16,
    /// a 4-byte value, specifying the size of the class
    pub class_size: u32,
    /// an index into the `TypeDef` table
    pub parent: u32,
}

impl ClassLayoutRaw {
    /// Apply an `ClassLayoutRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'types' - The `CilTypeMap` of loaded entities
    ///
    /// # Errors
    /// Returns an error if the type token cannot be resolved or if the class size or packing size
    /// is already set on the target type.
    pub fn apply(&self, types: &TypeRegistry) -> Result<()> {
        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(class) => {
                LayoutValidator::validate_class_layout(self.class_size, self.packing_size, &class)?;

                class
                    .class_size
                    .set(self.class_size)
                    .map_err(|_| malformed_error!("Class size already set"))?;
                class
                    .packing_size
                    .set(self.packing_size)
                    .map_err(|_| malformed_error!("Packing size already set"))
            }
            None => Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent | 0x0200_0000
            )),
        }
    }

    /// Convert an `ClassLayoutRaw`, into a `ClassLayout` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'refs' - The map of loaded `AssemblyRef` entities
    ///
    /// # Errors
    /// Returns an error if the parent type token cannot be resolved in the provided type registry.
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<ClassLayoutRc> {
        Ok(Arc::new(ClassLayout {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            packing_size: self.packing_size,
            class_size: self.class_size,
            parent: match types.get(&Token::new(self.parent | 0x0200_0000)) {
                Some(refs) => refs,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve parent token - {}",
                        self.parent | 0x0200_0000
                    ))
                }
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for ClassLayoutRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* packing_size */ 2 +
            /* class_size */   4 +
            /* parent */       sizes.table_index_bytes(TableId::TypeDef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let packing_size = read_le_at::<u16>(data, offset)?;
        let class_size = read_le_at::<u32>(data, offset)?;
        let parent = read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?;

        Ok(ClassLayoutRaw {
            rid,
            token: Token::new(0x0F00_0000 + rid),
            offset: offset_org,
            packing_size,
            class_size,
            parent,
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
            0x01, 0x01, // packing_size
            0x02, 0x02, 0x02, 0x02, // class_size
            0x03, 0x03, // parent
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ClassLayoutRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ClassLayoutRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0F000001);
            assert_eq!(row.packing_size, 0x0101);
            assert_eq!(row.class_size, 0x02020202);
            assert_eq!(row.parent, 0x0303);
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
            0x01, 0x01, // packing_size
            0x02, 0x02, 0x02, 0x02, // class_size
            0x03, 0x03, 0x03, 0x03, // parent
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<ClassLayoutRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: ClassLayoutRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0F000001);
            assert_eq!(row.packing_size, 0x0101);
            assert_eq!(row.class_size, 0x02020202);
            assert_eq!(row.parent, 0x03030303);
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
