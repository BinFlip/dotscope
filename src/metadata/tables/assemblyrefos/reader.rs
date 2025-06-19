use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{AssemblyRefOsRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for AssemblyRefOsRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* os_platform_id */   4 +
            /* os_major_version */ 4 +
            /* os_minor_version */ 4 +
            /* assembly_ref */     sizes.table_index_bytes(TableId::AssemblyRef)
        )
    }

    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(AssemblyRefOsRaw {
            rid,
            token: Token::new(0x2500_0000 + rid),
            offset: *offset,
            os_platform_id: read_le_at::<u32>(data, offset)?,
            os_major_version: read_le_at::<u32>(data, offset)?,
            os_minor_version: read_le_at::<u32>(data, offset)?,
            assembly_ref: read_le_at_dyn(data, offset, sizes.is_large(TableId::AssemblyRef))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // os_platform_id
            0x02, 0x02, 0x02, 0x02, // os_major_version
            0x03, 0x03, 0x03, 0x03, // os_minor_version
            0x04, 0x04, // assembly_ref
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRefOS, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyRefOsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRefOsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x25000001);
            assert_eq!(row.os_platform_id, 0x01010101);
            assert_eq!(row.os_major_version, 0x02020202);
            assert_eq!(row.os_minor_version, 0x03030303);
            assert_eq!(row.assembly_ref, 0x0404);
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
            0x01, 0x01, 0x01, 0x01, // os_platform_id
            0x02, 0x02, 0x02, 0x02, // os_major_version
            0x03, 0x03, 0x03, 0x03, // os_minor_version
            0x04, 0x04, 0x04, 0x04, // assembly_ref
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRefOS, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<AssemblyRefOsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRefOsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x25000001);
            assert_eq!(row.os_platform_id, 0x01010101);
            assert_eq!(row.os_major_version, 0x02020202);
            assert_eq!(row.os_minor_version, 0x03030303);
            assert_eq!(row.assembly_ref, 0x0404);
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
