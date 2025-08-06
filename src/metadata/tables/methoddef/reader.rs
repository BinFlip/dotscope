use crate::{
    metadata::{
        tables::{MethodDefRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for MethodDefRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MethodDefRaw {
            rid,
            token: Token::new(0x0600_0000 + rid),
            offset: *offset,
            rva: read_le_at::<u32>(data, offset)?,
            impl_flags: u32::from(read_le_at::<u16>(data, offset)?),
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            param_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::Param))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // impl_flags
            0x03, 0x03, // flags
            0x04, 0x04, // name
            0x05, 0x05, // signature
            0x06, 0x06, // param_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodDefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x06000001);
            assert_eq!(row.rva, 0x01010101);
            assert_eq!(row.impl_flags, 0x0202);
            assert_eq!(row.flags, 0x0303);
            assert_eq!(row.name, 0x0404);
            assert_eq!(row.signature, 0x0505);
            assert_eq!(row.param_list, 0x0606);
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
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // impl_flags
            0x03, 0x03, // flags
            0x04, 0x04, 0x04, 0x04, // name
            0x05, 0x05, 0x05, 0x05, // signature
            0x06, 0x06, 0x06, 0x06, // param_list
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodDefRaw>::new(&data, u16::MAX as u32 + 2, sizes).unwrap();

        let eval = |row: MethodDefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x06000001);
            assert_eq!(row.rva, 0x01010101);
            assert_eq!(row.impl_flags, 0x0202);
            assert_eq!(row.flags, 0x0303);
            assert_eq!(row.name, 0x04040404);
            assert_eq!(row.signature, 0x05050505);
            assert_eq!(row.param_list, 0x06060606);
        };

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
