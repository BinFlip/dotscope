//! Binary reader implementation for `CustomDebugInformation` table entries.
//!
//! This module implements the [`crate::metadata::tables::types::RowReadable`] trait for
//! [`crate::metadata::tables::customdebuginformation::CustomDebugInformationRaw`],
//! enabling direct parsing of `CustomDebugInformation` table entries from binary
//! metadata streams. The implementation handles variable-sized fields based on
//! heap sizes and provides comprehensive test coverage for different data sizes.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::types::RowReadable`] implementation for [`crate::metadata::tables::customdebuginformation::CustomDebugInformationRaw`]
//!
//! # Thread Safety
//!
//! All parsing operations are thread-safe and stateless, enabling concurrent
//! processing of multiple table entries.

use crate::{
    metadata::{
        tables::{
            types::{CodedIndex, CodedIndexType, TableInfoRef},
            CustomDebugInformationRaw, RowReadable,
        },
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for CustomDebugInformationRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let parent = CodedIndex::read(
            data,
            offset,
            sizes,
            CodedIndexType::HasCustomDebugInformation,
        )?;
        let kind = read_le_at_dyn(data, offset, sizes.is_large_guid())?;
        let value = read_le_at_dyn(data, offset, sizes.is_large_blob())?;

        Ok(CustomDebugInformationRaw {
            rid,
            token: Token::new(0x3700_0000 + rid),
            offset: offset_org,
            parent,
            kind,
            value,
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
            0x06, 0x00, // parent (2 bytes, normal coded index) - 0x0006 (tag=6, row=0)
            0x01, 0x00, // kind (2 bytes, normal GUID heap) - 0x0001
            0x0A, 0x00, // value (2 bytes, normal blob heap) - 0x000A
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::CustomDebugInformation, 1),
                (TableId::MethodDef, 1000),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<CustomDebugInformationRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: CustomDebugInformationRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x37000001);
            assert_eq!(row.parent.row, 0);
            assert_eq!(row.kind, 0x0001);
            assert_eq!(row.value, 0x000A);
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
            0x06, 0x01, 0x00,
            0x00, // parent (4 bytes, large coded index) - 0x00000106 (tag=6, row=8)
            0x01, 0x01, 0x00, 0x00, // kind (4 bytes, large GUID heap) - 0x00000101
            0x0A, 0x02, 0x00, 0x00, // value (4 bytes, large blob heap) - 0x0000020A
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::CustomDebugInformation, 1),
                (TableId::MethodDef, 100000),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<CustomDebugInformationRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: CustomDebugInformationRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x37000001);
            assert_eq!(row.parent.row, 8);
            assert_eq!(row.kind, 0x00000101);
            assert_eq!(row.value, 0x0000020A);
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
