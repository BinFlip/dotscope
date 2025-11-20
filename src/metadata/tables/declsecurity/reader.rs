//! Binary reader implementation for `DeclSecurity` table entries.
//!
//! This module implements the [`crate::metadata::tables::types::RowReadable`] trait for
//! [`crate::metadata::tables::declsecurity::DeclSecurityRaw`], enabling direct parsing
//! of `DeclSecurity` table entries from binary metadata streams. The implementation
//! handles variable-sized fields based on heap sizes and provides comprehensive test
//! coverage for different data sizes.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::types::RowReadable`] implementation for [`crate::metadata::tables::declsecurity::DeclSecurityRaw`]
//!
//! # Thread Safety
//!
//! All parsing operations are thread-safe and stateless, enabling concurrent
//! processing of multiple table entries.

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, DeclSecurityRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for DeclSecurityRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let action = read_le_at::<u16>(data, offset)?;

        Ok(DeclSecurityRaw {
            rid,
            token: Token::new(0x0E00_0000 + rid),
            offset: offset_org,
            action,
            parent: CodedIndex::read(data, offset, sizes, CodedIndexType::HasDeclSecurity)?,
            permission_set: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // action
            0x02, 0x02, // parent
            0x03, 0x03, // permission_set
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1),
                (TableId::MethodDef, 1),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<DeclSecurityRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: DeclSecurityRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0E000001);
            assert_eq!(row.action, 0x0101);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Assembly, 128, CodedIndexType::HasDeclSecurity)
            );
            assert_eq!(row.permission_set, 0x303);
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
            0x01, 0x01, // action
            0x02, 0x02, 0x02, 0x02, // parent
            0x03, 0x03, 0x03, 0x03, // permission_set
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::Assembly, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<DeclSecurityRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: DeclSecurityRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0E000001);
            assert_eq!(row.action, 0x0101);
            assert_eq!(
                row.parent,
                CodedIndex::new(TableId::Assembly, 0x808080, CodedIndexType::HasDeclSecurity)
            );
            assert_eq!(row.permission_set, 0x3030303);
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
