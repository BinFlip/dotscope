use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        signatures::parse_field_signature,
        streams::{Blob, Strings},
        tables::{Field, FieldRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The Field table defines fields for types in the `TypeDef` table. `TableId` = 0x04
pub struct FieldRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `FieldAttributes`, §II.23.1.5
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Blob heap
    pub signature: u32,
}

impl FieldRaw {
    /// Convert an `FieldRaw`, into a `Field` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'strings'     - The #String heap
    ///
    /// # Errors
    /// Returns an error if string or blob lookup fails, or if signature parsing fails
    pub fn to_owned(&self, blob: &Blob, strings: &Strings) -> Result<FieldRc> {
        Ok(Arc::new(Field {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            name: strings.get(self.name as usize)?.to_string(),
            signature: parse_field_signature(blob.get(self.signature as usize)?)?,
            default: OnceLock::new(),
            rva: OnceLock::new(),
            layout: OnceLock::new(),
            marshal: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply a `FieldRaw` entry to update related metadata structures.
    ///
    /// Field entries define the fields of types. They are associated with their parent types
    /// but don't themselves modify other metadata during the dual variant resolution phase.
    /// Field-specific metadata (defaults, RVA, layout, marshalling) is resolved separately.
    ///
    /// # Errors
    /// Always returns `Ok(())` as Field entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for FieldRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2 +
            /* name */      sizes.str_bytes() +
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(FieldRaw {
            rid,
            token: Token::new(0x0400_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x04000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.signature, 0x0303);
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<FieldRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x04000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.signature, 0x03030303);
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
