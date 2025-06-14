use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        signatures::parse_property_signature,
        streams::{Blob, Strings},
        tables::{Property, PropertyRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `Property` table defines properties for types. Each entry includes the property name, flags, and signature. `TableId` = 0x17
pub struct PropertyRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `PropertyAttributes`, §II.23.1.14
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Blob heap
    pub signature: u32,
}

impl PropertyRaw {
    /// Convert an `PropertyRaw`, into a `Property` which has indexes resolved and owns the referenced data
    ///
    /// # Errors
    /// Returns an error if the property name cannot be retrieved from the strings heap
    /// or if the property signature cannot be parsed from the blob heap.
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    /// * 'blob'    - The #Blob heap
    pub fn to_owned(&self, strings: &Strings, blob: &Blob) -> Result<PropertyRc> {
        Ok(Arc::new(Property {
            token: self.token,
            flags: self.flags,
            name: strings.get(self.name as usize)?.to_string(),
            signature: parse_property_signature(blob.get(self.signature as usize)?)?,
            default: OnceLock::new(),
            fn_setter: OnceLock::new(),
            fn_getter: OnceLock::new(),
            fn_other: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply a `PropertyRaw` entry to update related metadata structures.
    ///
    /// Property entries define properties that types can expose. They are associated with types
    /// but don't themselves modify other metadata during the dual variant resolution phase.
    /// Property methods (getter, setter, etc.) are resolved separately through method resolution.
    ///
    /// # Errors
    /// Always returns `Ok(())` as Property entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for PropertyRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */          2 +
            /* name */           sizes.str_bytes() +
            /* type_signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(PropertyRaw {
            rid,
            token: Token::new(0x1700_0000 + rid),
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
            0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
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
            0x03, 0x03, 0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
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
