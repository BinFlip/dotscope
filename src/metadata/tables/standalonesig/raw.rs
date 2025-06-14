use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::Blob,
        tables::{RowDefinition, StandAloneSigRc, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `StandAloneSig` table stores signatures that are referenced directly rather than through a member.
/// These are primarily used for local variables and method parameters. `TableId` = 0x11
pub struct StandAloneSigRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the Blob heap
    pub signature: u32,
}

impl StandAloneSigRaw {
    /// Convert an `StandAloneSigRaw`, into a `StandAloneSig` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Currently returns an error as this function is not yet implemented.
    pub fn to_owned(&self, _blob: &Blob) -> Result<StandAloneSigRc> {
        todo!("Implement StandAloneSig::from - solve storage / resolution of signature types")
    }

    /// Apply a `StandAloneSigRaw` entry to update related metadata structures.
    ///
    /// `StandAloneSig` entries define standalone signatures that can be referenced by other
    /// metadata elements. They are primarily signature definitions and don't require
    /// cross-table updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `StandAloneSig` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for StandAloneSigRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let signature = read_le_at_dyn(data, offset, sizes.is_large_blob())?;

        Ok(StandAloneSigRaw {
            rid,
            token: Token::new(0x1100_0000 + rid),
            offset: offset_org,
            signature,
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
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));
        let table = MetadataTable::<StandAloneSigRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StandAloneSigRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x11000001);
            assert_eq!(row.signature, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(&[], true, true, true));
        let table =
            MetadataTable::<StandAloneSigRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: StandAloneSigRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x11000001);
            assert_eq!(row.signature, 0x01010101);
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
