//! Raw MethodDebugInformation table representation for Portable PDB format
//!
//! This module provides the [`MethodDebugInformationRaw`] struct that represents
//! the binary format of MethodDebugInformation table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::Blob,
        tables::{types::*, MethodDebugInformation, MethodDebugInformationRc},
        token::Token,
    },
    Result,
};
use std::sync::Arc;

/// Raw binary representation of a MethodDebugInformation table entry
///
/// This structure matches the exact binary layout of MethodDebugInformation table
/// entries in the metadata tables stream. All heap references remain as unresolved
/// indices that must be resolved through the appropriate heap during the conversion
/// to the owned [`MethodDebugInformation`] variant.
///
/// # Binary Format
///
/// Each MethodDebugInformation table entry consists of:
/// - Document: Simple index into Document table
/// - SequencePoints: Blob heap index containing sequence point data
///
/// The exact byte size depends on whether large heap indices are used, determined
/// by the heap size flags in the metadata header.
///
/// # Heap Index Resolution
///
/// - `document`: Simple table index into Document table (0 = no document)
/// - `sequence_points`: Must be resolved through blob heap to get encoded sequence data
///
/// # Reference
/// * [Portable PDB Format - MethodDebugInformation Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)
#[derive(Debug, Clone)]
pub struct MethodDebugInformationRaw {
    /// Row identifier within the MethodDebugInformation metadata table
    pub rid: u32,

    /// Metadata token for this method debug information entry
    pub token: Token,

    /// Byte offset of this entry within the metadata tables stream
    pub offset: usize,

    /// Document table index (unresolved)
    ///
    /// Simple index into the Document table that identifies the source document
    /// containing this method. A value of 0 indicates no associated document.
    pub document: u32,

    /// Sequence points blob index (unresolved)
    ///
    /// Index into the blob heap containing encoded sequence point data.
    /// A value of 0 indicates no sequence points are available for this method.
    /// The blob contains compressed sequence point information mapping IL
    /// instructions to source code locations.
    pub sequence_points: u32,
}

impl MethodDebugInformationRaw {
    /// Convert raw method debug information to owned representation with resolved heap references
    ///
    /// Resolves all heap indices to their actual data values, creating a
    /// [`MethodDebugInformation`] instance with owned data that provides immediate
    /// access to debug information without requiring additional heap lookups.
    ///
    /// # Arguments
    /// * `blobs` - Blob heap for resolving sequence points data
    ///
    /// # Returns
    /// * `Ok(Arc<MethodDebugInformation>)` - Reference-counted owned method debug info
    /// * `Err(Error)` - If heap resolution fails
    ///
    /// # Heap Resolution
    /// - `document`: Preserved as table index for later resolution during loading
    /// - `sequence_points`: Resolved to `Option<Vec<u8>>` (None if index is 0)
    ///
    /// # Examples
    /// ```rust,ignore
    /// # use dotscope::metadata::tables::MethodDebugInformationRaw;
    /// # use dotscope::metadata::streams::{Strings, Blob, Guid};
    /// # fn example(raw: &MethodDebugInformationRaw, strings: &Strings, blobs: &Blob, guids: &Guid) -> dotscope::Result<()> {
    /// let method_debug_info = raw.to_owned(strings, blobs, guids)?;
    /// println!("Method debug info: {:?}", method_debug_info.document);
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_owned(&self, blobs: &Blob) -> Result<MethodDebugInformationRc> {
        let sequence_points = if self.sequence_points == 0 {
            None
        } else {
            Some(blobs.get(self.sequence_points as usize)?.to_vec())
        };

        // ToDo: Resolve document index to actual Document entry if needed
        let method_debug_info = MethodDebugInformation {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            document: self.document,
            sequence_points,
        };

        Ok(Arc::new(method_debug_info))
    }
}

impl<'a> RowDefinition<'a> for MethodDebugInformationRaw {
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodDebugInformationRaw {
            rid,
            token: Token::new(0x3100_0000 + rid),
            offset: *offset,
            document: read_le_at_dyn(data, offset, sizes.is_large(TableId::Document))?,
            sequence_points: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.table_index_bytes(TableId::Document) + // document
            sizes.blob_bytes()  // sequence_points
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // document (2 bytes)
            0x02, 0x02, // sequence_points (2 bytes)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDebugInformation, 1), (TableId::Document, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodDebugInformationRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDebugInformationRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x31000001);
            assert_eq!(row.document, 0x0101);
            assert_eq!(row.sequence_points, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // document (4 bytes)
            0x02, 0x02, 0x02, 0x02, // sequence_points (4 bytes)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDebugInformation, 1),
                (TableId::Document, 100000),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodDebugInformationRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDebugInformationRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x31000001);
            assert_eq!(row.document, 0x01010101);
            assert_eq!(row.sequence_points, 0x02020202);
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
