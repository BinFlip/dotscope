//! Raw ImportScope table representation for Portable PDB format
//!
//! This module provides the [`ImportScopeRaw`] struct that represents
//! the binary format of ImportScope table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        importscope::{parse_imports_blob, ImportsInfo},
        streams::Blob,
        tables::{types::*, ImportScope, ImportScopeRc},
        token::Token,
    },
    Result,
};
use std::sync::Arc;

/// Raw binary representation of an ImportScope table entry
///
/// This structure matches the exact binary layout of ImportScope table
/// entries in the metadata tables stream. The Parent field contains an
/// unresolved index to another ImportScope entry, and the Imports field contains
/// an unresolved index into the #Blob heap that must be resolved during
/// conversion to the owned [`ImportScope`] variant.
///
/// # Binary Format
///
/// Each ImportScope table entry consists of:
/// - Parent: Index into ImportScope table for parent scope (may be 0)
/// - Imports: Index into #Blob heap for import information
#[derive(Debug, Clone)]
pub struct ImportScopeRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this ImportScope entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Index into ImportScope table for parent scope
    ///
    /// Points to the parent import scope that encloses this scope, or 0 if
    /// this is a root-level import scope. Import scopes form a tree structure
    /// where child scopes inherit imports from their parent scopes.
    pub parent: u32,

    /// Index into #Blob heap for import information
    ///
    /// Points to the binary blob containing the import data for this scope.
    /// The blob format contains the list of imported namespaces and types
    /// that are available within this lexical scope.
    pub imports: u32,
}

impl ImportScopeRaw {
    /// Converts this raw ImportScope entry to an owned [`ImportScope`] instance
    ///
    /// This method resolves the raw ImportScope entry to create a complete ImportScope
    /// object by resolving the imports blob data from the #Blob heap. The parent
    /// reference is kept as an index that can be resolved through the ImportScope table.
    ///
    /// # Parameters
    /// - `blobs`: Reference to the #Blob heap for resolving the imports index
    ///
    /// # Returns
    /// Returns `Ok(ImportScopeRc)` with the resolved import scope data, or an error if
    /// the imports index is invalid or points to malformed data.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use dotscope::metadata::tables::importscope::ImportScopeRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example() -> dotscope::Result<()> {
    /// let scope_raw = ImportScopeRaw {
    ///     rid: 1,
    ///     token: Token::new(0x35000001),
    ///     offset: 0,
    ///     parent: 0,          // Root scope
    ///     imports: 100,       // Index into #Blob heap
    /// };
    ///
    /// let scope = scope_raw.to_owned(blobs)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_owned(&self, blobs: &Blob) -> Result<ImportScopeRc> {
        let imports = if self.imports == 0 {
            ImportsInfo::new()
        } else {
            let blob_data = blobs.get(self.imports as usize)?;
            parse_imports_blob(blob_data, blobs)?
        };

        let scope = ImportScope {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent: self.parent,
            imports,
        };

        Ok(Arc::new(scope))
    }
}

impl<'a> RowDefinition<'a> for ImportScopeRaw {
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ImportScopeRaw {
            rid,
            token: Token::new(0x3500_0000 + rid),
            offset: *offset,
            parent: read_le_at_dyn(data, offset, sizes.is_large(TableId::ImportScope))?,
            imports: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.table_index_bytes(TableId::ImportScope) +   // parent (ImportScope table index)
            sizes.blob_bytes()                          // imports (blob heap index)
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
            0x00, 0x00, // parent (2 bytes, normal table) - 0x0000 (root scope)
            0x01, 0x00, // imports (2 bytes, short blob heap) - 0x0001
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ImportScope, 1)],
            false, // large strings
            false, // large blob
            false, // large GUID
        ));
        let table = MetadataTable::<ImportScopeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImportScopeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x35000001);
            assert_eq!(row.parent, 0x0000);
            assert_eq!(row.imports, 0x0001);
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
            0x02, 0x00, 0x00, 0x00, // parent (4 bytes, large table) - 0x00000002
            0x01, 0x00, // imports (2 bytes, normal blob heap) - 0x0001
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ImportScope, 70000)], // Large table triggers 4-byte indices
            false,                            // large strings
            false,                            // large blob
            false,                            // large GUID
        ));
        let table = MetadataTable::<ImportScopeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImportScopeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x35000001);
            assert_eq!(row.parent, 0x00000002);
            assert_eq!(row.imports, 0x0001);
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
