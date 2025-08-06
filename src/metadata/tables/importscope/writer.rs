//! Writer implementation for `ImportScope` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`ImportScopeRaw`] struct, enabling serialization of import scope information
//! rows back to binary format. This supports Portable PDB generation and
//! assembly modification scenarios where debug information needs to be preserved.
//!
//! # Binary Format
//!
//! Each `ImportScope` row consists of two fields:
//! - `parent` (2/4 bytes): Simple index into ImportScope table (0 = root scope)
//! - `imports` (2/4 bytes): Blob heap index for import information
//!
//! # Row Layout
//!
//! `ImportScope` table rows are serialized with this binary structure:
//! - Parent ImportScope index (2 or 4 bytes, depending on ImportScope table size)
//! - Imports blob index (2 or 4 bytes, depending on blob heap size)
//! - Total row size varies based on table and heap sizes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table and heap sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::importscope::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        importscope::ImportScopeRaw,
        types::{RowWritable, TableInfoRef},
        TableId,
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for ImportScopeRaw {
    /// Write an `ImportScope` table row to binary data
    ///
    /// Serializes one `ImportScope` table entry to the metadata tables stream format, handling
    /// variable-width table and blob heap indexes based on the table and heap size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this import scope entry (unused for `ImportScope`)
    /// * `sizes` - Table sizing information for writing table and heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized import scope row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Parent ImportScope index (2/4 bytes, little-endian, 0 = root scope)
    /// 2. Imports blob index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write parent ImportScope table index
        write_le_at_dyn(
            data,
            offset,
            self.parent,
            sizes.is_large(TableId::ImportScope),
        )?;

        // Write imports blob index
        write_le_at_dyn(data, offset, self.imports, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::types::{RowReadable, TableInfo, TableRow},
        metadata::token::Token,
    };

    #[test]
    fn test_round_trip_serialization_small_indices() {
        // Create test data with small table and heap indices
        let original_row = ImportScopeRaw {
            rid: 1,
            token: Token::new(0x3500_0001),
            offset: 0,
            parent: 0, // Root scope
            imports: 42,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::ImportScope, 100)], // Small ImportScope table
            false,                          // small string heap
            false,                          // small guid heap
            false,                          // small blob heap
        ));

        // Calculate buffer size and serialize
        let row_size = <ImportScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ImportScopeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.parent, deserialized_row.parent);
        assert_eq!(original_row.imports, deserialized_row.imports);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_indices() {
        // Create test data with large table and heap indices
        let original_row = ImportScopeRaw {
            rid: 2,
            token: Token::new(0x3500_0002),
            offset: 0,
            parent: 0x1BEEF,
            imports: 0x2CAFE,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::ImportScope, 100000)], // Large ImportScope table
            true,                                                       // large string heap
            true,                                                       // large guid heap
            true,                                                       // large blob heap
        ));

        // Calculate buffer size and serialize
        let row_size = <ImportScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ImportScopeRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.parent, deserialized_row.parent);
        assert_eq!(original_row.imports, deserialized_row.imports);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_indices() {
        // Test with specific binary layout for small indices
        let import_scope = ImportScopeRaw {
            rid: 1,
            token: Token::new(0x3500_0001),
            offset: 0,
            parent: 0x1234,
            imports: 0x5678,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::ImportScope, 100)],
            false,
            false,
            false,
        ));

        let row_size = ImportScopeRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        import_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes for small indices");

        // Parent ImportScope index (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Imports blob index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);
    }

    #[test]
    fn test_known_binary_format_large_indices() {
        // Test with specific binary layout for large indices
        let import_scope = ImportScopeRaw {
            rid: 1,
            token: Token::new(0x3500_0001),
            offset: 0,
            parent: 0x12345678,
            imports: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::ImportScope, 100000)],
            true,
            true,
            true,
        ));

        let row_size = ImportScopeRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        import_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes for large indices");

        // Parent ImportScope index (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // Imports blob index (0x9ABCDEF0) as little-endian
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);
    }

    #[test]
    fn test_root_scope() {
        // Test with root scope (parent = 0)
        let import_scope = ImportScopeRaw {
            rid: 1,
            token: Token::new(0x3500_0001),
            offset: 0,
            parent: 0, // Root scope
            imports: 100,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::ImportScope, 100)],
            false,
            false,
            false,
        ));

        let row_size = ImportScopeRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        import_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify that zero parent is preserved
        let mut read_offset = 0;
        let deserialized_row = ImportScopeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.parent, 0);
        assert_eq!(deserialized_row.imports, 100);
    }

    #[test]
    fn test_nested_scope_hierarchy() {
        // Test with nested scope (parent != 0)
        let test_cases = vec![
            (1, 100),  // Child scope with parent 1
            (5, 200),  // Another child scope with parent 5
            (10, 300), // Deep nested scope with parent 10
        ];

        for (parent, imports) in test_cases {
            let import_scope = ImportScopeRaw {
                rid: 1,
                token: Token::new(0x3500_0001),
                offset: 0,
                parent,
                imports,
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::ImportScope, 100)],
                false,
                false,
                false,
            ));

            let row_size = ImportScopeRaw::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            import_scope
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                ImportScopeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(deserialized_row.parent, parent);
            assert_eq!(deserialized_row.imports, imports);
        }
    }

    #[test]
    fn test_mixed_index_sizes() {
        // Test with mixed index sizes (large table, small blob)
        let import_scope = ImportScopeRaw {
            rid: 1,
            token: Token::new(0x3500_0001),
            offset: 0,
            parent: 0x12345678, // Large table index
            imports: 0x1234,    // Small blob index
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::ImportScope, 100000)],
            false,
            false,
            false,
        ));

        let row_size = ImportScopeRaw::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        import_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 6,
            "Row size should be 6 bytes for mixed index sizes"
        );

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ImportScopeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.parent, 0x12345678);
        assert_eq!(deserialized_row.imports, 0x1234);
    }
}
