//! Metadata table serialization for .NET assembly writing.
//!
//! This module provides comprehensive metadata table serialization capabilities for .NET assembly
//! binary generation, implementing efficient table writing using delegation to the RowWritable trait
//! implementations. It handles both complete table replacements and sparse modifications while
//! maintaining ECMA-335 compliance and proper table structure integrity.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::writers::table::TableWriter`] - Stateful writer for all metadata table operations
//! - [`crate::cilassembly::write::writers::table::TableWriter::write_all_tables`] - Complete table stream writing
//! - [`crate::cilassembly::write::writers::table::TableWriter::write_all_table_modifications`] - Selective table updates
//! - [`crate::cilassembly::write::writers::table::TableWriter::write_tables_stream_header`] - Metadata tables header writing
//! - [`crate::cilassembly::write::writers::table::TableWriter::write_table_replacement`] - Complete table replacement
//! - [`crate::cilassembly::write::writers::table::TableWriter::write_sparse_modifications`] - Individual row updates
//!
//! # Architecture
//!
//! The table writing system implements a comprehensive approach to metadata table serialization:
//!
//! ## Delegation Strategy
//! Uses [`crate::metadata::tables::RowWritable`] trait implementations for efficient serialization:
//! - Delegates to each table row's specific serialization logic
//! - Maintains proper ECMA-335 binary format compliance
//! - Handles variable-size fields and cross-table references
//! - Ensures correct endianness and alignment requirements
//!
//! ## Table Modification Support
//! Handles both replacement and sparse modification scenarios:
//! - **Complete Replacement**: Writes entirely new table content
//! - **Sparse Modifications**: Updates individual rows without full table rewrite
//! - **Row Count Updates**: Maintains accurate table header row counts
//! - **Offset Calculation**: Ensures proper table positioning within metadata stream
//!
//! ## Tables Stream Management
//! Manages the complete metadata tables stream structure:
//! - Writes ECMA-335 compliant tables stream header
//! - Calculates and updates row counts for modified tables
//! - Maintains proper table ordering and alignment
//! - Handles heap size flags based on heap expansions
//!
//! ## Type Safety and Context
//! Provides type-safe table operations with proper context:
//! - Encapsulates [`crate::metadata::tables::TableInfoRef`] for consistent serialization context
//! - Maintains [`crate::metadata::streams::TablesHeader`] reference for structure access
//! - Ensures proper RID (Row ID) management and validation
//! - Handles cross-table reference integrity
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::writers::table::TableWriter;
//! use crate::cilassembly::write::output::Output;
//! use crate::cilassembly::write::planner::LayoutPlan;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! # let layout_plan = LayoutPlan { // placeholder
//! #     total_size: 1000,
//! #     original_size: 800,
//! #     file_layout: crate::cilassembly::write::planner::FileLayout {
//! #         dos_header: crate::cilassembly::write::planner::FileRegion { offset: 0, size: 64 },
//! #         pe_headers: crate::cilassembly::write::planner::FileRegion { offset: 64, size: 100 },
//! #         section_table: crate::cilassembly::write::planner::FileRegion { offset: 164, size: 80 },
//! #         sections: vec![]
//! #     },
//! #     pe_updates: crate::cilassembly::write::planner::PeUpdates {
//! #         section_table_needs_update: false,
//! #         checksum_needs_update: false,
//! #         section_updates: vec![]
//! #     },
//! #     metadata_modifications: crate::cilassembly::write::planner::metadata::MetadataModifications {
//! #         stream_modifications: vec![],
//! #         root_needs_update: false
//! #     },
//! #     heap_expansions: crate::cilassembly::write::planner::calc::HeapExpansions {
//! #         string_heap_addition: 0,
//! #         blob_heap_addition: 0,
//! #         guid_heap_addition: 0,
//! #         userstring_heap_addition: 0
//! #     },
//! #     table_modifications: vec![]
//! # };
//! # let mut output = Output::new(1000)?;
//!
//! // Create table writer with necessary context
//! let mut table_writer = TableWriter::new(&assembly, &mut output, &layout_plan)?;
//!
//! // Write all table modifications
//! table_writer.write_all_table_modifications()?;
//!
//! println!("Table modifications written successfully");
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::write::writers::table::TableWriter`] is designed for single-threaded use during binary
//! generation. It maintains mutable state for output buffer management and is not thread-safe.
//! Each table writing operation should be completed atomically within a single thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning and table modification detection
//! - [`crate::cilassembly::write::output`] - Binary output buffer management
//! - [`crate::metadata::tables`] - Table structure definitions and serialization traits
//! - [`crate::cilassembly::changes`] - Source of table modification data

use crate::{
    cilassembly::{
        write::{
            output::Output,
            planner::{FileRegion, LayoutPlan, TableModificationRegion},
            utils::calculate_table_row_size,
        },
        CilAssembly, Operation, TableModifications, TableOperation,
    },
    dispatch_table_type,
    file::io::write_le_at,
    metadata::{
        streams::TablesHeader,
        tables::{
            MetadataTable, RowReadable, RowWritable, TableDataOwned, TableId, TableInfo,
            TableInfoRef,
        },
    },
    Error, Result,
};

/// A stateful writer for metadata tables that encapsulates all necessary context.
///
/// [`crate::cilassembly::write::writers::table::TableWriter`] provides a clean API for writing metadata tables by maintaining
/// references to the assembly, output buffer, layout plan, and table information.
/// This eliminates the need to pass these parameters around and provides a more
/// object-oriented interface for table serialization operations.
///
/// # Design Benefits
///
/// - **Encapsulation**: All writing context is stored in one place
/// - **Clean API**: Methods don't require numerous parameters
/// - **Type Safety**: [`crate::metadata::tables::TableInfoRef`] context is always available and correct
/// - **Maintainability**: Easier to extend and modify functionality
/// - **Performance**: Avoids repeated parameter passing and context lookup
/// - **Safety**: Centralized bounds checking and validation
///
/// # Usage
/// Created via [`crate::cilassembly::write::writers::table::TableWriter::new`] and used throughout
/// the table writing process to serialize metadata tables and modifications.
pub struct TableWriter<'a> {
    /// Reference to the [`crate::cilassembly::CilAssembly`] for table data access
    assembly: &'a CilAssembly,
    /// Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer for writing
    output: &'a mut Output,
    /// Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    layout_plan: &'a LayoutPlan,
    /// Cached reference to the [`crate::metadata::streams::TablesHeader`] for efficient access
    tables_header: &'a TablesHeader<'a>,
    /// Cached reference to the [`crate::metadata::tables::TableInfoRef`] for proper serialization context
    table_info: &'a TableInfoRef,
}

impl<'a> TableWriter<'a> {
    /// Helper method to calculate the size of the tables stream header.
    ///
    /// Calculates the total size of the ECMA-335 metadata tables stream header,
    /// which includes fixed fields (24 bytes) plus 4 bytes per present table.
    ///
    /// # Returns
    /// Returns the total header size in bytes.
    fn calculate_tables_header_size(&self) -> Result<usize> {
        let present_table_count = self.tables_header.valid.count_ones() as usize;
        Ok(24 + (present_table_count * 4))
    }

    /// Helper method to get the row size for a specific table.
    ///
    /// Delegates to [`crate::cilassembly::write::utils::calculate_table_row_size`] with the
    /// cached [`crate::metadata::tables::TableInfoRef`] for efficient row size calculation.
    ///
    /// # Arguments
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to calculate size for
    ///
    /// # Returns
    /// Returns the row size in bytes for the specified table type.
    fn get_table_row_size(&self, table_id: TableId) -> u32 {
        calculate_table_row_size(table_id, self.table_info)
    }

    /// Creates a new [`crate::cilassembly::write::writers::table::TableWriter`] with the necessary context.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing table data
    /// * `output` - Mutable reference to the [`crate::cilassembly::write::output::Output`] buffer
    /// * `layout_plan` - Reference to the [`crate::cilassembly::write::planner::LayoutPlan`] for offset calculations
    ///
    /// # Returns
    ///
    /// Returns a [`crate::cilassembly::write::writers::table::TableWriter`] instance or an error if the assembly lacks metadata tables.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMissingMetadata`] if no metadata tables are found in the assembly.
    pub fn new(
        assembly: &'a CilAssembly,
        output: &'a mut Output,
        layout_plan: &'a LayoutPlan,
    ) -> Result<Self> {
        let tables_header = assembly
            .view
            .tables()
            .ok_or_else(|| Error::WriteMissingMetadata {
                message: "No metadata tables found in original assembly".to_string(),
            })?;

        let table_info = &tables_header.info;

        Ok(Self {
            assembly,
            output,
            layout_plan,
            tables_header,
            table_info,
        })
    }

    /// Writes all metadata tables to the output file.
    ///
    /// This method writes the complete metadata tables stream including:
    /// 1. Tables stream header with metadata and row counts via [`crate::cilassembly::write::writers::table::TableWriter::write_tables_stream_header`]
    /// 2. All present tables in the correct order via [`crate::cilassembly::write::writers::table::TableWriter::write_table_by_id`]
    ///
    /// # Errors
    /// Returns [`crate::Error`] if table writing fails due to invalid structure or
    /// insufficient output buffer space.
    pub fn write_all_tables(&mut self) -> Result<()> {
        // Get the base offset for the tables stream in the output file
        // For now, we'll use a placeholder offset and update this when the method is available
        let tables_stream_offset = self.layout_plan.tables_stream_offset(self.assembly)?;

        // Write the tables stream header first
        let header_size = self.write_tables_stream_header(tables_stream_offset)?;

        // Calculate the offset where table data begins (after the header)
        let mut current_table_offset = tables_stream_offset + header_size as u64;

        // Write each present table in order
        for table_id in self.tables_header.present_tables() {
            let table_size = self.write_table_by_id(table_id, current_table_offset)?;
            current_table_offset += table_size;
        }

        Ok(())
    }

    /// Writes all table modifications from the layout plan.
    ///
    /// This method handles all table modifications internally by iterating through
    /// the [`crate::cilassembly::write::planner::LayoutPlan::table_modifications`] and applying each one.
    /// It first updates table header row counts, then applies individual modifications.
    ///
    /// # Process
    /// 1. Updates table header row counts via [`crate::cilassembly::write::writers::table::TableWriter::update_table_header_row_counts`]
    /// 2. Calculates table offsets with updated row counts
    /// 3. Applies modifications via [`crate::cilassembly::write::writers::table::TableWriter::write_single_table_modification`]
    ///
    /// # Errors
    /// Returns [`crate::Error`] if table modifications fail due to invalid data or offsets.
    pub fn write_all_table_modifications(&mut self) -> Result<()> {
        // First, we need to calculate the actual table offsets
        let tables_stream_offset = self.layout_plan.tables_stream_offset(self.assembly)?;
        let header_size = self.calculate_tables_header_size()?;

        // Update the table header with new row counts FIRST
        self.update_table_header_row_counts(tables_stream_offset)?;

        // Build a map of table offsets using UPDATED row counts
        let mut table_offsets = std::collections::HashMap::new();
        let mut current_offset = tables_stream_offset + header_size as u64;

        for table_id in self.tables_header.present_tables() {
            // Use updated row counts if table has been modified
            let mut row_count = self.tables_header.table_row_count(table_id);
            if let Some(table_mod) = self.assembly.changes().get_table_modifications(table_id) {
                match table_mod {
                    TableModifications::Replaced(new_rows) => {
                        row_count = new_rows.len() as u32;
                    }
                    TableModifications::Sparse { operations, .. } => {
                        let inserts = operations
                            .iter()
                            .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                            .count();
                        row_count += inserts as u32;
                    }
                }
            }

            let row_size = self.get_table_row_size(table_id);
            let table_size = row_count as u64 * row_size as u64;

            let table_region = FileRegion::new(current_offset, table_size);
            table_offsets.insert(table_id, table_region.offset);
            current_offset = table_region.end_offset();
        }

        // Now apply modifications with correct offsets
        for table_modification in self.layout_plan.table_modifications.iter() {
            let actual_offset =
                table_offsets
                    .get(&table_modification.table_id)
                    .ok_or_else(|| Error::WriteInternalError {
                        message: format!(
                            "Table {:?} not found in present tables",
                            table_modification.table_id
                        ),
                    })?;

            // Create a modified table modification with the correct offset
            let mut corrected_modification = table_modification.clone();
            corrected_modification.original_offset = *actual_offset;

            self.write_single_table_modification(&corrected_modification)?;
        }

        Ok(())
    }

    /// Writes table modifications for a specific table.
    ///
    /// Dispatches to appropriate modification handlers based on the type of
    /// [`crate::cilassembly::TableModifications`] (Replaced or Sparse).
    ///
    /// # Arguments
    /// * `table_modification` - The specific [`crate::cilassembly::write::planner::TableModificationRegion`] to apply
    fn write_single_table_modification(
        &mut self,
        table_modification: &TableModificationRegion,
    ) -> Result<()> {
        let table_id = table_modification.table_id;
        let changes = self.assembly.changes();

        if let Some(table_mod) = changes.get_table_modifications(table_id) {
            match table_mod {
                TableModifications::Replaced(new_rows) => {
                    self.write_table_replacement(table_modification, new_rows)?;
                }
                TableModifications::Sparse { operations, .. } => {
                    self.write_sparse_modifications(table_modification, operations)?;
                }
            }
        }

        Ok(())
    }

    /// Updates the table header row counts in place to reflect modifications.
    ///
    /// This method updates the row count fields in the table header that was copied
    /// from the original assembly to include the new row counts after modifications.
    /// The row counts are updated directly in the output buffer.
    ///
    /// # Arguments
    /// * `tables_stream_offset` - Absolute file offset of the tables stream start
    ///
    /// # Errors
    /// Returns [`crate::Error`] if row count updates fail due to buffer access issues.
    fn update_table_header_row_counts(&mut self, tables_stream_offset: u64) -> Result<()> {
        // Calculate the offset where row counts start in the header
        // Header format: Reserved(4) + Version(2) + HeapSizes(1) + Reserved(1) + Valid(8) + Sorted(8) = 24 bytes
        let row_counts_offset = tables_stream_offset + 24;
        let mut current_offset = row_counts_offset;

        // Update row count for each present table
        for table_id in self.tables_header.present_tables() {
            let mut row_count = self.tables_header.table_row_count(table_id);

            // Check if this table has been modified and update the count
            if let Some(table_mod) = self.assembly.changes().get_table_modifications(table_id) {
                match table_mod {
                    TableModifications::Replaced(new_rows) => {
                        row_count = new_rows.len() as u32;
                    }
                    TableModifications::Sparse { operations, .. } => {
                        // Count insert operations to get the new total
                        let inserts = operations
                            .iter()
                            .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                            .count();
                        row_count += inserts as u32;
                    }
                }

                // Write the updated row count
                self.output.write_u32_le_at(current_offset, row_count)?;
            }

            // Move to next row count field (4 bytes per table)
            current_offset += 4;
        }

        Ok(())
    }

    /// Writes the metadata tables stream header and returns its size.
    ///
    /// Writes the complete ECMA-335 II.24.2.6 tables stream header with updated
    /// row counts for modified tables. Uses [`crate::file::io::write_le_at`] for
    /// consistent endianness handling.
    ///
    /// # Header Format (ECMA-335 II.24.2.6)
    /// - Reserved (4 bytes): 0x00000000
    /// - MajorVersion (1 byte): 2
    /// - MinorVersion (1 byte): 0
    /// - HeapSizes (1 byte): flags indicating heap index sizes
    /// - Reserved (1 byte): 0x01
    /// - Valid (8 bytes): bitmask of present tables
    /// - Sorted (8 bytes): bitmask of sorted tables
    /// - Rows (4*N bytes): row count for each present table
    ///
    /// # Arguments
    /// * `offset` - Absolute file offset where the header should be written
    ///
    /// # Returns
    /// Returns the total size of the written header in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if header writing fails due to buffer access issues.
    fn write_tables_stream_header(&mut self, offset: u64) -> Result<usize> {
        // Calculate header size: 24 bytes fixed + 4 bytes per present table
        let present_table_count = self.tables_header.valid.count_ones() as usize;
        let header_size = 24 + (present_table_count * 4);

        // Get mutable slice for the header
        let header_slice = self.output.get_mut_slice(offset as usize, header_size)?;
        let mut pos = 0;

        // Write header fields using project's IO functions
        // Reserved (4 bytes)
        write_le_at(header_slice, &mut pos, 0u32)?;

        // Major version (1 byte)
        write_le_at(header_slice, &mut pos, self.tables_header.major_version)?;

        // Minor version (1 byte)
        write_le_at(header_slice, &mut pos, self.tables_header.minor_version)?;

        // Heap sizes (1 byte) - calculate from table_info directly
        let heap_sizes = Self::calculate_heap_sizes(self.table_info);
        write_le_at(header_slice, &mut pos, heap_sizes)?;

        // Reserved (1 byte)
        write_le_at(header_slice, &mut pos, 0x01u8)?;

        // Valid tables mask (8 bytes)
        write_le_at(header_slice, &mut pos, self.tables_header.valid)?;

        // Sorted tables mask (8 bytes)
        write_le_at(header_slice, &mut pos, self.tables_header.sorted)?;

        // Row counts for each present table (4 bytes each)
        for table_id in self.tables_header.present_tables() {
            let mut row_count = self.tables_header.table_row_count(table_id);

            // Check if this table has been modified and update the count
            if let Some(table_mod) = self.assembly.changes().get_table_modifications(table_id) {
                match table_mod {
                    TableModifications::Replaced(new_rows) => {
                        row_count = new_rows.len() as u32;
                    }
                    TableModifications::Sparse { operations, .. } => {
                        // Count insert operations to get the new total
                        let inserts = operations
                            .iter()
                            .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                            .count();
                        row_count += inserts as u32;
                    }
                }
            }

            write_le_at(header_slice, &mut pos, row_count)?;
        }

        Ok(header_size)
    }

    /// Calculates the heap sizes byte based on the table info.
    ///
    /// Generates the HeapSizes field for the tables stream header by examining
    /// the [`crate::metadata::tables::TableInfo`] to determine which heaps require
    /// 4-byte indices due to size thresholds.
    ///
    /// # Bit Layout
    /// - Bit 0: String heap uses 4-byte indices
    /// - Bit 1: GUID heap uses 4-byte indices  
    /// - Bit 2: Blob heap uses 4-byte indices
    ///
    /// # Arguments
    /// * `table_info` - The [`crate::metadata::tables::TableInfo`] containing heap size information
    ///
    /// # Returns
    /// Returns the heap sizes byte with appropriate flags set.
    fn calculate_heap_sizes(table_info: &TableInfo) -> u8 {
        let mut heap_sizes = 0u8;

        if table_info.is_large_str() {
            heap_sizes |= 0x01;
        }

        if table_info.is_large_guid() {
            heap_sizes |= 0x02;
        }

        if table_info.is_large_blob() {
            heap_sizes |= 0x04;
        }

        heap_sizes
    }

    /// Writes a specific table by its ID and returns the size written.
    ///
    /// Uses a macro-based dispatch to the appropriate typed table writing method
    /// based on the [`crate::metadata::tables::TableId`]. Delegates to
    /// [`crate::cilassembly::write::writers::table::TableWriter::write_typed_table`] for actual serialization.
    ///
    /// # Arguments
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to write
    /// * `table_offset` - Absolute file offset where the table should be written
    ///
    /// # Returns
    /// Returns the total size of the written table in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if table writing fails.
    fn write_table_by_id(&mut self, table_id: TableId, table_offset: u64) -> Result<u64> {
        dispatch_table_type!(table_id, |RawType| {
            if let Some(table) = self.tables_header.table::<RawType>() {
                self.write_typed_table(table, table_offset)
            } else {
                Ok(0)
            }
        })
    }

    /// Writes a typed metadata table by delegating to each row's [`crate::metadata::tables::RowWritable`] implementation.
    ///
    /// Serializes all rows of a specific table type using the [`crate::metadata::tables::RowWritable::row_write`]
    /// trait method. Maintains proper RID (Row ID) assignment for cross-table references.
    ///
    /// # Type Parameters
    /// * `T` - Table row type implementing [`crate::metadata::tables::RowReadable`], [`crate::metadata::tables::RowWritable`], and [`Clone`]
    ///
    /// # Arguments
    /// * `table` - The [`crate::metadata::tables::MetadataTable`] containing rows to serialize
    /// * `table_offset` - Absolute file offset where the table should be written
    ///
    /// # Returns
    /// Returns the total size of the written table in bytes.
    fn write_typed_table<T>(&mut self, table: &MetadataTable<T>, table_offset: u64) -> Result<u64>
    where
        T: RowReadable + RowWritable + Clone,
    {
        let row_size = T::row_size(self.table_info) as u64;
        let table_size = table.row_count as u64 * row_size;

        if table_size == 0 {
            return Ok(0);
        }

        // Get mutable slice for the entire table
        let table_slice = self
            .output
            .get_mut_slice(table_offset as usize, table_size as usize)?;

        // Serialize each row by delegating to the row's RowWritable implementation
        let mut current_offset = 0;
        for (row_index, row) in table.iter().enumerate() {
            let rid = (row_index + 1) as u32; // RIDs are 1-based
            row.row_write(table_slice, &mut current_offset, rid, self.table_info)?;
        }

        Ok(table_size)
    }

    /// Writes a complete table replacement by delegating to owned struct serialization.
    ///
    /// Handles [`crate::cilassembly::TableModifications::Replaced`] scenarios by writing
    /// entirely new table content using [`crate::metadata::tables::TableDataOwned::row_write`].
    ///
    /// # Arguments
    /// * `table_modification` - The [`crate::cilassembly::write::planner::TableModificationRegion`] containing offset information
    /// * `new_rows` - Array of [`crate::metadata::tables::TableDataOwned`] representing the new table content
    fn write_table_replacement(
        &mut self,
        table_modification: &TableModificationRegion,
        new_rows: &[TableDataOwned],
    ) -> Result<()> {
        // ToDo: Verify in CilAssembly, that a table_replacement contains only rows of the same type
        let table_offset = table_modification.original_offset;

        let total_size: u64 = new_rows
            .iter()
            .map(|row| row.calculate_row_size(self.table_info) as u64)
            .sum();

        if total_size == 0 {
            return Ok(());
        }

        let table_slice = self
            .output
            .get_mut_slice(table_offset as usize, total_size as usize)?;

        let mut current_offset = 0;
        for (row_index, row_data) in new_rows.iter().enumerate() {
            let rid = (row_index + 1) as u32; // RIDs are 1-based
            row_data.row_write(table_slice, &mut current_offset, rid, self.table_info)?;
        }

        Ok(())
    }

    /// Writes sparse table modifications by delegating to owned struct serialization.
    ///
    /// Handles [`crate::cilassembly::TableModifications::Sparse`] scenarios by applying
    /// individual [`crate::cilassembly::TableOperation`] updates without rewriting the entire table.
    ///
    /// # Arguments
    /// * `table_modification` - The [`crate::cilassembly::write::planner::TableModificationRegion`] containing offset information
    /// * `operations` - Array of [`crate::cilassembly::TableOperation`] to apply to the table
    fn write_sparse_modifications(
        &mut self,
        table_modification: &TableModificationRegion,
        operations: &[TableOperation],
    ) -> Result<()> {
        let table_offset = table_modification.original_offset;

        for operation in operations {
            match &operation.operation {
                Operation::Insert(rid, row_data) | Operation::Update(rid, row_data) => {
                    let row_size = row_data.calculate_row_size(self.table_info) as u64;
                    let row_offset = table_offset + ((*rid - 1) as u64 * row_size);

                    let row_slice = self
                        .output
                        .get_mut_slice(row_offset as usize, row_size as usize)?;
                    let mut write_offset = 0;

                    row_data.row_write(row_slice, &mut write_offset, *rid, self.table_info)?;
                }
                Operation::Delete(_rid) => {
                    // Delete operations in metadata tables are typically handled by
                    // omitting the row from the new table rather than marking as deleted
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heap_sizes_calculation() {
        // Test with all 2-byte indices
        let table_info = TableInfo::new_test(&[], false, false, false);
        assert_eq!(TableWriter::calculate_heap_sizes(&table_info), 0x00);

        // Test with all 4-byte indices
        let table_info = TableInfo::new_test(&[], true, true, true);
        assert_eq!(TableWriter::calculate_heap_sizes(&table_info), 0x07);
    }
}
