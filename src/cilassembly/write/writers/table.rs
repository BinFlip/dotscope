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
//! - [`crate::cilassembly::write::writers::table::TableWriter::write_all_table_modifications`] - Systematic table rebuilding
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
        remapping::RidRemapper,
        write::{output::Output, planner::LayoutPlan, utils::calculate_table_row_size},
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
use std::collections::HashMap;

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

    /// Systematically rebuilds the complete tables stream when any modifications exist.
    ///
    /// This method implements a simplified approach that eliminates complex selective
    /// modification logic by systematically rebuilding the entire tables stream, ensuring
    /// complete consistency between modified and unmodified tables.
    ///
    /// # Process
    /// 1. Rebuilds complete tables stream header with updated row counts
    /// 2. Systematically writes ALL tables (both modified and unmodified)
    /// 3. Applies modifications while preserving unmodified table data
    ///
    /// # Errors
    /// Returns [`crate::Error`] if table writing fails due to invalid data or offsets.
    pub fn write_all_table_modifications(&mut self) -> Result<()> {
        let tables_stream_offset = self.layout_plan.tables_stream_offset(self.assembly)?;

        // Step 1: Write the complete tables stream header with updated row counts
        self.write_complete_tables_stream_header(tables_stream_offset)?;

        // Step 2: Systematically write ALL tables (both modified and unmodified)
        self.write_all_tables_systematically(tables_stream_offset)?;

        Ok(())
    }

    /// Writes the complete tables stream header with updated row counts for all tables.
    ///
    /// This function systematically rebuilds the entire tables stream header, ensuring
    /// that all row counts are accurate and the header structure is consistent.
    fn write_complete_tables_stream_header(&mut self, tables_stream_offset: u64) -> Result<()> {
        let mut updated_row_counts = std::collections::HashMap::new();

        for table_id in self.tables_header.present_tables() {
            let mut row_count = self.tables_header.table_row_count(table_id);

            // Apply modifications to get final row count
            if let Some(table_mod) = self.assembly.changes().get_table_modifications(table_id) {
                match table_mod {
                    TableModifications::Replaced(new_rows) => {
                        row_count = u32::try_from(new_rows.len()).map_err(|_| {
                            Error::WriteLayoutFailed {
                                message: "New table row count exceeds u32 range".to_string(),
                            }
                        })?;
                    }
                    TableModifications::Sparse { operations, .. } => {
                        let original_row_count = self.tables_header.table_row_count(table_id);
                        let remapper =
                            RidRemapper::build_from_operations(operations, original_row_count);
                        row_count = remapper.final_row_count();
                    }
                }
            }

            updated_row_counts.insert(table_id, row_count);
        }

        // Write the tables stream header with all updated row counts
        self.write_tables_stream_header_with_counts(tables_stream_offset, &updated_row_counts)?;

        Ok(())
    }

    /// Systematically writes ALL tables to ensure complete consistency.
    ///
    /// This function rebuilds the entire table data section, writing both modified
    /// and unmodified tables to their correct positions. This eliminates any gaps
    /// or inconsistencies that could occur with selective modification approaches.
    fn write_all_tables_systematically(&mut self, tables_stream_offset: u64) -> Result<()> {
        let header_size = self.calculate_tables_header_size()?;
        let mut current_offset = tables_stream_offset + header_size as u64;

        // Process each table systematically
        for table_id in self.tables_header.present_tables() {
            let row_size = self.get_table_row_size(table_id);

            // Check if this table has modifications
            if let Some(table_mod) = self.assembly.changes().get_table_modifications(table_id) {
                // Table has modifications - write modified version
                let table_size = match table_mod {
                    TableModifications::Replaced(new_rows) => {
                        // Write complete replacement
                        self.write_replaced_table_at_offset(new_rows, current_offset)?;
                        u64::try_from(new_rows.len()).map_err(|_| Error::WriteTableFailed {
                            message: "New rows count exceeds u64 range".to_string(),
                        })? * u64::from(row_size)
                    }
                    TableModifications::Sparse { operations, .. } => {
                        // Apply sparse modifications to original table data
                        self.write_table_with_sparse_modifications(
                            table_id,
                            operations,
                            current_offset,
                        )?
                    }
                };
                current_offset += table_size;
            } else {
                // Table has no modifications - copy original table data completely
                let original_row_count = self.tables_header.table_row_count(table_id);
                let table_size = u64::from(original_row_count) * u64::from(row_size);

                if table_size > 0 {
                    self.write_table_by_id(table_id, current_offset)?;
                }
                current_offset += table_size;
            }
        }

        Ok(())
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
        let row_size = u64::from(T::row_size(self.table_info));
        let table_size = u64::from(table.row_count) * row_size;

        if table_size == 0 {
            return Ok(0);
        }

        // Get mutable slice for the entire table
        let table_slice = self.output.get_mut_slice(
            usize::try_from(table_offset).map_err(|_| Error::WriteLayoutFailed {
                message: "Table offset exceeds usize range".to_string(),
            })?,
            usize::try_from(table_size).map_err(|_| Error::WriteLayoutFailed {
                message: "Table size exceeds usize range".to_string(),
            })?,
        )?;

        // Serialize each row by delegating to the row's RowWritable implementation
        let mut current_offset = 0;
        for (row_index, row) in table.iter().enumerate() {
            let rid = u32::try_from(row_index + 1).map_err(|_| Error::WriteLayoutFailed {
                message: "Row index exceeds u32 range".to_string(),
            })?; // RIDs are 1-based
            row.row_write(table_slice, &mut current_offset, rid, self.table_info)?;
        }

        Ok(table_size)
    }

    /// Writes the tables stream header with specified row counts.
    ///
    /// This is a variant of `write_tables_stream_header` that allows specifying
    /// custom row counts for each table, used by the systematic rebuild approach.
    fn write_tables_stream_header_with_counts(
        &mut self,
        offset: u64,
        row_counts: &std::collections::HashMap<TableId, u32>,
    ) -> Result<usize> {
        // Calculate header size: 24 bytes fixed + 4 bytes per present table
        let present_table_count = self.tables_header.valid.count_ones() as usize;
        let header_size = 24 + (present_table_count * 4);

        // Get mutable slice for the header
        let header_slice = self.output.get_mut_slice(
            usize::try_from(offset).map_err(|_| Error::WriteLayoutFailed {
                message: "Header offset exceeds usize range".to_string(),
            })?,
            header_size,
        )?;
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

        // Write row counts for each present table using updated counts
        for table_id in self.tables_header.present_tables() {
            let row_count = row_counts
                .get(&table_id)
                .copied()
                .unwrap_or_else(|| self.tables_header.table_row_count(table_id));
            write_le_at(header_slice, &mut pos, row_count)?;
        }

        Ok(header_size)
    }

    /// Writes a complete table replacement at the specified offset.
    ///
    /// Used by the systematic rebuild approach to write replaced tables.
    fn write_replaced_table_at_offset(
        &mut self,
        new_rows: &[TableDataOwned],
        offset: u64,
    ) -> Result<()> {
        let total_size: u64 = new_rows
            .iter()
            .map(|row| u64::from(row.calculate_row_size(self.table_info)))
            .sum();

        if total_size == 0 {
            return Ok(());
        }

        let table_slice = self.output.get_mut_slice(
            usize::try_from(offset).map_err(|_| Error::WriteLayoutFailed {
                message: "Table offset exceeds usize range".to_string(),
            })?,
            usize::try_from(total_size).map_err(|_| Error::WriteLayoutFailed {
                message: "Table size exceeds usize range".to_string(),
            })?,
        )?;

        let mut current_offset = 0;
        for (index, row) in new_rows.iter().enumerate() {
            let rid = u32::try_from(index + 1).map_err(|_| Error::WriteLayoutFailed {
                message: "Row index exceeds u32 range".to_string(),
            })?; // RIDs are 1-based
            row.row_write(table_slice, &mut current_offset, rid, self.table_info)?;
        }

        Ok(())
    }

    /// Writes a table with sparse modifications applied to original data.
    ///
    /// Used by the systematic rebuild approach to handle sparse modifications.
    /// This implementation uses RID remapping to create sequential, gap-free
    /// RID assignments while properly handling row deletions.
    fn write_table_with_sparse_modifications(
        &mut self,
        table_id: TableId,
        operations: &[TableOperation],
        offset: u64,
    ) -> Result<u64> {
        let original_row_count = self.tables_header.table_row_count(table_id);
        let row_size = u64::from(self.get_table_row_size(table_id));
        let remapper = RidRemapper::build_from_operations(operations, original_row_count);
        let final_row_count = remapper.final_row_count();
        let final_table_size = u64::from(final_row_count) * row_size;

        if final_row_count == 0 {
            return Ok(0);
        }

        // Create operation data map for quick lookup
        let mut operation_data: HashMap<u32, TableDataOwned> = HashMap::new();
        for operation in operations {
            match &operation.operation {
                Operation::Insert(rid, row_data) | Operation::Update(rid, row_data) => {
                    operation_data.insert(*rid, row_data.clone());
                }
                Operation::Delete(_) => {
                    // Deletions are handled by the remapper
                }
            }
        }

        dispatch_table_type!(table_id, |RawType| {
            let original_table = self.tables_header.table::<RawType>();

            for final_rid in 1..=final_row_count {
                if let Some(original_rid) = remapper.reverse_lookup(final_rid) {
                    let row_offset = offset + (u64::from(final_rid - 1) * row_size);
                    let row_slice = self.output.get_mut_slice(
                        usize::try_from(row_offset).map_err(|_| Error::WriteLayoutFailed {
                            message: "Row offset exceeds usize range".to_string(),
                        })?,
                        usize::try_from(row_size).map_err(|_| Error::WriteLayoutFailed {
                            message: "Row size exceeds usize range".to_string(),
                        })?,
                    )?;
                    let mut write_offset = 0;

                    if let Some(modified_data) = operation_data.get(&original_rid) {
                        modified_data.row_write(
                            row_slice,
                            &mut write_offset,
                            final_rid,
                            self.table_info,
                        )?;
                    } else if let Some(original_table) = original_table {
                        if let Some(original_row) = original_table.get(original_rid) {
                            original_row.row_write(
                                row_slice,
                                &mut write_offset,
                                final_rid,
                                self.table_info,
                            )?;
                        } else {
                            return Err(Error::Error(format!(
                                "Cannot read original row {original_rid} from table {table_id:?}"
                            )));
                        }
                    } else {
                        return Err(Error::Error(format!(
                            "Original table {table_id:?} not found during sparse modification writing"
                        )));
                    }
                }
            }

            Ok(final_table_size)
        })
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
