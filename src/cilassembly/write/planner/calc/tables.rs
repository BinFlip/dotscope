//! Table size calculation functions for metadata table modifications.
//!
//! This module provides specialized size calculation logic for metadata table modifications,
//! implementing exact ECMA-335 specification requirements for table expansion and row counting.
//! It handles both complete table replacements and sparse operations to determine accurate
//! space requirements for the metadata tables stream.
//!
//! # Key Components
//!
//! - [`calculate_table_stream_expansion`] - Calculates additional bytes needed for tables stream expansion
//! - [`calculate_new_row_count`] - Determines final row count after modifications
//!
//! # Architecture
//!
//! The table size calculation system handles two types of table modifications:
//!
//! ## Complete Table Replacement
//! When a table is completely replaced, the calculation is straightforward:
//! - Compare new row count with original row count
//! - Calculate additional space needed for extra rows
//! - Handle table shrinking (no additional space needed)
//!
//! ## Sparse Operations
//! When tables are modified through individual operations:
//! - Count insert operations for additional rows
//! - Account for delete operations reducing row count
//! - Handle update operations (no row count change)
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::calc::tables::{
//!     calculate_table_stream_expansion, calculate_new_row_count
//! };
//! use crate::cilassembly::CilAssembly;
//! use crate::metadata::tables::TableId;
//!
//! # let assembly = CilAssembly::new(view);
//! // Calculate total expansion needed for all modified tables
//! let total_expansion = calculate_table_stream_expansion(&assembly)?;
//! println!("Tables stream needs {} additional bytes", total_expansion);
//!
//! // Calculate new row count for a specific table
//! // if let Some(table_mod) = assembly.changes().get_table_modifications(TableId::TypeDef) {
//! //     let new_count = calculate_new_row_count(&assembly, TableId::TypeDef, table_mod)?;
//! //     println!("TypeDef table will have {} rows after modifications", new_count);
//! // }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are [`Send`] and [`Sync`] as they perform pure calculations
//! on immutable data without maintaining any mutable state.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Main layout planning coordination
//! - [`crate::cilassembly::write::utils`] - Table row size calculation utilities
//! - [`crate::cilassembly::changes`] - Table modification tracking
//! - [`crate::metadata::tables`] - Table schema and metadata information

use crate::{
    cilassembly::{
        write::utils::calculate_table_row_size, CilAssembly, Operation, TableModifications,
    },
    metadata::tables::TableId,
    Error, Result,
};

/// Calculates the additional bytes needed for the tables stream due to table modifications.
///
/// This function analyzes all table modifications to determine how much additional space
/// is needed in the tables stream. It accounts for both sparse operations and complete
/// table replacements, calculating the exact byte requirements for ECMA-335 compliance.
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing table modifications
///
/// # Returns
///
/// Returns the total additional bytes needed for the tables stream as a [`u64`].
///
/// # Errors
///
/// Returns [`crate::Error::WriteLayoutFailed`] if table information is unavailable or
/// if there are issues accessing table schema information.
///
/// # Algorithm
///
/// 1. **Modification Analysis**: Examine all modified tables in the assembly
/// 2. **Row Size Calculation**: Determine byte size per row for each table type
/// 3. **Expansion Calculation**: Calculate additional rows needed for each table
/// 4. **Size Aggregation**: Sum total additional bytes across all modified tables
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::calc::tables::calculate_table_stream_expansion;
/// use crate::cilassembly::CilAssembly;
///
/// # let assembly = CilAssembly::new(view);
/// // Calculate total expansion needed
/// let expansion = calculate_table_stream_expansion(&assembly)?;
/// if expansion > 0 {
///     println!("Tables stream needs {} additional bytes", expansion);
/// } else {
///     println!("No table stream expansion needed");
/// }
/// # Ok::<(), crate::Error>(())
/// ```
pub fn calculate_table_stream_expansion(assembly: &CilAssembly) -> Result<u64> {
    let changes = assembly.changes();
    let view = assembly.view();

    let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
        message: "No tables found in assembly for expansion calculation".to_string(),
    })?;

    let mut total_expansion = 0u64;

    // Calculate expansion for each modified table
    for table_id in changes.modified_tables() {
        if let Some(table_mod) = changes.get_table_modifications(table_id) {
            let row_size = calculate_table_row_size(table_id, &tables.info);

            let additional_rows = match table_mod {
                TableModifications::Replaced(new_rows) => {
                    let original_count = tables.table_row_count(table_id);
                    if new_rows.len() as u32 > original_count {
                        new_rows.len() as u32 - original_count
                    } else {
                        0 // Table shrunk or stayed same size
                    }
                }
                TableModifications::Sparse { operations, .. } => {
                    // Count insert operations
                    operations
                        .iter()
                        .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                        .count() as u32
                }
            };

            let expansion_bytes = additional_rows as u64 * row_size as u64;
            total_expansion += expansion_bytes;
        }
    }

    Ok(total_expansion)
}

/// Calculates the new row count for a table after modifications.
///
/// This function determines the final number of rows in a table after applying
/// all modifications, handling both replacement and sparse modification patterns.
/// It provides accurate row counts for layout planning and size calculations.
///
/// # Arguments
///
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for accessing original table data
/// * `table_id` - The [`crate::metadata::tables::TableId`] to calculate row count for
/// * `table_mod` - The [`crate::cilassembly::TableModifications`] to apply to the table
///
/// # Returns
///
/// Returns the final row count after all modifications are applied as a [`u32`].
///
/// # Errors
///
/// Returns [`crate::Error::WriteLayoutFailed`] if table information is unavailable or
/// if there are issues accessing the original table data.
///
/// # Implementation Notes
///
/// ## Complete Replacement
/// For complete table replacements, the calculation is straightforward - simply
/// return the length of the replacement table.
///
/// ## Sparse Operations
/// For sparse modifications, this uses a simplified calculation that counts insert
/// and delete operations. This may not account for complex operation interactions
/// such as insert followed by delete on the same RID. Production code should use
/// proper operation sequence processing for accuracy.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::cilassembly::write::planner::calc::tables::calculate_new_row_count;
/// use crate::cilassembly::{CilAssembly, TableModifications};
/// use crate::metadata::tables::TableId;
///
/// # let assembly = CilAssembly::new(view);
/// # let table_mod = TableModifications::Sparse { operations: vec![], original_count: 10 };
/// // Calculate new row count for TypeDef table
/// let new_count = calculate_new_row_count(&assembly, TableId::TypeDef, &table_mod)?;
/// println!("TypeDef table will have {} rows after modifications", new_count);
/// # Ok::<(), crate::Error>(())
/// ```
pub fn calculate_new_row_count(
    assembly: &CilAssembly,
    table_id: TableId,
    table_mod: &TableModifications,
) -> Result<u32> {
    match table_mod {
        TableModifications::Replaced(rows) => Ok(rows.len() as u32),
        TableModifications::Sparse { operations, .. } => {
            // Calculate final row count after all operations
            let view = assembly.view();
            let tables = view.tables().ok_or_else(|| Error::WriteLayoutFailed {
                message: "No tables found".to_string(),
            })?;
            let original_count = tables.table_row_count(table_id);

            // This is a simplified calculation - in a real implementation,
            // we'd need to process all operations to get the final count
            let added_count = operations
                .iter()
                .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                .count();

            let deleted_count = operations
                .iter()
                .filter(|op| matches!(op.operation, Operation::Delete(_)))
                .count();

            Ok(original_count + added_count as u32 - deleted_count as u32)
        }
    }
}
