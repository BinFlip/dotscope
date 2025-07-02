//! Table size calculation functions for metadata table modifications.
//!
//! This module provides specialized size calculation logic for metadata table modifications,
//! implementing exact ECMA-335 specification requirements for table expansion and row counting.

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
/// table replacements.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing table modifications
///
/// # Returns
/// Returns the total additional bytes needed for the tables stream.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if table information is unavailable.
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
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `table_id` - The [`crate::metadata::tables::TableId`] to calculate for
/// * `table_mod` - The [`crate::cilassembly::TableModifications`] to apply
///
/// # Returns
/// Returns the final row count after all modifications are applied.
///
/// # Errors
/// Returns [`crate::Error::WriteLayoutFailed`] if table information is unavailable.
///
/// # Note
/// For sparse modifications, this uses a simplified calculation that may not account
/// for complex operation interactions. Production code should use proper operation
/// sequence processing.
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
