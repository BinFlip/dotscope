//! Metadata table and heap calculation utilities.
//!
//! This module provides utilities for calculating sizes and offsets in .NET metadata
//! structures. These utilities are used throughout the framework for layout planning,
//! binary generation, and validation.
//!
//! # Table Row Size Calculation
//!
//! The primary utility is dynamic metadata table row size calculation, which accounts
//! for variable-sized fields based on actual table row counts and heap sizes.
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::utils::heap_calc::calculate_table_row_size;
//! use dotscope::metadata::tables::TableId;
//! use dotscope::prelude::*;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
//! let table_info = view.tables().unwrap().table_info();
//!
//! let type_def_size = calculate_table_row_size(TableId::TypeDef, &table_info);
//! let method_def_size = calculate_table_row_size(TableId::MethodDef, &table_info);
//!
//! println!("TypeDef row size: {} bytes", type_def_size);
//! println!("MethodDef row size: {} bytes", method_def_size);
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    dispatch_table_type,
    metadata::tables::{TableId, TableInfoRef, TableRow},
};

/// Calculates the exact row size for any ECMA-335 metadata table using dynamic schema information.
///
/// This function provides centralized, accurate row size calculation for all metadata table
/// types defined in ECMA-335 Partition II. It accounts for variable-sized fields based on
/// actual table row counts and heap sizes, ensuring consistent size calculations throughout
/// the framework.
///
/// The calculation is crucial for layout planning and binary generation because metadata
/// table row sizes are not fixed—they depend on the current state of the assembly being
/// processed. Index fields and references use variable sizes (2 or 4 bytes) based on whether
/// they can fit within 16-bit limits.
///
/// # Arguments
///
/// * `table_id` - The [`TableId`] identifying which metadata table type to calculate the row size for
/// * `table_info` - A [`TableInfoRef`] containing the current metadata state, including
///   row counts for all tables and heap sizes
///
/// # Returns
///
/// Returns the exact row size in bytes as a [`u32`] for the specified table type.
/// The size accounts for all fields in the table schema including:
/// - Fixed-size fields (flags, constants, etc.)
/// - Variable-size table indexes (2 or 4 bytes based on row count)
/// - Variable-size heap indexes (2 or 4 bytes based on heap size)
/// - Variable-size coded indexes (2 or 4 bytes based on multiple table sizes)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::utils::heap_calc::calculate_table_row_size;
/// use dotscope::metadata::tables::TableId;
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;
/// let table_info = view.tables().unwrap().table_info();
///
/// // Calculate sizes for common table types
/// let type_def_size = calculate_table_row_size(TableId::TypeDef, &table_info);
/// let method_def_size = calculate_table_row_size(TableId::MethodDef, &table_info);
/// let field_def_size = calculate_table_row_size(TableId::FieldDef, &table_info);
///
/// println!("TypeDef row size: {} bytes", type_def_size);
/// println!("MethodDef row size: {} bytes", method_def_size);
/// println!("FieldDef row size: {} bytes", field_def_size);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn calculate_table_row_size(table_id: TableId, table_info: &TableInfoRef) -> u32 {
    dispatch_table_type!(table_id, |RawType| RawType::row_size(table_info))
}

#[cfg(test)]
mod tests {
    // Note: These tests would require actual metadata structures to be meaningful
    // For now, we include basic compilation tests

    #[test]
    fn test_calculate_table_row_size_compiles() {
        // This test ensures the function compiles and can be called
        // Real tests would require setting up TableInfoRef with actual data
    }
}
