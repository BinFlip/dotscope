//! Size calculation utilities for layout planning.
//!
//! This module provides comprehensive size calculation logic for all components of .NET
//! assemblies during the binary generation process. It handles the complex task of determining
//! exact byte sizes for metadata heaps, table expansions, and structural alignments required
//! for ECMA-335 compliance.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::planner::HeapExpansions::calculate`] - Main entry point for heap size calculations
//! - [`crate::cilassembly::write::planner::calc::HeapExpansions`] - Structure containing all heap expansion information
//! - [`crate::cilassembly::write::planner::calc::calculate_string_heap_size`] - String heap size calculation with null termination
//! - [`crate::cilassembly::write::planner::calc::calculate_blob_heap_size`] - Blob heap size with compressed length prefixes
//! - [`crate::cilassembly::write::planner::calc::calculate_guid_heap_size`] - GUID heap size (16 bytes per GUID)
//! - [`crate::cilassembly::write::planner::calc::calculate_userstring_heap_size`] - UserString heap with UTF-16 encoding
//! - [`crate::cilassembly::write::planner::calc::calculate_table_stream_expansion`] - Table modifications size calculation
//! - [`crate::cilassembly::write::planner::calc::calculate_new_row_count`] - Row count after table modifications
//!
//! # Architecture
//!
//! The size calculation system implements the exact ECMA-335 specification requirements:
//!
//! ## Heap Size Calculations
//! Each metadata heap type has specific encoding and alignment requirements:
//! - **String Heap**: UTF-8 encoded with null terminators, 4-byte aligned
//! - **Blob Heap**: Binary data with compressed length prefixes, 4-byte aligned
//! - **GUID Heap**: Fixed 16-byte GUIDs, naturally aligned
//! - **UserString Heap**: UTF-16 encoded with compressed length prefixes, 4-byte aligned
//!
//! ## Table Size Calculations
//! Table expansions are calculated based on:
//! - Row size determined by table schema and index sizes
//! - Number of additional rows from modifications
//! - Sparse vs replacement modification patterns
//!
//! ## Alignment Requirements
//! All calculations respect ECMA-335 alignment requirements:
//! - Heap data aligned to 4-byte boundaries
//! - Compressed integers for length prefixes
//! - UTF-16 encoding for user strings
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::HeapExpansions;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! // Calculate all heap expansions for layout planning
//! let expansions = HeapExpansions::calculate(&assembly)?;
//!
//! println!("String heap needs {} additional bytes", expansions.string_heap_addition);
//! println!("Total expansion: {} bytes", expansions.total_heap_addition);
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are pure calculations that do not modify shared state,
//! making them inherently thread-safe. However, they are designed for single-threaded
//! use during the layout planning phase.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning coordination
//! - [`crate::cilassembly::changes`] - Source of modification data
//! - [`crate::cilassembly::write::utils`] - Utility functions for table calculations
//! - [`crate::metadata::tables`] - Table schema and size information

mod heaps;
mod tables;

pub use crate::cilassembly::write::planner::heap_expansions::HeapExpansions;
pub(crate) use heaps::{
    calculate_blob_heap_size, calculate_guid_heap_size, calculate_string_heap_size,
    calculate_string_heap_total_size, calculate_userstring_heap_size,
};
pub use tables::{calculate_new_row_count, calculate_table_stream_expansion};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cilassembly::changes::HeapChanges, CilAssemblyView};
    use std::path::Path;

    #[test]
    fn test_heap_expansion_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions = HeapExpansions::calculate(&assembly)
            .expect("Heap expansion calculation should succeed");

        // For an unmodified assembly, all expansions should be 0
        assert_eq!(
            heap_expansions.string_heap_addition, 0,
            "String heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.blob_heap_addition, 0,
            "Blob heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.guid_heap_addition, 0,
            "GUID heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.userstring_heap_addition, 0,
            "UserString heap addition should be 0 for unmodified assembly"
        );
        assert_eq!(
            heap_expansions.total_heap_addition, 0,
            "Total heap addition should be 0 for unmodified assembly"
        );
    }

    #[test]
    fn test_string_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("test".to_string());
        heap_changes.appended_items.push("hello world".to_string());

        let size = heaps::calculate_string_heap_size(&heap_changes, &assembly).unwrap();

        // "test" (4) + null (1) + "hello world" (11) + null (1) = 17 bytes
        // Aligned to 4 bytes = 20 bytes
        assert_eq!(size, 20);
    }

    #[test]
    fn test_blob_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        // Test 1: Rebuild scenario (with changes)
        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push(vec![1, 2, 3]); // length 3, prefix 1 byte
        heap_changes.appended_items.push(vec![4, 5]); // length 2, prefix 1 byte

        let rebuilt_size = heaps::calculate_blob_heap_size(&heap_changes, &assembly).unwrap();

        // In rebuild scenario, should include original heap + new additions
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len()
        } else {
            0
        };

        // blob1: 1 (prefix) + 3 (data) = 4 bytes
        // blob2: 1 (prefix) + 2 (data) = 3 bytes
        // total additions: 7 bytes, aligned to 4 = 8 bytes
        // But since has_changes()=true, we get original + additions
        assert!(rebuilt_size > original_heap_size as u64);
        assert!(rebuilt_size <= (original_heap_size + 8) as u64);
    }

    #[test]
    fn test_guid_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push([0u8; 16]);
        heap_changes.appended_items.push([1u8; 16]);

        let size = heaps::calculate_guid_heap_size(&heap_changes, &assembly).unwrap();

        // 2 GUIDs * 16 bytes each = 32 bytes (already aligned)
        assert_eq!(size, 32);
    }

    #[test]
    fn test_userstring_heap_size_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("A".to_string()); // 1 char = 2 UTF-16 bytes

        let size = heaps::calculate_userstring_heap_size(&heap_changes, &assembly).unwrap();

        // 1 (prefix) + 2 (UTF-16 data) + 1 (terminator) = 4 bytes, aligned to 4 = 4 bytes
        assert_eq!(size, 4);
    }

    #[test]
    fn test_empty_heap_changes() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let empty_string_changes = HeapChanges::<String>::new(0);
        let empty_blob_changes = HeapChanges::<Vec<u8>>::new(0);
        let empty_guid_changes = HeapChanges::<[u8; 16]>::new(0);

        assert_eq!(
            heaps::calculate_string_heap_size(&empty_string_changes, &assembly).unwrap(),
            0
        );
        assert_eq!(
            heaps::calculate_blob_heap_size(&empty_blob_changes, &assembly).unwrap(),
            0
        );
        assert_eq!(
            heaps::calculate_guid_heap_size(&empty_guid_changes, &assembly).unwrap(),
            0
        );
        assert_eq!(
            heaps::calculate_userstring_heap_size(&empty_string_changes, &assembly).unwrap(),
            0
        );
    }

    #[test]
    fn test_empty_string_addition() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("".to_string());

        let size = heaps::calculate_string_heap_size(&heap_changes, &assembly).unwrap();

        // Empty string = 0 bytes + 1 null terminator = 1 byte, aligned to 4 = 4 bytes
        assert_eq!(size, 4);
    }

    #[test]
    fn test_unicode_string_calculation() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        heap_changes.appended_items.push("Test🦀Rust".to_string());

        let size = heaps::calculate_string_heap_size(&heap_changes, &assembly).unwrap();

        // String is stored as UTF-8 bytes in string heap
        let utf8_len = "Test🦀Rust".len(); // 12 bytes (🦀 is 4 bytes in UTF-8)
        let expected_size = (utf8_len + 1).div_ceil(4) * 4; // +1 for null, align to 4

        assert_eq!(size, expected_size as u64);
    }

    #[test]
    fn test_large_blob_compressed_length() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let mut heap_changes = HeapChanges::new(0);
        let large_blob = vec![0u8; 200]; // 200 bytes requires 2-byte compressed length
        heap_changes.appended_items.push(large_blob);

        let rebuilt_size = heaps::calculate_blob_heap_size(&heap_changes, &assembly).unwrap();

        // In rebuild scenario, should include original heap + new additions
        let original_heap_size = if let Some(blob_heap) = assembly.view().blobs() {
            blob_heap.data().len()
        } else {
            0
        };

        // 200-byte blob: 2 bytes length prefix + 200 bytes data = 202 bytes, aligned to 4 = 204 bytes
        // But since has_changes()=true, we get original + additions
        assert!(rebuilt_size > original_heap_size as u64);
        assert!(rebuilt_size <= (original_heap_size + 204) as u64);
    }
}
