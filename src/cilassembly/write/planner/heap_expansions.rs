//! Heap expansion calculation and analysis for binary generation.
//!
//! This module provides the [`HeapExpansions`] type which encapsulates all heap expansion
//! calculations and provides rich methods for analysis and decision-making during layout planning.
//! It represents a more type-driven approach where the data structure itself provides the
//! methods for working with heap expansion data.

use crate::{
    cilassembly::{
        write::planner::calc::heaps::{
            calculate_blob_heap_size, calculate_guid_heap_size, calculate_string_heap_size,
            calculate_userstring_heap_size,
        },
        CilAssembly,
    },
    Result,
};

/// Comprehensive heap expansion information with analysis methods.
///
/// This structure contains all heap expansion requirements calculated from assembly modifications
/// and provides methods for analyzing the expansions, making layout decisions, and determining
/// impact on file structure.
///
/// # Philosophy
/// Instead of passing this data structure to many static functions, `HeapExpansions` provides
/// rich methods that encapsulate the knowledge about heap expansion behavior. This makes the
/// API more discoverable and intuitive for users.
///
/// # Examples
/// ```rust,ignore
/// let expansions = HeapExpansions::calculate(&assembly)?;
///
/// if expansions.requires_relocation() {
///     println!("Sections need to be relocated due to {} bytes of expansion",
///              expansions.total_addition());
/// }
///
/// if let Some(largest) = expansions.largest_expansion() {
///     println!("Largest expansion is in {} heap", largest);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct HeapExpansions {
    /// Additional bytes needed for string heap.
    /// Includes null terminators and 4-byte alignment padding.
    pub string_heap_addition: u64,

    /// Additional bytes needed for blob heap.
    /// Includes compressed length prefixes and 4-byte alignment padding.
    pub blob_heap_addition: u64,

    /// Additional bytes needed for GUID heap.
    /// Each GUID is exactly 16 bytes with natural alignment.
    pub guid_heap_addition: u64,

    /// Additional bytes needed for user string heap.
    /// Includes UTF-16 encoding, compressed length prefixes, and 4-byte alignment padding.
    pub userstring_heap_addition: u64,

    /// Total additional space needed for all heaps and table modifications.
    /// Sum of all individual heap additions plus table stream expansion.
    pub total_heap_addition: u64,
}

impl HeapExpansions {
    /// Calculates heap expansions for the given assembly.
    ///
    /// This is the main entry point for heap expansion calculation. It analyzes all
    /// modifications in the assembly and calculates the exact additional space needed
    /// for each metadata heap.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to analyze for heap expansion requirements
    ///
    /// # Returns
    /// Returns a `HeapExpansions` instance with all calculations completed.
    ///
    /// # Errors
    /// Returns [`crate::Error`] if heap size calculations fail due to invalid data or encoding issues.
    pub fn calculate(assembly: &CilAssembly) -> Result<Self> {
        let changes = assembly.changes();

        // Use the aligned heap size calculations to ensure consistency
        let string_heap_addition = if changes.string_heap_changes.has_additions()
            || changes.string_heap_changes.has_modifications()
            || changes.string_heap_changes.has_removals()
        {
            Self::calculate_string_heap_size(assembly)?
        } else {
            0
        };

        let blob_heap_addition = if changes.blob_heap_changes.has_additions()
            || changes.blob_heap_changes.has_modifications()
            || changes.blob_heap_changes.has_removals()
        {
            Self::calculate_blob_heap_size(assembly)?
        } else {
            0
        };

        let guid_heap_addition = if changes.guid_heap_changes.has_additions()
            || changes.guid_heap_changes.has_modifications()
            || changes.guid_heap_changes.has_removals()
        {
            Self::calculate_guid_heap_size(assembly)?
        } else {
            0
        };

        let userstring_heap_addition = if changes.userstring_heap_changes.has_additions()
            || changes.userstring_heap_changes.has_modifications()
            || changes.userstring_heap_changes.has_removals()
        {
            Self::calculate_userstring_heap_size(assembly)?
        } else {
            0
        };

        // Calculate table stream expansion
        let table_expansion = super::calc::calculate_table_stream_expansion(assembly)?;

        let total_heap_addition = string_heap_addition
            + blob_heap_addition
            + guid_heap_addition
            + userstring_heap_addition
            + table_expansion;

        Ok(HeapExpansions {
            string_heap_addition,
            blob_heap_addition,
            guid_heap_addition,
            userstring_heap_addition,
            total_heap_addition,
        })
    }

    /// Returns the total additional space needed across all heaps.
    ///
    /// This is the sum of all individual heap expansions and represents the total
    /// additional space that will be needed in the metadata section.
    pub fn total_addition(&self) -> u64 {
        self.total_heap_addition
    }

    /// Determines if the expansions are significant enough to require section relocation.
    ///
    /// Small expansions (under 4KB) can often be accommodated in-place without moving
    /// sections, while larger expansions typically require full section relocation.
    ///
    /// # Returns
    /// Returns `true` if sections should be relocated due to significant expansions.
    pub fn requires_relocation(&self) -> bool {
        self.total_heap_addition > 4096 // More than 4KB of changes
    }

    /// Checks if any heap modifications are present.
    ///
    /// # Returns
    /// Returns `true` if any heap has additions, `false` if no heap modifications exist.
    pub fn has_modifications(&self) -> bool {
        self.total_heap_addition > 0
    }

    /// Returns the type of heap with the largest expansion.
    ///
    /// This can be useful for logging, debugging, or optimization decisions.
    ///
    /// # Returns
    /// Returns the name of the heap with the largest expansion, or `None` if no expansions exist.
    pub fn largest_expansion(&self) -> Option<&'static str> {
        if self.total_heap_addition == 0 {
            return None;
        }

        let mut max_size = 0;
        let mut max_heap = None;

        if self.string_heap_addition > max_size {
            max_size = self.string_heap_addition;
            max_heap = Some("string");
        }
        if self.blob_heap_addition > max_size {
            max_size = self.blob_heap_addition;
            max_heap = Some("blob");
        }
        if self.guid_heap_addition > max_size {
            max_size = self.guid_heap_addition;
            max_heap = Some("guid");
        }
        if self.userstring_heap_addition > max_size {
            max_heap = Some("userstring");
        }

        max_heap
    }

    /// Checks if only string heap modifications are present.
    ///
    /// This can be useful for optimization decisions, as string-only modifications
    /// have different characteristics than mixed heap modifications.
    ///
    /// # Returns
    /// Returns `true` if only the string heap has additions.
    pub fn is_string_only(&self) -> bool {
        self.string_heap_addition > 0
            && self.blob_heap_addition == 0
            && self.guid_heap_addition == 0
            && self.userstring_heap_addition == 0
    }

    /// Checks if the expansions are minimal (under 1KB total).
    ///
    /// Minimal expansions can often use optimized layout strategies that preserve
    /// more of the original file structure.
    ///
    /// # Returns
    /// Returns `true` if total expansions are under 1KB.
    pub fn is_minimal(&self) -> bool {
        self.total_heap_addition < 1024
    }

    /// Returns expansion information formatted for logging or debugging.
    ///
    /// # Returns
    /// Returns a formatted string with expansion details.
    pub fn summary(&self) -> String {
        if self.total_heap_addition == 0 {
            "No heap expansions needed".to_string()
        } else {
            format!(
                "Heap expansions: String +{}, Blob +{}, GUID +{}, UserString +{} (Total: {} bytes)",
                self.string_heap_addition,
                self.blob_heap_addition,
                self.guid_heap_addition,
                self.userstring_heap_addition,
                self.total_heap_addition
            )
        }
    }

    /// Calculate the total size needed for the string heap after modifications.
    ///
    /// This method calculates the complete size required for the string heap
    /// including all additions, modifications, and removals according to ECMA-335.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to analyze for string heap requirements
    ///
    /// # Returns
    /// Returns the total size in bytes needed for the string heap.
    pub fn calculate_string_heap_size(assembly: &CilAssembly) -> Result<u64> {
        let changes = &assembly.changes().string_heap_changes;
        calculate_string_heap_size(changes, assembly)
    }

    /// Calculate the total size needed for the blob heap after modifications.
    ///
    /// This method calculates the complete size required for the blob heap
    /// including all additions, modifications, and removals according to ECMA-335.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to analyze for blob heap requirements
    ///
    /// # Returns
    /// Returns the total size in bytes needed for the blob heap.
    pub fn calculate_blob_heap_size(assembly: &CilAssembly) -> Result<u64> {
        let changes = &assembly.changes().blob_heap_changes;
        calculate_blob_heap_size(changes, assembly)
    }

    /// Calculate the total size needed for the GUID heap after modifications.
    ///
    /// This method calculates the complete size required for the GUID heap
    /// including all additions, modifications, and removals according to ECMA-335.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to analyze for GUID heap requirements
    ///
    /// # Returns
    /// Returns the total size in bytes needed for the GUID heap.
    pub fn calculate_guid_heap_size(assembly: &CilAssembly) -> Result<u64> {
        let changes = &assembly.changes().guid_heap_changes;
        calculate_guid_heap_size(changes, assembly)
    }

    /// Calculate the total size needed for the user string heap after modifications.
    ///
    /// This method calculates the complete size required for the user string heap
    /// including all additions, modifications, and removals according to ECMA-335.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to analyze for user string heap requirements
    ///
    /// # Returns
    /// Returns the total size in bytes needed for the user string heap.
    pub fn calculate_userstring_heap_size(assembly: &CilAssembly) -> Result<u64> {
        let changes = &assembly.changes().userstring_heap_changes;
        calculate_userstring_heap_size(changes, assembly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_heap_expansions_calculate() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let expansions = HeapExpansions::calculate(&assembly)
            .expect("Heap expansion calculation should succeed");

        // For an unmodified assembly, all expansions should be 0
        assert_eq!(expansions.string_heap_addition, 0);
        assert_eq!(expansions.blob_heap_addition, 0);
        assert_eq!(expansions.guid_heap_addition, 0);
        assert_eq!(expansions.userstring_heap_addition, 0);
        assert_eq!(expansions.total_heap_addition, 0);
    }

    #[test]
    fn test_heap_expansions_analysis_methods() {
        // Create test expansion with known values
        let expansions = HeapExpansions {
            string_heap_addition: 1000,
            blob_heap_addition: 500,
            guid_heap_addition: 32, // 2 GUIDs
            userstring_heap_addition: 0,
            total_heap_addition: 1532,
        };

        assert_eq!(expansions.total_addition(), 1532);
        assert!(!expansions.requires_relocation()); // Under 4KB
        assert!(expansions.has_modifications());
        assert_eq!(expansions.largest_expansion(), Some("string"));
        assert!(!expansions.is_string_only()); // Has other heaps too
        assert!(!expansions.is_minimal()); // Over 1KB
    }

    #[test]
    fn test_heap_expansions_large_expansion() {
        let expansions = HeapExpansions {
            string_heap_addition: 5000, // 5KB
            blob_heap_addition: 0,
            guid_heap_addition: 0,
            userstring_heap_addition: 0,
            total_heap_addition: 5000,
        };

        assert!(expansions.requires_relocation()); // Over 4KB
        assert!(expansions.is_string_only());
        assert_eq!(expansions.largest_expansion(), Some("string"));
    }

    #[test]
    fn test_heap_expansions_minimal() {
        let expansions = HeapExpansions {
            string_heap_addition: 100,
            blob_heap_addition: 0,
            guid_heap_addition: 16, // 1 GUID
            userstring_heap_addition: 0,
            total_heap_addition: 116,
        };

        assert!(expansions.is_minimal()); // Under 1KB
        assert!(!expansions.requires_relocation()); // Under 4KB
        assert!(!expansions.is_string_only()); // Has GUID too
    }

    #[test]
    fn test_heap_expansions_no_modifications() {
        let expansions = HeapExpansions {
            string_heap_addition: 0,
            blob_heap_addition: 0,
            guid_heap_addition: 0,
            userstring_heap_addition: 0,
            total_heap_addition: 0,
        };

        assert!(!expansions.has_modifications());
        assert!(!expansions.requires_relocation());
        assert!(!expansions.is_string_only());
        assert!(expansions.is_minimal());
        assert_eq!(expansions.largest_expansion(), None);
    }

    #[test]
    fn test_heap_expansions_summary() {
        let expansions = HeapExpansions {
            string_heap_addition: 1000,
            blob_heap_addition: 500,
            guid_heap_addition: 32,
            userstring_heap_addition: 200,
            total_heap_addition: 1732,
        };

        let summary = expansions.summary();
        assert!(summary.contains("1000"));
        assert!(summary.contains("500"));
        assert!(summary.contains("32"));
        assert!(summary.contains("200"));
        assert!(summary.contains("1732"));
    }
}
