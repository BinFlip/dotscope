//! File region utilities for positioning components within output files.
//!
//! This module provides the [`crate::cilassembly::writer::layout::region::FileRegion`] type and related utilities for managing
//! contiguous regions of bytes within binary files during layout planning. It serves as the
//! fundamental building block for the simplified assembly writer's layout system, enabling
//! precise positioning and bounds management for all file components.
//!
//! # Architecture
//!
//! The file region system provides the foundation for layout planning in the simplified writer:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                          Output File Layout                                 │
//! ├─────────────────┬─────────────────┬─────────────────┬─────────────────────┤
//! │   PE Headers    │  Section Table  │   .text Sect   │     .meta Sect      │
//! │   FileRegion    │   FileRegion    │   FileRegion    │    FileRegion       │
//! │ offset: 0x80    │ offset: 0x1F8   │ offset: 0x400   │  offset: 0x2000     │
//! │ size: 0x178     │ size: 0x28      │ size: 0x1C00    │  size: 0x3000       │
//! └─────────────────┴─────────────────┴─────────────────┴─────────────────────┘
//! ```
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::layout::region::FileRegion`] - Represents a contiguous byte region with offset and size
//!
//! # Design Principles
//!
//! ## Precise Positioning
//! Every component in the output file is positioned using [`crate::cilassembly::writer::layout::region::FileRegion`] instances,
//! ensuring precise control over file layout and preventing overlaps or gaps.
//!
//! ## Bounds Checking
//! Comprehensive bounds checking and overlap detection prevent layout errors that could
//! result in corrupted output files or runtime failures.
//!
//! ## Alignment Awareness
//! While [`crate::cilassembly::writer::layout::region::FileRegion`] itself is alignment-agnostic, it provides the foundation
//! for higher-level alignment calculations and section positioning.
//!
//! # Usage Patterns
//!
//! ## Sequential Layout
//! Common pattern for laying out components sequentially:
//!
//! ```rust,ignore
//! let mut current_offset = 0x400; // Start after headers
//!
//! let text_section = FileRegion::new(current_offset, text_size);
//! current_offset = text_section.end_offset();
//!
//! let meta_section = FileRegion::new(current_offset, meta_size);
//! current_offset = meta_section.end_offset();
//! ```
//!
//! ## Overlap Detection
//! Preventing layout conflicts:
//!
//! ```rust,ignore
//! if region1.overlaps(&region2) {
//!     return Err(Error::WriteLayoutFailed {
//!         message: "Detected region overlap in file layout".to_string(),
//!     });
//! }
//! ```
//!
//! ## Bounds Validation
//! Ensuring proper containment:
//!
//! ```rust,ignore
//! if !section_region.contains(stream_offset) {
//!     return Err(Error::WriteLayoutFailed {
//!         message: "Stream extends beyond section boundaries".to_string(),
//!     });
//! }
//! ```
//!
//! # Thread Safety
//!
//! [`crate::cilassembly::writer::layout::region::FileRegion`] is [`Send`] and [`Sync`] as it contains only immutable data
//! after creation. All methods are pure functions that don't modify internal state.
//!
//! # Integration
//!
//! This module integrates with:
//!
//! - [`crate::cilassembly::writer::layout`] - Layout planning data structures
//! - [`crate::cilassembly::writer::output`] - Output file operations using regions
//! - [`crate::cilassembly::writer::planner`] - Layout planning using region calculations
//! - [`crate::file::physical`] - PE file structure analysis and region mapping
//!
//! # Examples
//!
//! ## Basic Region Creation and Usage
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::region::FileRegion;
//!
//! // Create regions for PE file components
//! let pe_headers = FileRegion::new(0x80, 0x178);
//! let section_table = FileRegion::new(pe_headers.end_offset(), 5 * 40);
//! let text_section = FileRegion::new(0x400, 0x1C00);
//!
//! // Verify no overlaps
//! assert!(!pe_headers.overlaps(&section_table));
//! assert!(!section_table.overlaps(&text_section));
//!
//! // Check containment
//! assert!(text_section.contains(0x800));
//! assert!(!text_section.contains(0x300));
//! ```
//!
//! ## Layout Validation
//!
//! ```rust,ignore
//! use dotscope::cilassembly::writer::layout::region::FileRegion;
//!
//! fn validate_layout(regions: &[FileRegion]) -> Result<(), String> {
//!     // Check for overlaps between all regions
//!     for (i, region1) in regions.iter().enumerate() {
//!         for region2 in regions.iter().skip(i + 1) {
//!             if region1.overlaps(region2) {
//!                 return Err(format!(
//!                     "Overlap detected: [{:x}-{:x}] and [{:x}-{:x}]",
//!                     region1.offset, region1.end_offset(),
//!                     region2.offset, region2.end_offset()
//!                 ));
//!             }
//!         }
//!     }
//!     Ok(())
//! }
//!
//! let regions = vec![
//!     FileRegion::new(0x80, 0x178),
//!     FileRegion::new(0x400, 0x1C00),
//!     FileRegion::new(0x2000, 0x3000),
//! ];
//! validate_layout(&regions).expect("Layout validation failed");
//! ```

/// A contiguous region within a binary file with precise positioning and size tracking.
///
/// [`crate::cilassembly::writer::layout::region::FileRegion`] represents a contiguous region of bytes within the output file,
/// serving as the fundamental building block for all file layout calculations in the simplified
/// assembly writer. It provides precise positioning, bounds checking, and overlap detection
/// capabilities essential for robust binary file generation.
///
/// # Design Philosophy
///
/// The FileRegion follows the **"Precise Positioning, Safe Boundaries"** principle:
/// - **Exact Positioning**: Every byte has a precise location within the file
/// - **Bounds Awareness**: All operations respect region boundaries
/// - **Overlap Prevention**: Built-in overlap detection prevents layout conflicts
/// - **Immutable Semantics**: Regions are immutable after creation for safety
///
/// # Use Cases
///
/// ## PE File Structure
/// Used for positioning all PE file components:
/// - DOS header and stub (typically `FileRegion::new(0, 0x80)`)
/// - PE headers (e.g., `FileRegion::new(0x80, 0x178)`)
/// - Section table entries (e.g., `FileRegion::new(0x1F8, sections * 40)`)
/// - Section content (e.g., `FileRegion::new(0x400, section_size)`)
///
/// ## .NET Metadata Layout
/// Essential for .NET metadata stream positioning:
/// - COR20 header placement within sections
/// - Metadata root and stream directory layout
/// - Individual stream positioning (Tables, Strings, Blobs, etc.)
/// - Heap boundary management and alignment
///
/// ## Layout Validation
/// Critical for preventing file corruption:
/// - Overlap detection between file components
/// - Boundary validation for nested components
/// - Sequential layout verification
/// - Alignment requirement checking
///
/// # Memory Layout
///
/// ```text
/// FileRegion Structure:
/// ┌─────────────┬─────────────┐
/// │   offset    │    size     │
/// │   (u64)     │   (u64)     │  
/// └─────────────┴─────────────┘
///      |              |
///      v              v
/// ┌─────────────────────────────────────────┐
/// │           File Content                  │
/// ├─────────────────────────────────────────┤
/// │  offset    │  region data   │  end_offset │
/// │     |      │       |        │      |      │
/// │     v      │       v        │      v      │
/// │ 0x1000     │   actual data  │   0x1500    │
/// └─────────────────────────────────────────┘
/// ```
///
/// # Thread Safety
///
/// [`crate::cilassembly::writer::layout::region::FileRegion`] is fully thread-safe:
/// - **Immutable after creation**: All fields are read-only after initialization
/// - **No shared state**: Each instance is independent
/// - **Pure methods**: All methods are pure functions without side effects
/// - **Safe sharing**: Can be safely shared between threads via [`Send`] and [`Sync`]
///
/// # Performance Characteristics
///
/// - **Constant time operations**: All methods execute in O(1) time
/// - **Minimal memory footprint**: Only 16 bytes per instance (2 × u64)
/// - **Zero allocation**: No heap allocations during normal operations
/// - **Cache-friendly**: Small, contiguous memory layout
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::region::FileRegion;
///
/// // Create region for PE headers
/// let pe_headers = FileRegion::new(0x80, 0x178);
/// assert_eq!(pe_headers.offset, 0x80);
/// assert_eq!(pe_headers.size, 0x178);
/// assert_eq!(pe_headers.end_offset(), 0x1F8);
/// ```
///
/// ## Sequential Layout Planning
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::region::FileRegion;
///
/// let mut current_offset = 0x400;
///
/// // Layout sections sequentially
/// let text_section = FileRegion::new(current_offset, 0x1C00);
/// current_offset = text_section.end_offset();
///
/// let meta_section = FileRegion::new(current_offset, 0x3000);
/// current_offset = meta_section.end_offset();
///
/// // Verify proper sequencing
/// assert!(text_section.is_adjacent_to(&meta_section));
/// assert!(!text_section.overlaps(&meta_section));
/// ```
///
/// ## Overlap Detection and Validation
///
/// ```rust,ignore
/// use dotscope::cilassembly::writer::layout::region::FileRegion;
///
/// let region1 = FileRegion::new(0x1000, 0x500);
/// let region2 = FileRegion::new(0x1400, 0x300); // Overlaps with region1
/// let region3 = FileRegion::new(0x1500, 0x300); // Adjacent to region1
///
/// // Overlap detection
/// assert!(region1.overlaps(&region2));
/// assert!(!region1.overlaps(&region3));
///
/// // Adjacency checking
/// assert!(region1.is_adjacent_to(&region3));
/// assert!(!region1.is_adjacent_to(&region2));
///
/// // Containment testing
/// assert!(region1.contains(0x1200));
/// assert!(!region1.contains(0x1600));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRegion {
    /// Starting byte offset from the beginning of the file.
    ///
    /// This represents the absolute position where this region begins within
    /// the output file. All file operations using this region will be relative
    /// to this offset.
    pub offset: u64,

    /// Size of the region in bytes.
    ///
    /// This represents the total number of bytes that this region encompasses.
    /// The region spans from `offset` to `offset + size` (exclusive).
    pub size: u64,
}

impl FileRegion {
    /// Creates a new [`crate::cilassembly::writer::layout::region::FileRegion`] with the specified offset and size.
    ///
    /// Constructs a new file region representing a contiguous range of bytes within the output file.
    /// The region spans from `offset` to `offset + size` (exclusive), providing precise positioning
    /// for file layout operations.
    ///
    /// # Arguments
    ///
    /// * `offset` - The starting byte offset from the beginning of the file (inclusive)
    /// * `size` - The size of the region in bytes (exclusive end boundary)
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::cilassembly::writer::layout::region::FileRegion`] instance representing the specified range.
    ///
    /// # Examples
    ///
    /// ## Basic Region Creation
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::region::FileRegion;
    ///
    /// let region = FileRegion::new(0x1000, 0x500);
    /// assert_eq!(region.offset, 0x1000);
    /// assert_eq!(region.size, 0x500);
    /// assert_eq!(region.end_offset(), 0x1500);
    /// ```
    ///
    /// ## PE Structure Layout
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::region::FileRegion;
    ///
    /// // DOS header region
    /// let dos_header = FileRegion::new(0, 0x80);
    ///
    /// // PE headers following DOS header
    /// let pe_headers = FileRegion::new(dos_header.end_offset(), 0x178);
    ///
    /// // Section table after PE headers
    /// let section_table = FileRegion::new(pe_headers.end_offset(), 5 * 40);
    /// ```
    pub fn new(offset: u64, size: u64) -> Self {
        Self { offset, size }
    }

    /// Returns the exclusive end offset of this region (offset + size).
    ///
    /// Calculates the first byte position immediately after this region, which is essential
    /// for sequential layout planning and file size calculations. The end offset is exclusive,
    /// meaning it points to the first byte that is NOT part of this region.
    ///
    /// # Returns
    ///
    /// Returns the end offset as a [`u64`] representing the first byte after this region.
    ///
    /// # Examples
    ///
    /// ## Basic End Offset Calculation
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::region::FileRegion;
    ///
    /// let region = FileRegion::new(0x1000, 0x500);
    /// assert_eq!(region.end_offset(), 0x1500);
    ///
    /// // The region contains bytes 0x1000..0x14FF
    /// // The end_offset (0x1500) is the first byte NOT in the region
    /// ```
    ///
    /// ## Sequential Layout Planning
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::region::FileRegion;
    ///
    /// let first_region = FileRegion::new(0x400, 0x1000);
    /// let second_region = FileRegion::new(first_region.end_offset(), 0x800);
    ///
    /// assert_eq!(second_region.offset, 0x1400);
    /// assert!(first_region.is_adjacent_to(&second_region));
    /// ```
    pub fn end_offset(&self) -> u64 {
        self.offset + self.size
    }

    /// Checks if this region contains the specified offset.
    ///
    /// # Arguments
    /// * `offset` - The offset to check for containment
    ///
    /// # Returns
    /// Returns `true` if the offset falls within this region's bounds.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region = FileRegion::new(0x1000, 0x500);
    /// assert!(region.contains(0x1200));
    /// assert!(!region.contains(0x1600));
    /// ```
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.offset && offset < self.end_offset()
    }

    /// Checks if this region overlaps with another region.
    ///
    /// Determines whether any portion of this region's byte range intersects with another
    /// region's byte range. This is crucial for layout validation to prevent file corruption
    /// caused by overlapping components.
    ///
    /// # Overlap Detection Algorithm
    ///
    /// Two regions overlap if:
    /// ```text
    /// self.offset < other.end_offset() AND other.offset < self.end_offset()
    /// ```
    ///
    /// This handles all overlap cases:
    /// - Partial overlap from either direction
    /// - Complete containment in either direction
    /// - Identical regions
    ///
    /// # Arguments
    ///
    /// * `other` - The other [`crate::cilassembly::writer::layout::region::FileRegion`] to check for overlap
    ///
    /// # Returns
    ///
    /// Returns `true` if the regions have any overlapping bytes, `false` if they are
    /// completely separate or merely adjacent.
    ///
    /// # Examples
    ///
    /// ## Overlap Detection
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::region::FileRegion;
    ///
    /// let region1 = FileRegion::new(0x1000, 0x500); // 0x1000..0x1500
    /// let region2 = FileRegion::new(0x1400, 0x300); // 0x1400..0x1700 (overlaps)
    /// let region3 = FileRegion::new(0x1500, 0x300); // 0x1500..0x1800 (adjacent)
    /// let region4 = FileRegion::new(0x1800, 0x300); // 0x1800..0x1B00 (separate)
    ///
    /// assert!(region1.overlaps(&region2));  // Partial overlap
    /// assert!(!region1.overlaps(&region3)); // Adjacent, no overlap
    /// assert!(!region1.overlaps(&region4)); // Completely separate
    /// ```
    ///
    /// ## Layout Validation
    ///
    /// ```rust,ignore
    /// use dotscope::cilassembly::writer::layout::region::FileRegion;
    ///
    /// fn validate_no_overlaps(regions: &[FileRegion]) -> Result<(), String> {
    ///     for (i, region1) in regions.iter().enumerate() {
    ///         for region2 in regions.iter().skip(i + 1) {
    ///             if region1.overlaps(region2) {
    ///                 return Err(format!(
    ///                     "Regions overlap: [{:x}-{:x}] and [{:x}-{:x}]",
    ///                     region1.offset, region1.end_offset(),
    ///                     region2.offset, region2.end_offset()
    ///                 ));
    ///             }
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn overlaps(&self, other: &FileRegion) -> bool {
        self.offset < other.end_offset() && other.offset < self.end_offset()
    }

    /// Checks if this region is empty (has zero size).
    ///
    /// # Examples
    /// ```rust,ignore
    /// let empty_region = FileRegion::new(0x1000, 0);
    /// assert!(empty_region.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Checks if this region is adjacent to another region.
    ///
    /// Two regions are adjacent if one ends exactly where the other begins.
    ///
    /// # Arguments
    /// * `other` - The other region to check for adjacency
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region1 = FileRegion::new(0x1000, 0x500);
    /// let region2 = FileRegion::new(0x1500, 0x300);
    /// assert!(region1.is_adjacent_to(&region2));
    /// ```
    pub fn is_adjacent_to(&self, other: &FileRegion) -> bool {
        self.end_offset() == other.offset || other.end_offset() == self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_region_creation() {
        let region = FileRegion::new(0x1000, 0x500);
        assert_eq!(region.offset, 0x1000);
        assert_eq!(region.size, 0x500);
    }

    #[test]
    fn test_end_offset() {
        let region = FileRegion::new(0x1000, 0x500);
        assert_eq!(region.end_offset(), 0x1500);
    }

    #[test]
    fn test_contains() {
        let region = FileRegion::new(0x1000, 0x500);
        assert!(region.contains(0x1000)); // Start boundary
        assert!(region.contains(0x1200)); // Middle
        assert!(region.contains(0x14FF)); // End boundary - 1
        assert!(!region.contains(0x1500)); // End boundary (exclusive)
        assert!(!region.contains(0x0FFF)); // Before start
        assert!(!region.contains(0x1600)); // After end
    }

    #[test]
    fn test_overlaps() {
        let region1 = FileRegion::new(0x1000, 0x500);
        let region2 = FileRegion::new(0x1400, 0x300); // Overlaps
        let region3 = FileRegion::new(0x1500, 0x300); // Adjacent, no overlap
        let region4 = FileRegion::new(0x1600, 0x300); // No overlap

        assert!(region1.overlaps(&region2));
        assert!(region2.overlaps(&region1)); // Symmetric
        assert!(!region1.overlaps(&region3));
        assert!(!region1.overlaps(&region4));
    }

    #[test]
    fn test_is_empty() {
        let empty_region = FileRegion::new(0x1000, 0);
        let non_empty_region = FileRegion::new(0x1000, 1);

        assert!(empty_region.is_empty());
        assert!(!non_empty_region.is_empty());
    }

    #[test]
    fn test_is_adjacent_to() {
        let region1 = FileRegion::new(0x1000, 0x500);
        let region2 = FileRegion::new(0x1500, 0x300); // Adjacent after
        let region3 = FileRegion::new(0x0B00, 0x500); // Adjacent before
        let region4 = FileRegion::new(0x1400, 0x300); // Overlapping
        let region5 = FileRegion::new(0x1600, 0x300); // Gap

        assert!(region1.is_adjacent_to(&region2));
        assert!(region2.is_adjacent_to(&region1)); // Symmetric
        assert!(region1.is_adjacent_to(&region3));
        assert!(!region1.is_adjacent_to(&region4)); // Overlapping, not adjacent
        assert!(!region1.is_adjacent_to(&region5)); // Gap
    }

    #[test]
    fn test_equality() {
        let region1 = FileRegion::new(0x1000, 0x500);
        let region2 = FileRegion::new(0x1000, 0x500);
        let region3 = FileRegion::new(0x1000, 0x400);

        assert_eq!(region1, region2);
        assert_ne!(region1, region3);
    }
}
