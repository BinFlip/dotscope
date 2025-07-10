//! File region utilities for positioning components within output files.
//!
//! This module provides the [`FileRegion`] type and related utilities for managing
//! contiguous regions of bytes within binary files during layout planning.

/// A region within the file with start and size.
///
/// Represents a contiguous region of bytes within the output file,
/// used for positioning various file components like headers, sections,
/// and metadata streams.
///
/// # Usage
/// FileRegion provides the basic building block for all file layout
/// calculations, ensuring proper positioning and size tracking.
///
/// # Examples
/// ```rust,ignore
/// use crate::cilassembly::write::planner::layout::FileRegion;
///
/// let pe_headers = FileRegion {
///     offset: 0x80,
///     size: 0x178,
/// };
///
/// let section_table = FileRegion {
///     offset: pe_headers.end_offset(),
///     size: 5 * 40, // 5 sections * 40 bytes each
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRegion {
    /// Start offset in the file in bytes from beginning.
    pub offset: u64,

    /// Size of the region in bytes.
    pub size: u64,
}

impl FileRegion {
    /// Creates a new FileRegion with the specified offset and size.
    ///
    /// # Arguments
    /// * `offset` - The start offset in bytes from the beginning of the file
    /// * `size` - The size of the region in bytes
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region = FileRegion::new(0x1000, 0x500);
    /// assert_eq!(region.offset, 0x1000);
    /// assert_eq!(region.size, 0x500);
    /// ```
    pub fn new(offset: u64, size: u64) -> Self {
        Self { offset, size }
    }

    /// Returns the end offset of this region (offset + size).
    ///
    /// This is useful for positioning subsequent regions or calculating
    /// the total file size.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region = FileRegion::new(0x1000, 0x500);
    /// assert_eq!(region.end_offset(), 0x1500);
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
    /// # Arguments
    /// * `other` - The other region to check for overlap
    ///
    /// # Returns
    /// Returns `true` if the regions overlap.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region1 = FileRegion::new(0x1000, 0x500);
    /// let region2 = FileRegion::new(0x1400, 0x300);
    /// assert!(region1.overlaps(&region2));
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
