//! Stream-specific layout functionality for metadata streams.
//!
//! This module provides the [`StreamFileLayout`] type and related functionality
//! for working with individual metadata streams within file layouts. It includes
//! comprehensive analysis and utility methods for stream properties.
//!
//! # Key Types
//!
//! - [`StreamFileLayout`] - Layout information for individual metadata streams
//!
//! # Stream Analysis
//!
//! Provides rich methods for:
//! - **Size analysis**: Calculate additional data size and alignment
//! - **Content analysis**: Check for additional data beyond original content
//! - **Alignment checking**: Verify proper 4-byte stream alignment

use crate::cilassembly::write::planner::layout::FileRegion;

/// Layout of a metadata stream in the new file.
///
/// Contains the layout information for an individual metadata stream
/// within a metadata-containing section. Provides analysis methods
/// for stream properties and characteristics.
///
/// # Examples
/// ```rust,ignore
/// # let stream = StreamFileLayout { /* ... */ };
/// // Analyze stream properties
/// if stream.has_additional_data() {
///     println!("Stream {} has new data: {} bytes",
///              stream.name, stream.additional_data_size());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct StreamFileLayout {
    /// Stream name (e.g., "#Strings", "#Blob", "#GUID", "#US", "#~").
    pub name: String,

    /// Location in the new file with absolute offset and aligned size.
    pub file_region: FileRegion,

    /// Actual stream size in bytes (may be larger than original).
    /// Does not include alignment padding.
    pub size: u32,

    /// Whether this stream has additional data appended beyond original content.
    /// True for modified heaps with new entries.
    pub has_additions: bool,
}

impl StreamFileLayout {
    /// Checks if this stream has additional data beyond its original content.
    ///
    /// # Returns
    /// Returns `true` if the stream has additional data.
    ///
    /// # Examples
    /// ```rust,ignore
    /// if stream.has_additional_data() {
    ///     println!("Stream {} has been modified", stream.name);
    /// }
    /// ```
    pub fn has_additional_data(&self) -> bool {
        self.has_additions
    }

    /// Calculates the additional data size for this stream.
    ///
    /// This represents the amount of new data added beyond the original stream content.
    ///
    /// # Returns
    /// Returns the additional data size in bytes.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let additional = stream.additional_data_size();
    /// if additional > 0 {
    ///     println!("Stream {} grew by {} bytes", stream.name, additional);
    /// }
    /// ```
    pub fn additional_data_size(&self) -> u64 {
        if self.has_additions {
            // Calculate the difference between file region size and actual stream size
            self.file_region.size.saturating_sub(u64::from(self.size))
        } else {
            0
        }
    }

    /// Checks if this stream is aligned to a 4-byte boundary.
    ///
    /// # Returns
    /// Returns `true` if the stream is properly aligned.
    ///
    /// # Examples
    /// ```rust,ignore
    /// assert!(stream.is_aligned(), "Streams should be 4-byte aligned");
    /// ```
    pub fn is_aligned(&self) -> bool {
        self.file_region.offset % 4 == 0 && self.file_region.size % 4 == 0
    }
}
