//! Section-specific layout functionality for PE sections.
//!
//! This module provides the [`SectionFileLayout`] type and related functionality
//! for working with individual PE sections within file layouts. It includes
//! comprehensive methods for section analysis and metadata stream management.
//!
//! # Key Types
//!
//! - [`SectionFileLayout`] - Layout information for individual PE sections
//!
//! # Section Analysis
//!
//! Provides rich methods for:
//! - **Stream management**: Find, list, and check for specific metadata streams
//! - **Metadata analysis**: Work with sections containing .NET metadata
//! - **Stream queries**: Search and analyze streams within sections

use crate::{
    cilassembly::write::planner::layout::{FileRegion, StreamFileLayout},
    Error, Result,
};

/// Layout of a single section in the new file.
///
/// Contains the complete layout information for an individual PE section,
/// including its position, size, and metadata stream details if applicable.
/// Provides methods for working with section-specific functionality.
///
/// # Examples
/// ```rust,ignore
/// # let section = SectionFileLayout { /* ... */ };
/// // Find specific streams within metadata sections
/// if section.contains_metadata {
///     let blob_stream = section.find_stream_layout("#Blob")?;
///     println!("Blob stream size: {} bytes", blob_stream.size);
/// }
/// # Ok::<(), crate::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct SectionFileLayout {
    /// Section name (e.g., ".text", ".rsrc", ".reloc").
    pub name: String,

    /// Location in the new file with offset and size.
    /// May differ from original if section was relocated or resized.
    pub file_region: FileRegion,

    /// Virtual address where section is loaded in memory.
    /// May be updated if section was moved during layout planning.
    pub virtual_address: u32,

    /// Virtual size of section in memory.
    /// May be updated if section grew due to metadata additions.
    pub virtual_size: u32,

    /// Section characteristics flags from PE specification.
    /// Preserved from original section headers.
    pub characteristics: u32,

    /// Whether this section contains .NET metadata that needs updating.
    /// True for sections containing metadata streams.
    pub contains_metadata: bool,

    /// If this section contains metadata, the layout of metadata streams.
    /// Empty for non-metadata sections.
    pub metadata_streams: Vec<StreamFileLayout>,
}

impl SectionFileLayout {
    /// Finds a specific stream layout within this metadata section.
    ///
    /// This is used to locate specific metadata streams like "#Strings", "#Blob",
    /// "#GUID", "#US", "#~", etc. within this section.
    ///
    /// # Arguments
    /// * `stream_name` - The name of the stream to locate
    ///
    /// # Returns
    /// Returns a reference to the stream layout for the specified stream.
    ///
    /// # Errors
    /// Returns an error if the specified stream is not found in this section.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let strings_stream = metadata_section.find_stream_layout("#Strings")?;
    /// println!("Strings stream at offset: {}", strings_stream.file_region.offset);
    /// ```
    pub fn find_stream_layout(&self, stream_name: &str) -> Result<&StreamFileLayout> {
        self.metadata_streams
            .iter()
            .find(|stream| stream.name == stream_name)
            .ok_or_else(|| Error::WriteLayoutFailed {
                message: format!("Stream '{stream_name}' not found in metadata section"),
            })
    }

    /// Returns the names of all metadata streams in this section.
    ///
    /// # Returns
    /// Returns an iterator over the names of all metadata streams.
    ///
    /// # Examples
    /// ```rust,ignore
    /// for stream_name in metadata_section.stream_names() {
    ///     println!("Found stream: {}", stream_name);
    /// }
    /// ```
    pub fn stream_names(&self) -> impl Iterator<Item = &str> {
        self.metadata_streams
            .iter()
            .map(|stream| stream.name.as_str())
    }

    /// Checks if this section contains a specific stream.
    ///
    /// # Arguments
    /// * `stream_name` - The name of the stream to check for
    ///
    /// # Returns
    /// Returns `true` if the stream is present in this section.
    ///
    /// # Examples
    /// ```rust,ignore
    /// if metadata_section.has_stream("#Strings") {
    ///     println!("Section contains strings stream");
    /// }
    /// ```
    pub fn has_stream(&self, stream_name: &str) -> bool {
        self.metadata_streams
            .iter()
            .any(|stream| stream.name == stream_name)
    }
}
