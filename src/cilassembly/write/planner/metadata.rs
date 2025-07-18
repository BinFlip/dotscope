//! Metadata layout planning and stream calculations.
//!
//! This module provides comprehensive metadata layout planning for .NET assembly modification
//! and binary generation. It handles the complex task of calculating new metadata root
//! structures, stream layouts, and modification tracking when assemblies are modified
//! and need to be written to disk with proper ECMA-335 compliance.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::planner::metadata::extract_metadata_layout`] - Main metadata layout extraction
//! - [`crate::cilassembly::write::planner::metadata::identify_metadata_modifications`] - Modification analysis
//! - [`crate::cilassembly::write::planner::metadata::MetadataLayout`] - Complete metadata structure information
//! - [`crate::cilassembly::write::planner::metadata::MetadataModifications`] - Required modification tracking
//! - [`crate::cilassembly::write::planner::metadata::StreamLayout`] - Individual stream layout information
//! - [`crate::cilassembly::write::planner::StreamModification`] - Stream modification details
//!
//! # Architecture
//!
//! The metadata layout planning system handles the complex requirements of ECMA-335 metadata:
//!
//! ## Metadata Root Structure
//! The metadata root contains:
//! - Fixed header with signature, version, and flags
//! - Variable-length version string with 4-byte alignment
//! - Stream directory with offset, size, and name for each stream
//! - All properly aligned according to ECMA-335 requirements
//!
//! ## Stream Layout Planning
//! Each metadata stream has specific requirements:
//! - **String Heap (#Strings)**: UTF-8 strings with null terminators
//! - **Blob Heap (#Blob)**: Binary data with compressed length prefixes
//! - **GUID Heap (#GUID)**: Fixed 16-byte GUIDs
//! - **UserString Heap (#US)**: UTF-16 strings with length prefixes
//! - **Tables Stream (#~ or #-)**: Compressed or uncompressed table data
//!
//! ## Modification Tracking
//! The system tracks all required modifications:
//! - Which streams need size updates in the metadata root
//! - Where additional data should be written for each heap
//! - File offsets for updating stream directory entries
//! - Proper alignment and padding requirements
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::planner::metadata::{extract_metadata_layout, identify_metadata_modifications};
//! use crate::cilassembly::write::planner::HeapExpansions;
//! use crate::cilassembly::CilAssembly;
//!
//! # let assembly = CilAssembly::empty(); // placeholder
//! // Calculate required heap expansions
//! let heap_expansions = calculate_heap_expansions(&assembly)?;
//!
//! // Extract complete metadata layout with expansions
//! let metadata_layout = extract_metadata_layout(&assembly, &heap_expansions)?;
//!
//! // Identify what modifications are needed
//! let modifications = identify_metadata_modifications(&assembly)?;
//!
//! println!("Root header size: {} bytes", metadata_layout.root_header_size);
//! println!("Streams: {}", metadata_layout.streams.len());
//! println!("Root needs update: {}", modifications.root_needs_update);
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module perform read-only analysis and calculations, making them
//! inherently thread-safe. However, they are designed for single-threaded use during
//! the layout planning phase of binary generation.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner::calc`] - Size calculation utilities
//! - [`crate::cilassembly::write::planner`] - Overall layout planning coordination
//! - [`crate::cilassembly::changes`] - Source of modification data
//! - [`crate::cilassembly::write::writers`] - Binary writing coordination

use crate::{
    cilassembly::{
        write::{
            planner::calc::{
                self, calculate_string_heap_total_size, calculate_table_stream_expansion,
                calculate_userstring_heap_total_size, HeapExpansions,
            },
            utils::align_to_4_bytes,
        },
        CilAssembly,
    },
    Error, Result,
};

/// Metadata layout information for binary generation planning.
///
/// This structure contains the complete calculated layout of the metadata section
/// including the root header size and all stream layouts with their updated sizes
/// after applying modifications.
///
/// # Usage
/// Returned by [`crate::cilassembly::write::planner::metadata::extract_metadata_layout`]
/// and used by layout planners to determine metadata section structure.
#[derive(Debug, Clone)]
pub struct MetadataLayout {
    /// Root header size in bytes.
    /// Includes metadata signature, version string, and stream directory.
    pub root_header_size: u32,

    /// Stream layouts with calculated sizes and offsets.
    /// Contains all metadata streams with their updated dimensions.
    pub streams: Vec<StreamLayout>,
}

/// Stream layout information for individual metadata streams.
///
/// Contains the calculated layout information for a single metadata stream
/// including its final size after modifications and its offset within the
/// metadata section.
#[derive(Debug, Clone)]
pub struct StreamLayout {
    /// Stream name (e.g., "#Strings", "#Blob", "#GUID", "#US", "#~").
    pub name: String,

    /// Size of this stream in bytes after all modifications.
    /// Includes original size plus any additions, properly aligned.
    pub size: u32,

    /// Offset within metadata section where this stream begins.
    /// Calculated to maintain proper stream ordering and alignment.
    pub offset: u32,
}

/// Information about metadata modifications needed for binary generation.
///
/// This structure identifies all modifications that must be applied to the metadata
/// section during binary generation, including root header updates and individual
/// stream modifications.
///
/// # Usage
/// Returned by [`crate::cilassembly::write::planner::metadata::identify_metadata_modifications`]
/// and used to coordinate the binary writing process.
#[derive(Debug, Clone)]
pub struct MetadataModifications {
    /// Whether the metadata root needs to be updated due to stream size changes.
    /// True if any heap has additions or table modifications that affect stream sizes.
    pub root_needs_update: bool,

    /// Stream modifications that need to be applied during binary generation.
    /// Contains detailed information for each modified stream.
    pub stream_modifications: Vec<StreamModification>,
}

/// Information about stream modifications for binary generation.
///
/// This structure contains all the information needed to modify a specific metadata
/// stream during binary generation, including where to write additional data and
/// where to update the stream size in the metadata root.
#[derive(Debug, Clone)]
pub struct StreamModification {
    /// Name of the stream (e.g., "#Strings", "#Blob", "#GUID", "#US", "#~").
    pub name: String,

    /// Original offset of the stream within the metadata section.
    pub original_offset: u64,

    /// Original size in bytes before modifications.
    pub original_size: u64,

    /// New size needed after all modifications are applied.
    /// Includes original size plus additions, properly aligned.
    pub new_size: u64,

    /// Additional data size to append to this stream.
    /// Does not include original stream content.
    pub additional_data_size: u64,

    /// Absolute file offset where additional data should be written.
    /// Points to the location immediately after the original stream content.
    pub write_offset: u64,

    /// Absolute file offset of the stream size field in metadata directory.
    /// Used to update the stream size in the metadata root.
    pub size_field_offset: u64,
}

/// Extract metadata layout information from the original assembly.
///
/// This function analyzes the original assembly structure and calculates the complete
/// metadata layout including updated stream sizes after applying all modifications.
/// It ensures proper ECMA-335 compliance for the final metadata structure.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to analyze
/// * `heap_expansions` - The [`crate::cilassembly::write::planner::calc::HeapExpansions`] with calculated size additions
///
/// # Returns
/// Returns [`crate::cilassembly::write::planner::metadata::MetadataLayout`] with complete structure information.
///
/// # Errors
/// Returns [`crate::Error`] if metadata structure analysis fails or stream calculations are invalid.
pub fn extract_metadata_layout(
    assembly: &CilAssembly,
    _heap_expansions: &HeapExpansions,
) -> Result<MetadataLayout> {
    let view = assembly.view();
    let streams = view.streams();

    // Calculate the root header size based on the metadata root structure
    let metadata_root = view.metadata_root();

    // Base header: signature(4) + major(2) + minor(2) + reserved(4) + length(4) = 16 bytes
    // Version string: variable length (length field specifies it)
    // Flags(2) + stream_number(2) = 4 bytes
    // Stream headers: stream_number * (offset(4) + size(4) + name_length + padding)
    let base_size = 16u32;
    let version_length = metadata_root.length;
    let post_version_size = 4u32; // flags + stream_number

    // Calculate stream headers size
    let mut stream_headers_size = 0u32;
    for stream in streams.iter() {
        // Each stream header: offset(4) + size(4) + name_length + null terminator + padding to 4-byte boundary
        let name_with_null = stream.name.len() + 1;
        let padded_name_length = align_to_4_bytes(name_with_null as u64) as u32;
        stream_headers_size += 8 + padded_name_length; // offset + size + padded name
    }

    let root_header_size = base_size + version_length + post_version_size + stream_headers_size;

    // Create stream layouts with updated sizes for modified heaps
    let mut stream_layouts = Vec::new();
    let mut current_offset = 0u32;

    for stream in streams.iter() {
        let mut size = stream.size;

        // Add expansion size for heap streams and table stream
        match stream.name.as_str() {
            "#Strings" => {
                // Check if we need heap reconstruction
                let string_changes = &assembly.changes().string_heap_changes;
                if string_changes.has_additions()
                    || string_changes.has_modifications()
                    || string_changes.has_removals()
                {
                    // Use total reconstructed heap size for any changes
                    let total_heap_size =
                        calculate_string_heap_total_size(string_changes, assembly)?;
                    size = total_heap_size as u32;
                }
            }
            "#Blob" => {
                // Check if we need heap reconstruction
                let blob_changes = &assembly.changes().blob_heap_changes;
                if blob_changes.has_additions()
                    || blob_changes.has_modifications()
                    || blob_changes.has_removals()
                {
                    // Use total reconstructed heap size for any changes
                    let total_heap_size = HeapExpansions::calculate_blob_heap_size(assembly)?;
                    size = total_heap_size as u32;
                } else {
                    // No changes, keep original size
                    size = stream.size;
                }
            }
            "#GUID" => {
                // Check if we need heap reconstruction
                let guid_changes = &assembly.changes().guid_heap_changes;
                if guid_changes.has_additions()
                    || guid_changes.has_modifications()
                    || guid_changes.has_removals()
                {
                    // Use total reconstructed heap size for any changes
                    let total_heap_size = HeapExpansions::calculate_guid_heap_size(assembly)?;
                    size = total_heap_size as u32;
                } else {
                    // No changes, keep original size
                    size = stream.size;
                }
            }
            "#US" => {
                // Check if we need heap reconstruction
                let userstring_changes = &assembly.changes().userstring_heap_changes;
                if userstring_changes.has_additions()
                    || userstring_changes.has_modifications()
                    || userstring_changes.has_removals()
                {
                    // Use total reconstructed heap size for any changes
                    let total_heap_size =
                        calculate_userstring_heap_total_size(userstring_changes, assembly)?;
                    size = total_heap_size as u32;
                } else {
                    // No changes, keep original size
                    size = stream.size;
                }
            }
            "#~" | "#-" => {
                // Add space for additional table rows
                let table_expansion = calculate_table_stream_expansion(assembly)?;
                size += table_expansion as u32;
            }
            _ => {} // Other streams remain unchanged
        }

        stream_layouts.push(StreamLayout {
            name: stream.name.clone(),
            size,
            offset: current_offset,
        });

        // Align to 4-byte boundary
        current_offset += align_to_4_bytes(size as u64) as u32;
    }

    Ok(MetadataLayout {
        root_header_size,
        streams: stream_layouts,
    })
}

/// Identifies which metadata modifications need to be applied.
///
/// This function analyzes all assembly changes to determine which parts of the metadata
/// section need to be modified during binary generation. It creates detailed modification
/// instructions for each affected stream.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] with modifications to analyze
///
/// # Returns
/// Returns [`crate::cilassembly::write::planner::metadata::MetadataModifications`] with detailed modification instructions.
///
/// # Errors
/// Returns [`crate::Error`] if modification analysis fails or stream information is invalid.
pub fn identify_metadata_modifications(assembly: &CilAssembly) -> Result<MetadataModifications> {
    let changes = assembly.changes();

    // Identify which streams need modifications
    let mut stream_modifications = Vec::new();
    if changes.string_heap_changes.has_changes() {
        stream_modifications.push(create_string_stream_modification(assembly)?);
    }

    if changes.blob_heap_changes.has_changes() {
        stream_modifications.push(create_blob_stream_modification(assembly)?);
    }

    if changes.guid_heap_changes.has_changes() {
        stream_modifications.push(create_guid_stream_modification(assembly)?);
    }

    if changes.userstring_heap_changes.has_changes() {
        stream_modifications.push(create_userstring_stream_modification(assembly)?);
    }

    // Check if table stream needs modification due to table additions
    if !changes.table_changes.is_empty() {
        stream_modifications.push(create_table_stream_modification(assembly)?);
    }

    Ok(MetadataModifications {
        root_needs_update: !stream_modifications.is_empty(),
        stream_modifications,
    })
}

/// Creates stream modification info for the string heap.
///
/// Calculates modification details for the #Strings heap including size calculations
/// and file offset determinations for binary generation.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing string additions
fn create_string_stream_modification(assembly: &CilAssembly) -> Result<StreamModification> {
    let view = assembly.view();

    // Find the stream in the original file
    let stream = view
        .streams()
        .iter()
        .find(|s| s.name == "#Strings")
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: "Stream #Strings not found in original file".to_string(),
        })?;

    let (write_offset, size_field_offset) = calculate_stream_offsets(assembly, "#Strings")?;

    let string_changes = &assembly.changes().string_heap_changes;

    let (new_size, additional_data_size) = if string_changes.has_changes() {
        // Heap writer always does reconstruction for ANY changes, so use total reconstructed heap size
        let total_heap_size = calculate_string_heap_total_size(string_changes, assembly)?;
        let additional = total_heap_size.saturating_sub(stream.size as u64);
        (total_heap_size, additional)
    } else {
        // No changes at all
        (stream.size as u64, 0)
    };

    Ok(StreamModification {
        name: "#Strings".to_string(),
        original_offset: stream.offset as u64,
        original_size: stream.size as u64,
        new_size,
        additional_data_size,
        write_offset,
        size_field_offset,
    })
}

/// Creates stream modification info for the blob heap.
///
/// Calculates modification details for the #Blob heap including compressed length
/// prefix calculations and file offset determinations.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<Vec<u8>>`] containing blob additions
fn create_blob_stream_modification(assembly: &CilAssembly) -> Result<StreamModification> {
    let view = assembly.view();

    // Find the stream in the original file
    let stream = view
        .streams()
        .iter()
        .find(|s| s.name == "#Blob")
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: "Stream #Blob not found in original file".to_string(),
        })?;

    let (write_offset, size_field_offset) = calculate_stream_offsets(assembly, "#Blob")?;

    let blob_changes = &assembly.changes().blob_heap_changes;
    let (new_size, additional_data_size) = if blob_changes.has_changes() {
        // Calculate the total size needed for the blob heap
        let total_blob_heap_size = HeapExpansions::calculate_blob_heap_size(assembly)?;
        let additional = total_blob_heap_size.saturating_sub(stream.size as u64);
        (total_blob_heap_size, additional)
    } else {
        (stream.size as u64, 0)
    };

    Ok(StreamModification {
        name: "#Blob".to_string(),
        original_offset: stream.offset as u64,
        original_size: stream.size as u64,
        new_size,
        additional_data_size,
        write_offset,
        size_field_offset,
    })
}

/// Creates stream modification info for the GUID heap.
///
/// Calculates modification details for the #GUID heap with fixed 16-byte entries
/// and file offset determinations.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<[u8; 16]>`] containing GUID additions
fn create_guid_stream_modification(assembly: &CilAssembly) -> Result<StreamModification> {
    let view = assembly.view();

    // Find the stream in the original file
    let stream = view
        .streams()
        .iter()
        .find(|s| s.name == "#GUID")
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: "Stream #GUID not found in original file".to_string(),
        })?;

    let (write_offset, size_field_offset) = calculate_stream_offsets(assembly, "#GUID")?;

    let guid_changes = &assembly.changes().guid_heap_changes;
    let (new_size, additional_data_size) = if guid_changes.has_changes() {
        // Calculate the total size needed for the GUID heap
        let total_guid_heap_size = HeapExpansions::calculate_guid_heap_size(assembly)?;
        let additional = total_guid_heap_size.saturating_sub(stream.size as u64);
        (total_guid_heap_size, additional)
    } else {
        (stream.size as u64, 0)
    };

    Ok(StreamModification {
        name: "#GUID".to_string(),
        original_offset: stream.offset as u64,
        original_size: stream.size as u64,
        new_size,
        additional_data_size,
        write_offset,
        size_field_offset,
    })
}

/// Creates stream modification info for the userstring heap.
///
/// Calculates modification details for the #US heap including UTF-16 encoding,
/// compressed length prefixes, and file offset determinations.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for context
/// * `heap_changes` - The [`crate::cilassembly::HeapChanges<String>`] containing user string additions
fn create_userstring_stream_modification(assembly: &CilAssembly) -> Result<StreamModification> {
    let view = assembly.view();

    // Find the stream in the original file
    let stream = view
        .streams()
        .iter()
        .find(|s| s.name == "#US")
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: "Stream #US not found in original file".to_string(),
        })?;

    let (write_offset, size_field_offset) = calculate_stream_offsets(assembly, "#US")?;

    let userstring_changes = &assembly.changes().userstring_heap_changes;
    let (new_size, additional_data_size) = if userstring_changes.has_changes() {
        // Use the same function as metadata layout planning for consistency
        let total_heap_size = calculate_userstring_heap_total_size(userstring_changes, assembly)?;
        let additional = total_heap_size.saturating_sub(stream.size as u64);
        (total_heap_size, additional)
    } else {
        (stream.size as u64, 0)
    };

    Ok(StreamModification {
        name: "#US".to_string(),
        original_offset: stream.offset as u64,
        original_size: stream.size as u64,
        new_size,
        additional_data_size,
        write_offset,
        size_field_offset,
    })
}

/// Creates stream modification info for the table stream.
///
/// Calculates modification details for the table stream (#~ or #-) including
/// additional rows and file offset determinations.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] containing table modifications
fn create_table_stream_modification(assembly: &CilAssembly) -> Result<StreamModification> {
    let view = assembly.view();

    // Find the table stream in the original file
    let stream = view
        .streams()
        .iter()
        .find(|s| s.name == "#~" || s.name == "#-")
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: "Table stream (#~ or #-) not found in original file".to_string(),
        })?;

    let additional_data_size = calc::calculate_table_stream_expansion(assembly)?;
    let raw_new_size = stream.size as u64 + additional_data_size;
    let aligned_new_size = align_to_4_bytes(raw_new_size);

    let (write_offset, size_field_offset) = calculate_stream_offsets(assembly, &stream.name)?;

    Ok(StreamModification {
        name: stream.name.clone(),
        original_offset: stream.offset as u64,
        original_size: stream.size as u64,
        new_size: aligned_new_size,
        additional_data_size,
        write_offset,
        size_field_offset,
    })
}

/// Calculates the absolute file offsets for stream operations.
///
/// Determines where to write additional stream data and where to update the
/// stream size field in the metadata root directory.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for file structure analysis
/// * `stream_name` - Name of the stream to calculate offsets for
///
/// # Returns
/// Returns (write_offset, size_field_offset) tuple with absolute file positions.
fn calculate_stream_offsets(assembly: &CilAssembly, stream_name: &str) -> Result<(u64, u64)> {
    // Get the metadata root offset
    let metadata_root_offset = get_metadata_root_offset(assembly)?;

    // Find the stream in the original layout
    let view = assembly.view();
    let stream = view
        .streams()
        .iter()
        .find(|s| s.name == stream_name)
        .ok_or_else(|| Error::WriteLayoutFailed {
            message: format!("Stream '{stream_name}' not found in original file"),
        })?;

    // Write offset is where the additional data should be appended
    // (after the original stream content)
    let write_offset = metadata_root_offset as u64 +
        view.metadata_root().length as u64 + 20 + // root header size
        stream.offset as u64 +
        stream.size as u64;

    // Size field offset is where the stream size is stored in the stream directory
    // We need to parse the stream directory to find this
    let size_field_offset =
        find_stream_size_field_offset(assembly, metadata_root_offset, stream_name)?;

    Ok((write_offset, size_field_offset))
}

/// Gets the metadata root file offset.
///
/// Converts the metadata RVA from the COR20 header to an absolute file offset
/// using the PE section mappings.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to analyze
fn get_metadata_root_offset(assembly: &CilAssembly) -> Result<usize> {
    let cor20_header = assembly.view().cor20header();
    let file = assembly.view().file();
    file.rva_to_offset(cor20_header.meta_data_rva as usize)
        .map_err(|e| Error::WriteLayoutFailed {
            message: format!("Failed to convert metadata RVA to file offset: {e}"),
        })
}

/// Finds the offset where a stream's size field is stored in the metadata stream directory.
///
/// Parses the metadata stream directory to locate the size field for a specific stream.
/// This offset is used to update the stream size during binary generation.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] for stream directory analysis
/// * `metadata_root_offset` - Absolute file offset of the metadata root
/// * `stream_name` - Name of the stream to locate
fn find_stream_size_field_offset(
    assembly: &CilAssembly,
    metadata_root_offset: usize,
    stream_name: &str,
) -> Result<u64> {
    let view = assembly.view();
    let metadata_root = view.metadata_root();

    // Stream directory starts after the metadata root header
    let version_length = metadata_root.length as usize;
    let stream_directory_offset = metadata_root_offset + 16 + version_length + 4;

    // Iterate through stream entries to find the target stream
    let mut current_offset = stream_directory_offset;
    for stream in view.streams().iter() {
        if stream.name == stream_name {
            // The size field is at current_offset + 4 (after the offset field)
            return Ok(current_offset as u64 + 4);
        }

        // Move to next entry: offset(4) + size(4) + name + null + padding
        let name_with_null = stream.name.len() + 1;
        let padded_name_length = (name_with_null + 3) & !3; // Round up to 4-byte boundary
        current_offset += 8 + padded_name_length;
    }

    Err(Error::WriteLayoutFailed {
        message: format!("Stream '{stream_name}' not found in stream directory"),
    })
}

/// Calculates the size of the metadata root header.
///
/// Computes the total size of the metadata root header including the base header,
/// version string, flags, and complete stream directory according to ECMA-335.
///
/// # Arguments
/// * `assembly` - The [`crate::cilassembly::CilAssembly`] to analyze
///
/// # Returns
/// Returns the total metadata root header size in bytes.
pub fn calculate_metadata_root_header_size(assembly: &CilAssembly) -> Result<u64> {
    let view = assembly.view();
    let streams = view.streams();

    // Metadata root header:
    // - 16 bytes: signature, major version, minor version, reserved, length
    // - Version string (variable length, null-padded to 4-byte boundary)
    // - 2 bytes: flags, number of streams
    // - Stream directory entries (12 bytes each: offset, size, name)

    let mut size = 16u64; // Base header

    // Add version string size (use the original metadata root's length field)
    let metadata_root = view.metadata_root();
    size += metadata_root.length as u64;

    size += 4; // Flags (2 bytes) and stream count (2 bytes)

    // Add stream directory size
    for stream in streams {
        size += 8; // Offset and size fields
        let name_size = ((stream.name.len() + 1 + 3) & !3) as u64; // Name + null + align
        size += name_size;
    }

    Ok(size)
}

/// Gets the metadata version string from the original file.
///
/// Returns a standard .NET metadata version string. In a complete implementation,
/// this would read the actual version string from the original metadata root.
///
/// # Returns
/// Returns a version string compatible with .NET metadata requirements.
fn get_metadata_version_string() -> String {
    // For now, we'll use a standard version string
    // In a complete implementation, we'd read this from the original metadata root
    "v4.0.30319".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CilAssemblyView;
    use std::path::Path;

    #[test]
    fn test_extract_metadata_layout() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let heap_expansions =
            HeapExpansions::calculate(&assembly).expect("Should calculate heap expansions");

        let metadata_layout = extract_metadata_layout(&assembly, &heap_expansions)
            .expect("Should extract metadata layout");

        assert!(
            metadata_layout.root_header_size > 0,
            "Root header size should be positive"
        );
        assert!(!metadata_layout.streams.is_empty(), "Should have streams");

        // Verify we have expected streams
        let stream_names: Vec<&str> = metadata_layout
            .streams
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            stream_names.contains(&"#Strings"),
            "Should have #Strings stream"
        );
        assert!(stream_names.contains(&"#Blob"), "Should have #Blob stream");
    }

    #[test]
    fn test_identify_metadata_modifications() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let modifications =
            identify_metadata_modifications(&assembly).expect("Should identify modifications");

        // For an unmodified assembly, no modifications should be needed
        assert!(
            !modifications.root_needs_update,
            "Unmodified assembly should not need root updates"
        );
        assert!(
            modifications.stream_modifications.is_empty(),
            "Unmodified assembly should have no stream modifications"
        );
    }

    #[test]
    fn test_calculate_metadata_root_header_size() {
        let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly = view.to_owned();

        let header_size =
            calculate_metadata_root_header_size(&assembly).expect("Should calculate header size");

        assert!(header_size > 20, "Header size should be at least 20 bytes");
        assert!(header_size < 1024, "Header size should be reasonable");
    }
}
