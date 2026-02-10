//! Custom debug information parsing for Portable PDB format.
//!
//! This module provides comprehensive parsing capabilities for custom debug information
//! used in Portable PDB files. Custom debug information allows compilers and tools to
//! store additional debugging metadata beyond the standard format, including source link
//! information, embedded source files, and compiler-specific debugging data.
//!
//! # Architecture
//!
//! The module implements parsing for the `CustomDebugInformation` metadata table,
//! which contains compiler-specific debug information stored as GUID-identified blobs.
//! Each entry consists of a GUID that identifies the information type and a blob
//! containing the binary data in a format specific to that GUID.
//!
//! ## Debug Information Structure
//!
//! - **GUID Identification**: Each custom debug information type is identified by a unique GUID
//! - **Blob Data**: The actual debug information stored in binary format in the blob heap
//! - **Type-Specific Parsing**: Different parsing strategies based on the GUID value
//! - **Extensible Design**: Support for new debug information types through GUID registration
//!
//! # Key Components
//!
//! - [`crate::metadata::customdebuginformation::CustomDebugInfo`] - Parsed debug information variants
//! - [`crate::metadata::customdebuginformation::CustomDebugKind`] - GUID-based type identification
//! - [`crate::metadata::customdebuginformation::parse_custom_debug_blob`] - Main parsing function
//! - Support for standard debug information types (SourceLink, EmbeddedSource, etc.)
//!
//! # Usage Examples
//!
//! ## Basic Custom Debug Information Parsing
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind};
//!
//! // Parse a Source Link blob
//! let kind = CustomDebugKind::SourceLink;
//! let blob_data = b"{\"documents\":{}}";
//! let debug_info = parse_custom_debug_blob(blob_data, kind)?;
//!
//! // Process different types of debug information
//! match debug_info {
//!     CustomDebugInfo::SourceLink { document } => {
//!         println!("Source link JSON: {}", document);
//!     }
//!     CustomDebugInfo::EmbeddedSource { filename, content, was_compressed } => {
//!         println!("Embedded source: {} ({} bytes, compressed: {})",
//!                  filename, content.len(), was_compressed);
//!     }
//!     CustomDebugInfo::CompilationMetadata { metadata } => {
//!         println!("Compilation metadata: {}", metadata);
//!     }
//!     CustomDebugInfo::CompilationOptions { options } => {
//!         println!("Compilation options: {}", options);
//!     }
//!     CustomDebugInfo::Unknown { kind, data } => {
//!         println!("Unknown debug info type: {} ({} bytes)", kind, data.len());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Working with Source Link Information
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind};
//!
//! // Source Link JSON contains repository URL mappings
//! let kind = CustomDebugKind::SourceLink;
//! let blob_data = br#"{"documents":{"C:\\src\\*.cs":"https://raw.githubusercontent.com/user/repo/*"}}"#;
//! let debug_info = parse_custom_debug_blob(blob_data, kind)?;
//!
//! if let CustomDebugInfo::SourceLink { document } = debug_info {
//!     println!("Source Link JSON: {}", document);
//!
//!     // The document contains JSON that can be parsed with any JSON library
//!     assert!(document.contains("documents"));
//!     assert!(document.contains("github"));
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Processing Embedded Source Files
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind};
//!
//! // Embedded source blob: int32 format (0=raw, >0=compressed size) + content
//! let kind = CustomDebugKind::EmbeddedSource;
//! let mut blob_data = Vec::new();
//! blob_data.extend_from_slice(&0i32.to_le_bytes()); // format = 0 (uncompressed)
//! blob_data.extend_from_slice(b"using System;\n\nclass Program { }");
//! let debug_info = parse_custom_debug_blob(&blob_data, kind)?;
//!
//! if let CustomDebugInfo::EmbeddedSource { filename, content, was_compressed } = debug_info {
//!     // Note: filename comes from Document table, not the blob
//!     println!("File size: {} bytes", content.len());
//!     println!("Was compressed: {}", was_compressed);
//!
//!     // Count lines in the source
//!     let line_count = content.lines().count();
//!     println!("Source lines: {}", line_count);
//!     assert_eq!(line_count, 3);
//!     assert!(!was_compressed);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! All parsing operations return [`crate::Result<T>`] with comprehensive error information:
//! - **Format errors**: When blob data doesn't conform to expected format
//! - **Encoding errors**: When string data contains invalid UTF-8
//! - **Size errors**: When blob size doesn't match expected content
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe. The debug information types
//! contain only owned data and are [`std::marker::Send`] and [`std::marker::Sync`].
//! The parsing functions are stateless and can be called concurrently from multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - `CustomDebugInformation` table access
//! - [`crate::metadata::streams`] - GUID and blob heap access for debug data
//! - Low-level binary data parsing utilities
//! - [`crate::Error`] - Comprehensive error handling and reporting
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: Full compliance with Portable PDB format specification
//! - **GUID Standards**: Proper GUID handling according to RFC 4122
//! - **UTF-8 Encoding**: Correct handling of text data in debug information
//! - **Binary Format**: Accurate parsing of little-endian binary data
//!
//! # References
//!
//! - [Portable PDB Format Specification](https://github.com/dotnet/designs/blob/main/accepted/2020/diagnostics/portable-pdb.md)
//! - [CustomDebugInformation Table](https://github.com/dotnet/designs/blob/main/accepted/2020/diagnostics/portable-pdb.md#customdebuginformation-table-0x37)

mod parser;
mod types;

// Re-export all types
pub use parser::{parse_custom_debug_blob, CustomDebugParser};
pub use types::{debug_guids, CustomDebugInfo, CustomDebugKind};
