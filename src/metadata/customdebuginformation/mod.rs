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
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo};
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//!
//! # fn get_custom_debug_data() -> (uuid::Uuid, &'static [u8]) {
//! #     (uuid::Uuid::new_v4(), &[0x01, 0x02, 0x03])
//! # }
//! let (guid, blob_data) = get_custom_debug_data();
//!
//! if let Some(blob_heap) = assembly.blob() {
//!     let debug_info = parse_custom_debug_blob(blob_data, &guid, blob_heap)?;
//!     
//!     // Process different types of debug information
//!     match debug_info {
//!         CustomDebugInfo::SourceLink { url } => {
//!             println!("Source link: {}", url);
//!         }
//!         CustomDebugInfo::EmbeddedSource { filename, content } => {
//!             println!("Embedded source: {} ({} bytes)", filename, content.len());
//!         }
//!         CustomDebugInfo::Unknown { kind, data } => {
//!             println!("Unknown debug info type: {:?} ({} bytes)", kind, data.len());
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Working with Source Link Information
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::{CustomDebugInfo, CustomDebugKind};
//!
//! # fn get_debug_info() -> dotscope::metadata::customdebuginformation::CustomDebugInfo {
//! #     CustomDebugInfo::SourceLink { url: "https://example.com".to_string() }
//! # }
//! let debug_info = get_debug_info();
//!
//! if let CustomDebugInfo::SourceLink { url } = debug_info {
//!     println!("Source repository: {}", url);
//!     
//!     // Extract domain from URL for security analysis
//!     if let Ok(parsed_url) = url::Url::parse(&url) {
//!         if let Some(host) = parsed_url.host_str() {
//!             println!("Source host: {}", host);
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Processing Embedded Source Files
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::CustomDebugInfo;
//!
//! # fn get_embedded_source() -> dotscope::metadata::customdebuginformation::CustomDebugInfo {
//! #     CustomDebugInfo::EmbeddedSource {
//! #         filename: "Program.cs".to_string(),
//! #         content: b"using System;".to_vec()
//! #     }
//! # }
//! let debug_info = get_embedded_source();
//!
//! if let CustomDebugInfo::EmbeddedSource { filename, content } = debug_info {
//!     println!("Embedded file: {}", filename);
//!     println!("File size: {} bytes", content.len());
//!     
//!     // Check for source code content
//!     if let Ok(source_text) = std::str::from_utf8(&content) {
//!         let line_count = source_text.lines().count();
//!         println!("Source lines: {}", line_count);
//!     } else {
//!         println!("Binary embedded file");
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
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

// Re-export the main parsing function
pub use parser::parse_custom_debug_blob;

// Re-export all types
pub use types::{CustomDebugInfo, CustomDebugKind};
