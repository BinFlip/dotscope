//! Custom debug information parsing for Portable PDB format.
//!
//! This module provides comprehensive parsing capabilities for custom debug information
//! used in Portable PDB files. Custom debug information allows compilers and tools to
//! store additional debugging metadata beyond the standard format, including source link
//! information, embedded source files, and compiler-specific debugging data.
//!
//! # Custom Debug Information Format
//!
//! Custom debug information is stored in the CustomDebugInformation table and consists
//! of a GUID identifying the information type and a blob containing the actual data.
//! The blob format varies depending on the GUID type.
//!
//! # Key Components
//!
//! - **Types**: Custom debug information types and enums ([`crate::metadata::customdebuginformation::CustomDebugKind`], [`crate::metadata::customdebuginformation::CustomDebugInfo`])
//! - **Parser**: Binary blob parsing functionality ([`crate::metadata::customdebuginformation::parse_custom_debug_blob`])
//! - **Integration**: Seamless integration with the broader metadata system
//!
//! # Examples
//!
//! ## Basic Custom Debug Information Parsing
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo};
//! use dotscope::metadata::streams::Guid;
//!
//! // Parse custom debug blob from CustomDebugInformation table
//! let guid = guid_stream.get(kind_index)?;
//! let debug_info = parse_custom_debug_blob(blob_data, guid, blobs_heap)?;
//!
//! // Process debug information
//! match debug_info {
//!     CustomDebugInfo::SourceLink { url } => {
//!         println!("Source link: {}", url);
//!     }
//!     CustomDebugInfo::EmbeddedSource { filename, content } => {
//!         println!("Embedded source: {} ({} bytes)", filename, content.len());
//!     }
//!     CustomDebugInfo::Unknown { kind, data } => {
//!         println!("Unknown debug info type: {:?}", kind);
//!     }
//! }
//! ```
//!
//! # Format Specification
//!
//! Based on the Portable PDB format specification:
//! - [Portable PDB Format - CustomDebugInformation Table](https://github.com/dotnet/designs/blob/main/accepted/2020/diagnostics/portable-pdb.md)
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe and can be used
//! concurrently across multiple threads.

mod parser;
mod types;

// Re-export the main parsing function
pub use parser::parse_custom_debug_blob;

// Re-export all types
pub use types::{CustomDebugInfo, CustomDebugKind};
