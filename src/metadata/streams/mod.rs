//! Metadata streams for .NET assemblies.
//!
//! This module implements the parsing and representation of metadata streams according to
//! the ECMA-335 standard. Streams store different types of CIL-related data including
//! metadata tables, string heaps, binary data, and GUIDs.
//!
//! # Stream Types
//!
//! The .NET metadata format defines five standard stream types, each serving a specific purpose:
//!
//! ## String Heaps
//! - **`#Strings`** - UTF-8 identifier strings heap containing type names, member names, etc.
//!   The first entry is always null (`\0`). All valid entries are null-terminated.
//! - **`#US`** - UTF-16 user string heap containing string literals from IL code.
//!   Each entry includes a length prefix and terminal byte for special character handling.
//!
//! ## Binary Data
//! - **`#Blob`** - Binary heap containing signatures, custom attribute data, and other
//!   variable-length binary structures referenced by metadata tables.
//! - **`#GUID`** - Sequence of 128-bit GUIDs used for assembly identity and versioning.
//!
//! ## Metadata Tables
//! - **`#~`** - Compressed metadata tables containing type definitions, method signatures,
//!   field layouts, and all structural information about the assembly.
//!
//! # Iterator Support
//!
//! All heap types (Strings, UserStrings, Blob, Guid) provide both indexed access via `get()`
//! methods and efficient iterator support for sequential traversal of all entries. Iterators
//! provide efficient access and delegate to the parent heap's parsing logic for consistency.
//!
//! # Examples
//!
//! ```rust, no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//! let file = assembly.file();
//!
//! // Access string heap
//! if let Some(strings) = assembly.strings() {
//!     let type_name = strings.get(0x123)?; // Get string at offset 0x123
//!     
//!     // Iterate through all strings in the heap
//!     for result in strings.iter() {
//!         match result {
//!             Ok((offset, string)) => println!("String at {}: '{}'", offset, string),
//!             Err(e) => eprintln!("Error: {}", e),
//!         }
//!     }
//! }
//!
//! // Access blob heap for signatures
//! if let Some(blob) = assembly.blob() {
//!     let signature_data = blob.get(1)?; // Get blob at offset 1
//!     
//!     // Iterate through all blobs
//!     for result in blob.iter() {
//!         match result {
//!             Ok((offset, blob_data)) => println!("Blob at {}: {} bytes", offset, blob_data.len()),
//!             Err(e) => eprintln!("Error: {}", e),
//!         }
//!     }
//! }
//!
//! // Access GUID heap for assembly identifiers
//! if let Some(guid) = assembly.guids() {
//!     let assembly_guid = guid.get(1)?; // Get GUID at index 1
//!     
//!     // Iterate through all GUIDs
//!     for result in guid.iter() {
//!         match result {
//!             Ok((index, guid_bytes)) => println!("GUID at {}: {:?}", index, guid_bytes),
//!             Err(e) => eprintln!("Error: {}", e),
//!         }
//!     }
//! }
//!
//! // Access user strings heap for string literals
//! if let Some(user_strings) = assembly.userstrings() {
//!     let literal = user_strings.get(0x100)?; // Get user string at offset 0x100
//!     
//!     // Iterate through all user strings  
//!     for result in user_strings.iter() {
//!         match result {
//!             Ok((offset, string)) => println!("User string at {}: '{}'", offset, string.to_string_lossy()),
//!             Err(e) => eprintln!("Error: {}", e),
//!         }
//!     }
//! }
//!
//! // Access metadata tables
//! if let Some(tables) = assembly.tables() {
//!     let table_count = tables.table_count();
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Implementation Notes
//!
//! - All streams use compressed integer encoding for sizes and offsets
//! - String heaps use null-terminated UTF-8/UTF-16 encoding
//! - Blob heap entries are prefixed with compressed length values
//! - Metadata tables use token-based cross-references between entries
//!
//! # References
//!
//! - ECMA-335 6th Edition, Partition II, Section 24.2.2 - Stream Headers
//! - ECMA-335 6th Edition, Partition II, Section 22 - Metadata Tables

/// The header of a stream, indicates location + size + name
mod streamheader;
pub use streamheader::StreamHeader;

/// The '#String' heap implementation
mod strings;
pub use strings::{Strings, StringsIterator};

/// The '#US' heap implementation
mod userstrings;
pub use userstrings::{UserStrings, UserStringsIterator};

/// The '#~' / '#-' implementation
mod tablesheader;
pub use tablesheader::TablesHeader;

/// The '#GUID' heap / array implementation
mod guid;
pub use guid::{Guid, GuidIterator};

/// The '#Blob' heap implementation
mod blob;
pub use blob::{Blob, BlobIterator};
