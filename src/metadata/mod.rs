//! Metadata parsing and representation for .NET assemblies.
//!
//! This module contains the core metadata parsing infrastructure for .NET PE files.
//! It provides comprehensive support for parsing metadata tables, streams, and type
//! information according to the ECMA-335 standard.
//!
//! # Key Components
//!
//! - [`CilObject`](cilobject) - Main assembly representation with metadata and IL code
//! - [`method`] - Complete method analysis and IL disassembly
//! - Method body parsing, exception handlers, and local variables
//! - IL instruction decoding and basic block construction
//! - [`token`] - Metadata table row references used throughout .NET
//! - [`typesystem`] - Complete .NET type system representation
//! - [`signatures`] - Method and type signature parsing
//! - [`streams`] - Metadata stream parsing (strings, blobs, GUIDs, etc.)
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! // Load and parse a .NET assembly
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//!
//! // Access metadata
//! if let Some(assembly_info) = assembly.assembly() {
//!     println!("Assembly: {}", assembly_info.name);
//! }
//! println!("Methods: {}", assembly.methods().len());
//! println!("Types: {}", assembly.types().len());
//! # Ok::<(), dotscope::Error>(())
//! ```

/// Implementation of a loaded + parsed CIL binary
pub mod cilobject;
/// Implementation of the Header of CIL
pub mod cor20header;
/// Implementation of custom attribute parsing and representation
pub mod customattributes;
/// Implementation of 'Exports' by the loaded binary
pub mod exports;
/// Implementation of the verification mechanism of an `Assembly`
pub mod identity;
/// Implementation of methods that are imported from other binaries (native or .net)
pub mod imports;
/// Implementation of our MetaDataTable loader
pub(crate) mod loader;
/// Implementation of the type marshalling for native code invokations
pub mod marshalling;
/// Implementation of the MethodHeader of CIL
pub mod method;
/// Implementation of the .NET resources
pub mod resources;
/// Implementation of the root metadata structure
pub mod root;
/// Implementation of the .NET security model
pub mod security;
/// Implementation of method and type signatures
pub mod signatures;
/// Implementation of all metadata streams (tables, heaps, etc.)
pub mod streams;
/// Implementation of the .NET metadata tables
pub mod tables;
/// Commonly used metadata token type
pub mod token;
/// Implementation of the .NET type system
pub mod typesystem;
/// Metadata validation utilities
pub mod validation;
