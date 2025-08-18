// Copyright 2025 Johann Kempter
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#![doc(html_no_source)]
#![deny(missing_docs)]
#![allow(dead_code)]
//#![deny(unsafe_code)]
// - 'userstring.rs' uses a transmute for converting a &[u8] to &[u16]
// - 'file/physical.rs' uses mmap to map a file into memory

//! # dotscope
//!
//! [![Crates.io](https://img.shields.io/crates/v/dotscope.svg)](https://crates.io/crates/dotscope)
//! [![Documentation](https://docs.rs/dotscope/badge.svg)](https://docs.rs/dotscope)
//! [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/BinFlip/dotscope/blob/main/LICENSE-APACHE)
//!
//! A cross-platform framework for analyzing and reverse engineering .NET PE executables.
//! Built in pure Rust, `dotscope` provides comprehensive tooling for parsing CIL (Common Intermediate Language)
//! bytecode, metadata structures, and disassembling .NET assemblies without requiring Windows or the .NET runtime.
//!
//! # Architecture
//!
//! The library is organized into several key modules that work together to provide complete .NET assembly analysis:
//!
//! - **File Layer**: Memory-mapped file access and binary parsing
//! - **Metadata Layer**: ECMA-335 metadata parsing and type system representation  
//! - **Assembly Layer**: CIL instruction processing with complete disassembly and assembly capabilities
//! - **Validation Layer**: Configurable validation and integrity checking
//!
//! ## Key Components
//!
//! - [`crate::CilObject`] - Main entry point for .NET assembly analysis
//! - [`crate::metadata`] - Complete ECMA-335 metadata parsing and type system
//! - [`crate::assembly`] - Complete CIL instruction processing: disassembly, analysis, and assembly
//! - [`crate::prelude`] - Convenient re-exports of commonly used types
//! - [`crate::Error`] and [`crate::Result`] - Comprehensive error handling
//!
//! # Features
//!
//! - **🔍 Complete metadata analysis** - Parse all ECMA-335 metadata tables and streams
//! - **⚡ CIL processing** - Complete instruction decoding, encoding, and control flow analysis
//! - **🔧 Cross-platform** - Works on Windows, Linux, macOS, and any Rust-supported platform
//! - **🛡️ Memory safe** - Built in Rust with comprehensive error handling
//! - **📊 Rich type system** - Full support for generics, signatures, and complex .NET types
//! - **🧩 Extensible architecture** - Modular design for custom analysis and tooling
//!
//! # Usage Examples
//!
//! ## Quick Start
//!
//! Add `dotscope` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! dotscope = "0.3.2"
//! ```
//!
//! ### Using the Prelude
//!
//! For convenient access to the most commonly used types, import the prelude:
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! // Load and analyze a .NET assembly  
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//! println!("Found {} methods", assembly.methods().len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ### Basic Assembly Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::cilobject::CilObject;
//! use std::path::Path;
//!
//! // Load and parse a .NET assembly
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Access metadata
//! if let Some(module) = assembly.module() {
//!     println!("Module: {}", module.name);
//! }
//!
//! // Iterate through types and methods
//! let methods = assembly.methods();
//! println!("Found {} methods", methods.len());
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Memory-based Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::cilobject::CilObject;
//!
//! // Analyze from memory buffer
//! let binary_data: Vec<u8> = std::fs::read("assembly.dll")?;
//! let assembly = CilObject::from_mem(binary_data)?;
//!
//! // Same API as file-based analysis
//! println!("Assembly loaded from memory");
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Custom Analysis with Validation
//!
//! ```rust,no_run
//! use dotscope::{CilObject, ValidationConfig};
//!
//! fn analyze_assembly(path: &str) -> dotscope::Result<()> {
//!     // Use minimal validation for best performance
//!     let assembly = CilObject::from_file_with_validation(
//!         std::path::Path::new(path),
//!         ValidationConfig::minimal()
//!     )?;
//!     
//!     // Access imports and exports
//!     let imports = assembly.imports();
//!     let exports = assembly.exports();
//!     
//!     println!("Imports: {} items", imports.total_count());
//!     println!("Exports: {} items", exports.total_count());
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### CIL Instruction Processing
//!
//! The assembly module provides comprehensive CIL instruction processing with both disassembly
//! (bytecode to instructions) and assembly (instructions to bytecode) capabilities.
//!
//! #### Disassembly
//! ```rust,no_run
//! use dotscope::{assembly::decode_instruction, Parser};
//!
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(bytecode);
//! let instruction = decode_instruction(&mut parser, 0x1000)?;
//!
//! println!("Mnemonic: {}", instruction.mnemonic);
//! println!("Flow type: {:?}", instruction.flow_type);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! #### Assembly
//! ```rust,no_run
//! use dotscope::assembly::InstructionAssembler;
//!
//! let mut asm = InstructionAssembler::new();
//! asm.ldarg_0()?      // Load first argument
//!    .ldarg_1()?      // Load second argument
//!    .add()?          // Add them together
//!    .ret()?;         // Return result
//! let bytecode = asm.finish()?; // Returns [0x02, 0x03, 0x58, 0x2A]
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! The instruction processing seamlessly integrates with the metadata system. The [`crate::CilObject`] provides
//! access to both metadata and method bodies for comprehensive analysis workflows, while the assembly
//! system uses the same instruction metadata to ensure perfect consistency between disassembly and assembly.
//!
//! ### Metadata-Driven Disassembly
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_file(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Access raw metadata tables
//! if let Some(tables) = assembly.tables() {
//!     println!("Metadata tables present: {}", tables.table_count());
//! }
//!
//! // Access metadata heaps with indexed access and iteration
//! if let Some(strings) = assembly.strings() {
//!     let name = strings.get(1)?; // Indexed access
//!     
//!     // Iterate through all entries
//!     for (offset, string) in strings.iter() {
//!         println!("String at {}: '{}'", offset, string);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Standards Compliance
//!
//! `dotscope` implements the **ECMA-335 specification** (6th edition) for the Common Language Infrastructure.
//! All metadata structures, CIL instructions, and type system features conform to this standard.
//!
//! ### References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Official CLI specification
//! - [.NET Runtime](https://github.com/dotnet/runtime) - Microsoft's reference implementation
//!
//! # Error Handling
//!
//! All operations return [`Result<T, Error>`](Result) with comprehensive error information:
//!
//! ```rust,no_run
//! use dotscope::{Error, metadata::cilobject::CilObject};
//!
//! match CilObject::from_file(std::path::Path::new("tests/samples/crafted_2.exe")) {
//!     Ok(assembly) => println!("Successfully loaded assembly"),
//!     Err(Error::NotSupported) => println!("File format not supported"),
//!     Err(Error::Malformed { message, .. }) => println!("Malformed file: {}", message),
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```
//!
//! # Thread Safety
//!
//! All public types are [`std::marker::Send`] and [`std::marker::Sync`] unless explicitly documented otherwise. The library
//! is designed for safe concurrent access across multiple threads.
//!
//! # Development and Testing

#[macro_use]
pub(crate) mod macros;

#[macro_use]
pub(crate) mod error;
pub(crate) mod file;
pub(crate) mod utils;

/// Shared functionality which is used in unit- and integration-tests
#[cfg(test)]
pub(crate) mod test;

/// Convenient re-exports of the most commonly used types and traits.
///
/// This module provides a curated selection of the most frequently used types
/// from across the dotscope library, allowing for convenient glob imports.
///
/// # Architecture
///
/// The prelude follows Rust's standard library pattern, re-exporting the most commonly
/// used types and traits from various modules for convenient access.
///
/// # Key Components
///
/// - [`crate::CilObject`] - Main entry point for .NET assembly analysis
/// - [`crate::Error`] and [`crate::Result`] - Error handling types
/// - Core metadata types and validation configuration
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// // Now you have access to the most common types
/// let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
/// let methods = assembly.methods();
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// All re-exported types maintain their original thread safety guarantees.
pub mod prelude;

/// CIL instruction processing: disassembly, analysis, and assembly based on ECMA-335.
///
/// This module provides comprehensive CIL (Common Intermediate Language) instruction processing
/// capabilities, including both disassembly (bytecode to instructions) and assembly (instructions
/// to bytecode). It implements the complete ECMA-335 instruction set with support for control flow
/// analysis, stack effect tracking, and bidirectional instruction processing.
///
/// # Architecture
///
/// The assembly module is built around several core concepts:
/// - **Instruction Decoding**: Binary CIL bytecode to structured instruction representation
/// - **Instruction Encoding**: Structured instructions back to binary CIL bytecode
/// - **Control Flow Analysis**: Building basic blocks and analyzing program flow
/// - **Stack Effect Analysis**: Tracking how instructions affect the evaluation stack
/// - **Label Resolution**: Automatic resolution of branch targets and labels
/// - **Type Safety**: Compile-time validation of instruction operand types
///
/// # Key Components
///
/// ## Disassembly Components
/// - [`crate::assembly::decode_instruction`] - Decode a single instruction
/// - [`crate::assembly::decode_stream`] - Decode a sequence of instructions  
/// - [`crate::assembly::decode_blocks`] - Build basic blocks from instruction stream
///
/// ## Assembly Components  
/// - [`crate::assembly::InstructionEncoder`] - Low-level instruction encoding (supports all 220 CIL instructions)
/// - [`crate::assembly::InstructionAssembler`] - High-level fluent API for common instruction patterns
/// - [`crate::assembly::LabelFixup`] - Label resolution system for branch instructions
///
/// ## Shared Components
/// - [`crate::assembly::Instruction`] - Represents a decoded CIL instruction
/// - [`crate::assembly::BasicBlock`] - A sequence of instructions with single entry/exit
/// - [`crate::assembly::Operand`] - Instruction operands (immediates, tokens, targets)
/// - [`crate::assembly::FlowType`] - How instructions affect control flow
///
/// # Usage Examples
///
/// ## Disassembly
/// ```rust,no_run
/// use dotscope::{assembly::decode_instruction, Parser};
///
/// let bytecode = &[0x00, 0x2A]; // nop, ret
/// let mut parser = Parser::new(bytecode);
/// let instruction = decode_instruction(&mut parser, 0x1000)?;
///
/// println!("Mnemonic: {}", instruction.mnemonic);
/// println!("Flow type: {:?}", instruction.flow_type);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## High-Level Assembly
/// ```rust,no_run
/// use dotscope::assembly::InstructionAssembler;
///
/// let mut asm = InstructionAssembler::new();
/// asm.ldarg_0()?      // Load first argument
///    .ldarg_1()?      // Load second argument
///    .add()?          // Add them together
///    .ret()?;         // Return result
/// let bytecode = asm.finish()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Low-Level Assembly
/// ```rust,no_run
/// use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
///
/// let mut encoder = InstructionEncoder::new();
/// encoder.emit_instruction("nop", None)?;
/// encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(1))))?;
/// encoder.emit_instruction("ret", None)?;
/// let bytecode = encoder.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Integration
///
/// The assembly module integrates with the metadata system to resolve tokens and provide
/// rich semantic information about method calls, field access, and type operations. The
/// encoder and assembler use the same instruction metadata as the disassembler, ensuring
/// perfect consistency between assembly and disassembly operations.
///
/// # Thread Safety
///
/// All assembly types are [`std::marker::Send`] and [`std::marker::Sync`] for safe concurrent processing.
pub mod assembly;

/// .NET metadata parsing, loading, and type system based on ECMA-335.
///
/// This module implements the complete ECMA-335 metadata system for .NET assemblies.
/// It provides comprehensive parsing and access to all metadata tables, streams, and
/// type system constructs defined in the Common Language Infrastructure specification.
///
/// # Architecture
///
/// The metadata system is organized into several layers:
/// - **Physical Layer**: Raw binary data access and stream parsing
/// - **Logical Layer**: Structured access to metadata tables and heaps
/// - **Type System Layer**: High-level representation of .NET types and signatures
/// - **Validation Layer**: Configurable validation and integrity checking
///
/// # Key Components
///
/// ## Assembly Analysis
/// - [`crate::CilObject`] - Main entry point for assembly analysis
/// - [`crate::metadata::cor20header`] - CLR 2.0 header information
/// - [`crate::metadata::root`] - Metadata root and stream directory
///
/// ## Type System
/// - [`crate::metadata::typesystem`] - Complete .NET type system representation
/// - [`crate::metadata::signatures`] - Method and field signatures, generics support
/// - [`crate::metadata::token`] - Metadata tokens for cross-references
///
/// ## Method Body Analysis
/// - [`crate::metadata::method`] - Method body parsing and analysis
///
/// ## Metadata Streams
/// - [`crate::metadata::streams`] - All ECMA-335 metadata tables and heaps
/// - [`crate::Strings`], [`crate::Guid`], [`crate::Blob`], [`crate::UserStrings`] - String, GUID, Blob, and UserString heaps
/// - [`crate::TablesHeader`], [`crate::StreamHeader`] - Metadata tables and stream headers
///
/// ## Metadata Tables
/// - [`crate::metadata::tables`] - Assembly, Type, Method, Field, and other metadata tables
///
/// ## Import/Export Analysis  
/// - [`crate::metadata::imports`] - Analysis of imported types and methods
/// - [`crate::metadata::exports`] - Analysis of exported types and methods
/// - [`crate::metadata::resources`] - Embedded resources and manifests
///
/// ## Security and Identity
/// - [`crate::metadata::security`] - Code Access Security (CAS) permissions
/// - [`crate::metadata::identity`] - Assembly identity and verification
/// - [`crate::metadata::marshalling`] - P/Invoke and COM interop marshalling
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// // Load assembly and examine metadata
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Access basic information
/// if let Some(module) = assembly.module() {
///     println!("Module: {}", module.name);
/// }
///
/// // Examine metadata tables
/// if let Some(tables) = assembly.tables() {
///     println!("Tables present: {}", tables.table_count());
/// }
///
/// // Access type system
/// let methods = assembly.methods();
/// println!("Methods found: {}", methods.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Integration
///
/// The metadata system provides the foundation for the disassembler module, supplying
/// token resolution, type information, and method body access for comprehensive analysis.
///
/// # Thread Safety
///
/// All metadata types are [`std::marker::Send`] and [`std::marker::Sync`] for safe concurrent access.
pub mod metadata;

/// `dotscope` Result type.
///
/// A type alias for `std::result::Result<T, Error>` where the error type is always [`crate::Error`].
/// This is used consistently throughout the crate for all fallible operations.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{Result, CilObject};
///
/// fn load_assembly(path: &str) -> Result<CilObject> {
///     CilObject::from_file(std::path::Path::new(path))
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// `dotscope` Error type.
///
/// The main error type for all operations in this crate. Provides detailed error information
/// for file parsing, metadata validation, and disassembly operations.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{Error, CilObject};
///
/// match CilObject::from_file(std::path::Path::new("tests/samples/crafted_2.exe")) {
///     Ok(assembly) => println!("Loaded successfully"),
///     Err(Error::NotSupported) => println!("File format not supported"),
///     Err(Error::Malformed { message, .. }) => println!("Malformed: {}", message),
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
pub use error::Error;

/// Raw assembly view for editing and modification operations.
///
/// `CilAssemblyView` provides direct access to .NET assembly metadata structures
/// while maintaining a 1:1 mapping with the underlying file format. Unlike [`CilObject`]
/// which provides processed and resolved metadata optimized for analysis, `CilAssemblyView`
/// preserves the raw structure to enable future editing capabilities.
///
/// # Key Features
///
/// - **Raw Structure Access**: Direct access to metadata tables and streams as they appear in the file
/// - **No Validation**: Pure parsing without format validation or compliance checks
/// - **Memory Efficient**: Self-referencing pattern avoids data duplication
/// - **Thread Safe**: Immutable design enables safe concurrent access
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilAssemblyView;
/// use std::path::Path;
///
/// // Load assembly for raw metadata access
/// let view = CilAssemblyView::from_file(Path::new("assembly.dll"))?;
///
/// // Access raw metadata tables
/// if let Some(tables) = view.tables() {
///     println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
/// }
///
/// // Access string heaps directly
/// if let Some(strings) = view.strings() {
///     if let Ok(name) = strings.get(0x123) {
///         println!("Raw string: {}", name);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Converting to Mutable Assembly
///
/// `CilAssemblyView` can be converted to a mutable [`CilAssembly`] for editing operations:
///
/// ```rust,no_run
/// use dotscope::{CilAssemblyView, CilAssembly};
/// let view = CilAssemblyView::from_file(std::path::Path::new("assembly.dll"))?;
/// let mut assembly = view.to_owned(); // Convert to mutable CilAssembly
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::cilassemblyview::CilAssemblyView;

/// Mutable assembly for editing and modification operations.
///
/// `CilAssembly` provides a mutable layer on top of [`CilAssemblyView`] that enables
/// editing of .NET assembly metadata while tracking changes efficiently. It uses a
/// copy-on-write strategy to minimize memory usage and provides high-level APIs
/// for adding, modifying, and deleting metadata elements.
///
/// # Key Features
///
/// - **Change Tracking**: Efficiently tracks modifications without duplicating unchanged data
/// - **High-level APIs**: Builder patterns for creating types, methods, fields, etc.
/// - **Binary Generation**: Write modified assemblies back to disk
/// - **Validation**: Optional validation of metadata consistency
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{CilAssemblyView, CilAssembly};
///
/// // Load and convert to mutable assembly
/// let view = CilAssemblyView::from_file(std::path::Path::new("assembly.dll"))?;
/// let mut assembly = view.to_owned();
///
/// // Add a new string to the heap
/// let string_index = assembly.string_add("Hello, World!")?;
///
/// // Write changes back to file
/// assembly.write_to_file("modified_assembly.dll")?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use cilassembly::{
    BuilderContext, CilAssembly, LastWriteWinsResolver, MethodBodyBuilder, MethodBuilder,
    ReferenceHandlingStrategy,
};
mod cilassembly;

/// Main entry point for working with .NET assemblies.
///
/// See [`crate::metadata::cilobject::CilObject`] for high-level analysis and metadata access.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// let assembly = CilObject::from_file(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
/// println!("Found {} methods", assembly.methods().len());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::cilobject::CilObject;

/// Configuration for metadata validation during assembly loading.
///
/// Controls which validation checks are performed when loading .NET assemblies.
/// Different presets are available for various use cases.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{CilObject, ValidationConfig};
///
/// // Use minimal validation for best performance
/// let assembly = CilObject::from_file_with_validation(
///     std::path::Path::new("tests/samples/WindowsBase.dll"),
///     ValidationConfig::minimal()
/// )?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::validation::{ValidationConfig, ValidationEngine};

/// Metadata streams and heaps for direct access to ECMA-335 data structures.
///
/// These types provide low-level access to the metadata structures:
/// - [`crate::Blob`] - Binary blob heap for signatures and complex data
/// - [`crate::Guid`] - GUID heap for type and assembly identifiers  
/// - [`crate::Strings`] - String heap for names and identifiers
/// - [`crate::UserStrings`] - User string heap for string literals
/// - [`crate::TablesHeader`] - Metadata tables header information
/// - [`crate::StreamHeader`] - Individual stream header information
///
/// All heaps provide both indexed access via `get()` methods and iterator support
/// for efficient sequential traversal of all entries.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{CilObject, Strings};
/// let assembly = CilObject::from_file(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Access metadata heaps with indexed access and iteration
/// if let Some(strings) = assembly.strings() {
///     let name = strings.get(1)?; // Indexed access
///     
///     // Iterate through all entries
///     for (offset, string) in strings.iter() {
///         println!("String at {}: '{}'", offset, string);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// See the [`crate::metadata::streams`] module for comprehensive examples of all heap types and iterators.
pub use metadata::streams::{
    Blob, BlobIterator, Guid, GuidIterator, StreamHeader, Strings, StringsIterator, TablesHeader,
    UserStrings, UserStringsIterator,
};

/// Provides access to low-level file and memory parsing utilities.
///
/// The [`crate::Parser`] type is used for decoding CIL bytecode and metadata streams.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{Parser, assembly::decode_instruction};
/// let code = [0x2A]; // ret
/// let mut parser = Parser::new(&code);
/// let instr = decode_instruction(&mut parser, 0x1000)?;
/// assert_eq!(instr.mnemonic, "ret");
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use file::{
    parser::Parser,
    pe::{
        CoffHeader, DataDirectories, DataDirectory, DataDirectoryType, DosHeader,
        Export as PeExport, Import as PeImport, OptionalHeader, Pe, SectionTable, StandardFields,
        WindowsFields,
    },
    File,
};
