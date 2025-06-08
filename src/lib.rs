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
#![allow(clippy::too_many_arguments)]
//#![deny(unsafe_code)]
// - 'userstring.rs' uses a transmute for converting a &[u8] to &[u16]
// - 'tableheader.rs' uses a transmute for type conversion
// - 'file/physical.rs' uses mmap to map a file into memory

//! # dotscope
//!
//! [![Crates.io](https://img.shields.io/crates/v/dotscope.svg)](https://crates.io/crates/dotscope)
//! [![Documentation](https://docs.rs/dotscope/badge.svg)](https://docs.rs/dotscope)
//! [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/BinFlip/dotscope/blob/main/LICENSE-APACHE)
//!
//! A high-performance, cross-platform framework for analyzing and reverse engineering .NET PE executables.
//! Built in pure Rust, `dotscope` provides comprehensive tooling for parsing CIL (Common Intermediate Language)
//! bytecode, metadata structures, and disassembling .NET assemblies without requiring Windows or the .NET runtime.
//!
//! ## Features
//!
//! - **📦 Efficient memory access** - Memory-mapped file access with minimal allocations and reference-based parsing
//! - **🔍 Complete metadata analysis** - Parse all ECMA-335 metadata tables and streams
//! - **⚡ High-performance disassembly** - Fast CIL instruction decoding with control flow analysis
//! - **🔧 Cross-platform** - Works on Windows, Linux, macOS, and any Rust-supported platform
//! - **🛡️ Memory safe** - Built in Rust with comprehensive error handling
//! - **📊 Rich type system** - Full support for generics, signatures, and complex .NET types
//! - **🧩 Extensible architecture** - Modular design for custom analysis and tooling
//!
//! ## Quick Start
//!
//! Add `dotscope` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! dotscope = "0.1"
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
//! ### Basic Usage
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
//! ### Disassembly Example
//!
//! The disassembler module provides comprehensive CIL instruction decoding and control flow analysis.
//! See the [`disassembler`] module documentation for detailed usage examples.
//!
//! ## Architecture
//!
//! `dotscope` is organized into several key modules:
//!
//! - [`prelude`] - Convenient re-exports of commonly used types and traits
//! - [`metadata`] - Complete ECMA-335 metadata parsing and type system
//! - [`disassembler`] - CIL instruction decoding and control flow analysis  
//! - [`Error`] and [`Result`] - Comprehensive error handling
//!
//! ### Metadata Analysis
//!
//! The [`metadata::cilobject::CilObject`] is the main entry point for analyzing .NET assemblies.
//! It provides access to:
//!
//! - **Streams**: Strings, user strings, GUIDs, and blob heaps
//! - **Tables**: All ECMA-335 metadata tables (types, methods, fields, etc.)
//! - **Type System**: Rich representation of .NET types and signatures
//! - **Resources**: Embedded resources and manifest information
//! - **Security**: Code access security and permission sets
//!
//! ### Disassembly Engine
//!
//! The [`disassembler`] module provides:
//!
//! - **Instruction Decoding**: Parse individual CIL opcodes with full operand support
//! - **Control Flow Analysis**: Build basic blocks and control flow graphs
//! - **Stack Analysis**: Track stack effects and type flow
//! - **Exception Handling**: Parse and analyze try/catch/finally regions
//!
//! ## Advanced Usage
//!
//! ### Custom Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::cilobject::CilObject;
//!
//! fn analyze_assembly(path: &str) -> dotscope::Result<()> {
//!     let assembly = CilObject::from_file(std::path::Path::new(path))?;
//!     
//!     // Access raw metadata tables
//!     if let Some(tables) = assembly.tables() {
//!         println!("Metadata tables present: {}", tables.table_count());
//!     }
//!     
//!     // Examine imports and exports
//!     let imports = assembly.imports();
//!     let exports = assembly.exports();
//!     
//!     println!("Imports: {} items", imports.len());
//!     println!("Exports: {} items", exports.len());
//!     
//!     Ok(())
//! }
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
//! ## Standards Compliance
//!
//! `dotscope` implements the **ECMA-335 specification** (6th edition) for the Common Language Infrastructure.
//! All metadata structures, CIL instructions, and type system features conform to this standard.
//!
//! ### References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Official CLI specification
//! - [.NET Runtime](https://github.com/dotnet/runtime) - Microsoft's reference implementation
//!
//! ## Performance
//!
//! `dotscope` is designed for high-performance analysis:
//!
//! - **Efficient memory access** - Memory-mapped files with reference-based parsing where possible
//! - **Lazy evaluation** of metadata structures
//! - **Parallel processing** support for batch analysis
//! - **Minimal allocations** through careful memory management
//!
//! Benchmarks show parsing times in the milliseconds for typical assemblies.
//!
//! ## Error Handling
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
//! ## Development and Testing
//!
//! The crate includes comprehensive fuzzing support for security and robustness:
//!
//! ### Fuzzing
//!
//! ```bash
//! # Install fuzzing tools
//! cargo install cargo-fuzz cargo-llvm-cov cargo-binutils
//!
//! # Run fuzzer
//! cargo +nightly fuzz run cilobject --release
//!
//! # Multi-core fuzzing
//! cargo +nightly fuzz run cilobject --release -- -jobs=4 -fork=1
//!
//! # Coverage analysis
//! RUSTFLAGS="-C instrument-coverage" cargo +nightly fuzz coverage cilobject --release
//! ```
//!
//! ### Testing
//!
//! The test suite includes real-world .NET assemblies and edge cases:
//!
//! ```bash
//! cargo test
//! cargo test --release  # For performance tests
//! ```
#[macro_use]
pub(crate) mod macros;

#[macro_use]
pub(crate) mod error;
pub(crate) mod file;

/// Shared functionality which is used in unit- and integration-tests
#[cfg(test)]
pub(crate) mod test;

/// Convenient re-exports of the most commonly used types and traits.
///
/// This module provides a curated selection of the most frequently used types
/// from across the dotscope library, allowing for convenient glob imports.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// // Now you have access to the most common types
/// let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
/// let methods = assembly.methods();
/// # Ok::<(), dotscope::Error>(())
/// ```
pub mod prelude;

/// Instructions, Disassembler based on ECMA-355
///
/// This module provides comprehensive CIL (Common Intermediate Language) instruction decoding
/// and disassembly capabilities. It includes:
///
/// - **Instruction Decoding**: Parse individual CIL opcodes with full operand support
/// - **Control Flow Analysis**: Build basic blocks and analyze program flow
/// - **Stack Effect Analysis**: Track how instructions affect the evaluation stack
/// - **Exception Handling**: Parse try/catch/finally regions and exception handlers
///
/// # Key Types
///
/// - [`disassembler::Instruction`] - Represents a decoded CIL instruction
/// - [`disassembler::BasicBlock`] - A sequence of instructions with single entry/exit
/// - [`disassembler::Operand`] - Instruction operands (immediates, tokens, targets)
/// - [`disassembler::FlowType`] - How instructions affect control flow
///
/// # Main Functions
///
/// - [`disassembler::decode_instruction`] - Decode a single instruction
/// - [`disassembler::decode_stream`] - Decode a sequence of instructions  
/// - [`disassembler::decode_blocks`] - Build basic blocks from instruction stream
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{disassembler::decode_instruction, Parser};
///
/// let bytecode = &[0x00, 0x2A]; // nop, ret
/// let mut parser = Parser::new(bytecode);
/// let instruction = decode_instruction(&mut parser, 0x1000)?;
///
/// println!("Mnemonic: {}", instruction.mnemonic);
/// println!("Flow type: {:?}", instruction.flow_type);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub mod disassembler;

/// Definitions, parsing, loading, mapping of CIL metadata based on ECMA-355
///
/// This module implements the complete ECMA-335 metadata system for .NET assemblies.
/// It provides comprehensive parsing and access to all metadata tables, streams, and
/// type system constructs.
///
/// # Key Components
///
/// ## Assembly Analysis
/// - [`CilObject`] - Main entry point for assembly analysis
/// - [`metadata::cor20header`] - CLR 2.0 header information
/// - [`metadata::root`] - Metadata root and stream directory
///
/// ## Type System
/// - [`metadata::typesystem`] - Complete .NET type system representation
/// - [`metadata::signatures`] - Method and field signatures, generics support
/// - [`metadata::token`] - Metadata tokens for cross-references
///
/// ## Metadata Streams
/// - [`metadata::streams`] - All ECMA-335 metadata tables and heaps
/// - String, GUID, Blob, and UserString heaps via [`Strings`], [`Guid`], [`Blob`], [`UserStrings`]
/// - Metadata tables and stream headers via [`TablesHeader`], [`StreamHeader`]
/// - Assembly, Type, Method, Field, and other metadata tables
///
/// ## Import/Export Analysis  
/// - [`metadata::imports`] - Analysis of imported types and methods
/// - [`metadata::exports`] - Analysis of exported types and methods
/// - [`metadata::resources`] - Embedded resources and manifests
///
/// ## Security and Identity
/// - [`metadata::security`] - Code Access Security (CAS) permissions
/// - [`metadata::identity`] - Assembly identity and verification
/// - [`metadata::marshalling`] - P/Invoke and COM interop marshalling
///
/// # Examples
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
pub mod metadata;

/// `dotscope` Result type
///
/// A type alias for [`std::result::Result<T, Error>`] where the error type is always [`Error`].
/// This is used consistently throughout the crate for all fallible operations.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{Result, CilObject};
///
/// fn load_assembly(path: &str) -> Result<CilObject> {
///     CilObject::from_file(std::path::Path::new(path))
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// `dotscope` Error type
///
/// The main error type for all operations in this crate. Provides detailed error information
/// for file parsing, metadata validation, and disassembly operations.
///
/// # Examples
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

/// Main entry point for working with .NET assemblies.
///
/// See [`metadata::cilobject::CilObject`] for high-level analysis and metadata access.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// let assembly = CilObject::from_file(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
/// println!("Found {} methods", assembly.methods().len());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::cilobject::CilObject;

/// Metadata streams and heaps for direct access to ECMA-335 data structures.
///
/// These types provide low-level access to the metadata structures:
/// - [`Blob`] - Binary blob heap for signatures and complex data
/// - [`Guid`] - GUID heap for type and assembly identifiers  
/// - [`Strings`] - String heap for names and identifiers
/// - [`UserStrings`] - User string heap for string literals
/// - [`TablesHeader`] - Metadata tables header information
/// - [`StreamHeader`] - Individual stream header information
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::{CilObject, Blob, Strings};
/// let assembly = CilObject::from_file(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Access metadata heaps directly
/// if let Some(strings) = assembly.strings() {
///     // Try to get a string at index 1
///     if let Ok(name) = strings.get(1) {
///         println!("String at index 1: {}", name);
///     }
/// }
///
/// if let Some(blob) = assembly.blob() {
///     // Try to get a blob at index 1  
///     if let Ok(data) = blob.get(1) {
///         println!("Blob at index 1 has {} bytes", data.len());
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::streams::{Blob, Guid, StreamHeader, Strings, TablesHeader, UserStrings};

/// Provides access to low-level file and memory parsing utilities.
///
/// The [`Parser`] type is used for decoding CIL bytecode and metadata streams.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::{Parser, disassembler::decode_instruction};
/// let code = [0x2A]; // ret
/// let mut parser = Parser::new(&code);
/// let instr = decode_instruction(&mut parser, 0x1000)?;
/// assert_eq!(instr.mnemonic, "ret");
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use file::{parser::Parser, File};
