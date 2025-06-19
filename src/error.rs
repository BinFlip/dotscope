//! Error types and handling for the dotscope library.
//!
//! This module defines the comprehensive error handling system for the dotscope library,
//! providing detailed error types for .NET assembly parsing, metadata analysis, and
//! disassembly operations. The error types are designed to provide meaningful context
//! for different failure modes to enable appropriate error handling and debugging.
//!
//! # Architecture
//!
//! The error system is built around a single comprehensive [`crate::Error`] enum that
//! covers all possible error conditions. This approach provides a unified error handling
//! experience while maintaining detailed error categorization. The system includes:
//!
//! - Structured error variants for different failure modes
//! - Source location tracking for malformed file errors
//! - Integration with external library errors through automatic conversion
//! - Thread-safe error propagation for concurrent operations
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::Error`] - Main error enum covering all possible error conditions
//! - [`crate::Result`] - Convenience type alias for `Result<T, Error>`
//!
//! ## Error Categories
//! - **File Parsing Errors**: Invalid offsets, malformed data, out-of-bounds access
//! - **I/O Errors**: Filesystem operations, permission issues
//! - **Type System Errors**: Type registration, resolution, and conversion failures
//! - **Analysis Errors**: Recursion limits, synchronization failures, dependency graph issues
//!
//! # Usage Examples
//!
//! ## Basic Error Handling
//!
//! ```rust
//! use dotscope::{Error, Result};
//!
//! fn parse_data() -> Result<String> {
//!     // Function that might fail
//!     Err(Error::NotSupported)
//! }
//!
//! match parse_data() {
//!     Ok(data) => println!("Success: {}", data),
//!     Err(Error::NotSupported) => println!("Feature not supported"),
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```
//!
//! ## Advanced Error Handling
//!
//! ```rust,ignore
//! use dotscope::{Error, metadata::cilobject::CilObject};
//! use std::path::Path;
//!
//! match CilObject::from_file(Path::new("assembly.dll")) {
//!     Ok(assembly) => {
//!         println!("Successfully loaded assembly");
//!     }
//!     Err(Error::NotSupported) => {
//!         eprintln!("File format is not supported");
//!     }
//!     Err(Error::Malformed { message, file, line }) => {
//!         eprintln!("Malformed file: {} ({}:{})", message, file, line);
//!     }
//!     Err(Error::FileError(io_err)) => {
//!         eprintln!("I/O error: {}", io_err);
//!     }
//!     Err(e) => {
//!         eprintln!("Other error: {}", e);
//!     }
//! }
//! ```
//!
//! ## Using the Malformed Error Macro
//!
//! ```rust,ignore
//! use dotscope::malformed_error;
//!
//! fn validate_header(size: usize) -> dotscope::Result<()> {
//!     if size < 4 {
//!         return Err(malformed_error!("Header too small: {} bytes", size));
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Thread Safety
//!
//! All error types in this module are thread-safe. The [`crate::Error`] enum implements
//! [`std::marker::Send`] and [`std::marker::Sync`], allowing errors to be safely passed
//! between threads and shared across thread boundaries. This enables proper error
//! propagation in concurrent parsing and analysis operations.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata`] - Uses error types for metadata parsing failures
//! - [`crate::disassembler`] - Reports disassembly and analysis errors
//! - [`crate::file`] - Handles file I/O and parsing errors
//!
//! The error system supports automatic conversion from external library errors
//! (like `std::io::Error` and `goblin::error::Error`) through the `From` trait,
//! enabling seamless error propagation throughout the library.

use thiserror::Error;

use crate::metadata::token::Token;

/// Helper macro for creating malformed data errors with source location information.
///
/// This macro simplifies the creation of [`crate::Error::Malformed`] errors by automatically
/// capturing the current file and line number. It supports both simple string messages
/// and format string patterns with arguments.
///
/// # Arguments
///
/// * `$msg` - A string or expression that can be converted to a string
/// * `$fmt, $($arg)*` - A format string and its arguments (like `format!` macro)
///
/// # Returns
///
/// Returns a [`crate::Error::Malformed`] variant with the provided message and
/// automatically captured source location information.
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::malformed_error;
/// // Simple string message
/// let error = malformed_error!("Invalid data format");
///
/// // Format string with arguments
/// let expected = 4;
/// let actual = 2;
/// let error = malformed_error!("Expected {} bytes, got {}", expected, actual);
/// ```
macro_rules! malformed_error {
    // Single string version
    ($msg:expr) => {
        crate::Error::Malformed {
            message: $msg.to_string(),
            file: file!(),
            line: line!(),
        }
    };

    // Format string with arguments version
    ($fmt:expr, $($arg:tt)*) => {
        crate::Error::Malformed {
            message: format!($fmt, $($arg)*),
            file: file!(),
            line: line!(),
        }
    };
}

/// The generic Error type, which provides coverage for all errors this library can potentially
/// return.
///
/// This enum covers all possible error conditions that can occur during .NET assembly parsing,
/// metadata analysis, and disassembly operations. Each variant provides specific context about
/// the failure mode to enable appropriate error handling.
///
/// # Error Categories
///
/// ## File Parsing Errors
/// - [`crate::Error::InvalidOffset`] - Invalid file offset during parsing
/// - [`crate::Error::Malformed`] - Corrupted or invalid file structure
/// - [`crate::Error::OutOfBounds`] - Attempted to read beyond file boundaries
/// - [`crate::Error::NotSupported`] - Unsupported file format or feature
/// - [`crate::Error::Empty`] - Empty input provided
///
/// ## I/O and External Errors
/// - [`crate::Error::FileError`] - Filesystem I/O errors
/// - [`crate::Error::GoblinErr`] - PE/ELF parsing errors from goblin crate
///
/// ## Type System Errors
/// - [`crate::Error::TypeInsert`] - Failed to register new type in type system
/// - [`crate::Error::TypeNotFound`] - Requested type not found in type system
/// - [`crate::Error::TypeError`] - General type system operation error
/// - [`crate::Error::TypeMissingParent`] - Type inheritance chain broken
/// - [`crate::Error::TypeNotPrimitive`] - Expected primitive type
/// - [`crate::Error::TypeNotConst`] - Cannot convert to constant type
/// - [`crate::Error::TypeConversionInvalid`] - Invalid type conversion requested
///
/// ## Analysis Errors
/// - [`crate::Error::RecursionLimit`] - Maximum recursion depth exceeded
/// - [`crate::Error::LockError`] - Thread synchronization failure
/// - [`crate::Error::GraphError`] - Dependency graph analysis error
///
/// # Thread Safety
///
/// [`Error`] is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain thread-safe types.
/// This includes owned strings, primitive values, and errors from external crates that are themselves
/// thread-safe. Errors can be safely passed between threads and shared across thread boundaries.
#[derive(Error, Debug)]
pub enum Error {
    // File parsing Errors
    /// Encountered an invalid offset while parsing file structures.
    ///
    /// This error occurs when the parser encounters an offset that is invalid
    /// for the current file context, such as negative offsets or offsets that
    /// would point outside the valid file structure.
    #[error("Could not retrieve a valid offset!")]
    InvalidOffset,

    /// The file is damaged and could not be parsed.
    ///
    /// This error indicates that the file structure is corrupted or doesn't
    /// conform to the expected .NET PE format. The error includes the source
    /// location where the malformation was detected for debugging purposes.
    ///
    /// # Fields
    ///
    /// * `message` - Detailed description of what was malformed
    /// * `file` - Source file where the error was detected  
    /// * `line` - Source line where the error was detected
    #[error("Malformed - {file}:{line}: {message}")]
    Malformed {
        /// The message to be printed for the Malformed error
        message: String,
        /// The source file in which this error occured
        file: &'static str,
        /// The source line in which this error occured
        line: u32,
    },

    /// An out of bound access was attempted while parsing the file.
    ///
    /// This error occurs when trying to read data beyond the end of the file
    /// or stream. It's a safety check to prevent buffer overruns during parsing.
    #[error("Out of Bound read would have occurred!")]
    OutOfBounds,

    /// This file type is not supported.
    ///
    /// Indicates that the input file is not a supported .NET PE executable,
    /// or uses features that are not yet implemented in this library.
    #[error("This file type is not supported")]
    NotSupported,

    /// Provided input was empty.
    ///
    /// This error occurs when an empty file or buffer is provided where
    /// actual .NET assembly data was expected.
    #[error("Provided input was empty")]
    Empty,

    /// File I/O error.
    ///
    /// Wraps standard I/O errors that can occur during file operations
    /// such as reading from disk, permission issues, or filesystem errors.
    #[error("{0}")]
    FileError(#[from] std::io::Error),

    /// Generic error for miscellaneous failures.
    ///
    /// Used for errors that don't fit into other categories or for
    /// wrapping external library errors with additional context.
    #[error("{0}")]
    Error(String),

    /// Error from the goblin crate during PE/ELF parsing.
    ///
    /// The goblin crate is used for low-level PE format parsing.
    /// This error wraps any failures from that parsing layer.
    #[error("{0}")]
    GoblinErr(#[from] goblin::error::Error),

    /// Failed to insert new type into `TypeSystem`.
    ///
    /// This error occurs when attempting to register a new type in the
    /// type system fails, typically due to conflicting metadata tokens
    /// or invalid type definitions.
    ///
    /// The associated [`crate::metadata::token::Token`] identifies which type caused the failure.
    #[error("Failed to insert new type into TypeSystem - {0}")]
    TypeInsert(Token),

    /// Failed to find type in `TypeSystem`.
    ///
    /// This error occurs when looking up a type by token that doesn't
    /// exist in the loaded metadata or type system registry.
    ///
    /// The associated [`crate::metadata::token::Token`] identifies which type was not found.
    #[error("Failed to find type in TypeSystem - {0}")]
    TypeNotFound(Token),

    /// General error during `TypeSystem` usage.
    ///
    /// Covers various type system operations that can fail, such as
    /// type resolution, inheritance chain analysis, or generic instantiation.
    #[error("{0}")]
    TypeError(String),

    /// The parent of the current type is missing.
    ///
    /// This error occurs when analyzing type inheritance and the parent
    /// type referenced by a type definition cannot be found or resolved.
    #[error("The parent of the current type is missing")]
    TypeMissingParent,

    /// This type can not be converted to a primitive.
    ///
    /// Occurs when attempting to convert a complex type to a primitive
    /// type representation, but the type is not compatible with primitive
    /// type semantics.
    #[error("This type can not be converted to a primitive")]
    TypeNotPrimitive,

    /// This type can not be converted to a `ConstType`.
    ///
    /// Indicates that a type cannot be represented as a compile-time
    /// constant value. The associated value indicates the type code
    /// that failed conversion.
    #[error("This type can not be converted to a const type - {0}")]
    TypeNotConst(u8),

    /// The requested type conversion is not possible.
    ///
    /// This error occurs when attempting type conversions that are
    /// semantically invalid in the .NET type system.
    #[error("The requested type conversion is not possible")]
    TypeConversionInvalid,

    /// Recursion limit reached.
    ///
    /// To prevent stack overflow during recursive operations like type
    /// resolution or dependency analysis, a maximum recursion depth is
    /// enforced. This error indicates that limit was exceeded.
    ///
    /// The associated value shows the recursion limit that was reached.
    #[error("Reach the maximum recursion level allowed - {0}")]
    RecursionLimit(usize),

    /// Failed to lock target.
    ///
    /// This error occurs when thread synchronization fails, typically
    /// when trying to acquire a mutex or rwlock that is in an invalid state.
    #[error("Failed to lock target")]
    LockError,

    /// `LoaderGraph` error.
    ///
    /// Errors related to dependency graph analysis and metadata loading
    /// order resolution. This can occur when circular dependencies are
    /// detected or when the dependency graph cannot be properly constructed.
    #[error("{0}")]
    GraphError(String),
}
