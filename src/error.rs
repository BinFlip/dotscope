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
//! match CilObject::from_path(Path::new("assembly.dll")) {
//!     Ok(assembly) => {
//!         println!("Successfully loaded assembly");
//!     }
//!     Err(Error::NotSupported) => {
//!         eprintln!("File format is not supported");
//!     }
//!     Err(Error::Malformed { message, file, line }) => {
//!         eprintln!("Malformed file: {} ({}:{})", message, file, line);
//!     }
//!     Err(Error::Io(io_err)) => {
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

use thiserror::Error;

use crate::metadata::{tables::TableId, token::Token};

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
#[macro_export]
macro_rules! malformed_error {
    // Single string version
    ($msg:expr) => {
        $crate::Error::Malformed {
            message: $msg.to_string(),
            file: file!(),
            line: line!(),
        }
    };

    // Format string with arguments version
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::Malformed {
            message: format!($fmt, $($arg)*),
            file: file!(),
            line: line!(),
        }
    };
}

/// Helper macro for creating out-of-bounds errors with source location information.
///
/// This macro simplifies the creation of [`crate::Error::OutOfBounds`] errors by automatically
/// capturing the current file and line number where the out-of-bounds access was detected.
///
/// # Returns
///
/// Returns a [`crate::Error::OutOfBounds`] variant with automatically captured source
/// location information for debugging purposes.
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::out_of_bounds_error;
/// // Replace: Err(Error::OutOfBounds)
/// // With:    Err(out_of_bounds_error!())
/// if index >= data.len() {
///     return Err(out_of_bounds_error!());
/// }
/// ```
#[macro_export]
macro_rules! out_of_bounds_error {
    () => {
        $crate::Error::OutOfBounds {
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
/// - [`crate::Error::Malformed`] - Corrupted or invalid file structure
/// - [`crate::Error::OutOfBounds`] - Attempted to read beyond file boundaries
/// - [`crate::Error::NotSupported`] - Unsupported file format or feature
///
/// ## I/O and External Errors
/// - [`crate::Error::Io`] - Filesystem I/O errors
/// - [`crate::Error::Goblin`] - PE/ELF parsing errors from goblin crate
///
/// ## Type System Errors
/// - [`crate::Error::TypeNotFound`] - Requested type not found in type system
/// - [`crate::Error::TypeError`] - General type system operation error
/// - [`crate::Error::TypeMissingParent`] - Type inheritance chain broken
/// - [`crate::Error::TypeNotPrimitive`] - Expected primitive type
/// - [`crate::Error::TypeConversionInvalid`] - Invalid type conversion requested
///
/// ## Analysis Errors
/// - [`crate::Error::RecursionLimit`] - Maximum recursion depth exceeded
/// - [`crate::Error::DepthLimitExceeded`] - Maximum nesting depth exceeded in iterative parsing
/// - [`crate::Error::GraphError`] - Dependency graph analysis error
/// - [`crate::Error::SsaError`] - SSA construction error
///
/// # Thread Safety
///
/// This error enum is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain thread-safe types.
/// This includes owned strings, primitive values, and errors from external crates that are themselves
/// thread-safe. Errors can be safely passed between threads and shared across thread boundaries.
#[derive(Error, Debug)]
pub enum Error {
    // File parsing Errors
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
    /// The error includes the source location where the out-of-bounds access
    /// was detected for debugging purposes.
    ///
    /// # Fields
    ///
    /// * `file` - Source file where the error was detected
    /// * `line` - Source line where the error was detected
    #[error("Out of Bounds - {file}:{line}")]
    OutOfBounds {
        /// The source file in which this error occurred
        file: &'static str,
        /// The source line in which this error occurred
        line: u32,
    },

    /// This file type is not supported.
    ///
    /// Indicates that the input file is not a supported .NET PE executable,
    /// or uses features that are not yet implemented in this library.
    #[error("This file type is not supported")]
    NotSupported,

    /// File I/O error.
    ///
    /// Wraps standard I/O errors that can occur during file operations
    /// such as reading from disk, permission issues, or filesystem errors.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// Other errors that don't fit specific categories.
    ///
    /// NOTE: Prefer specific error types. Use this only for:
    /// - Wrapping external library errors with context
    /// - Temporary errors during development
    /// - Truly miscellaneous errors
    #[error("{0}")]
    Other(String),

    /// Error from the goblin crate during PE/ELF parsing.
    ///
    /// The goblin crate is used for low-level PE format parsing.
    /// This error wraps any failures from that parsing layer.
    #[error("{0}")]
    Goblin(#[from] goblin::error::Error),

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

    /// Marshalling descriptor encoding error.
    ///
    /// This error occurs when encoding marshalling information fails due
    /// to invalid or inconsistent marshalling descriptor data, such as
    /// sequential parameter constraints being violated.
    ///
    /// The associated string contains details about what failed during encoding.
    #[error("Marshalling error: {0}")]
    MarshallingError(String),

    ///
    /// To prevent resource exhaustion and stack overflow during iterative parsing
    /// operations, a maximum nesting depth is enforced. This error indicates that
    /// the depth limit was exceeded while parsing complex nested structures.
    ///
    /// This applies to iterative stack-based parsing in:
    /// - Signature type parsing (nested generic types, arrays, pointers)
    /// - Custom attribute parsing (nested arrays, tagged objects)
    /// - Any other iterative parser with explicit depth limiting
    ///
    /// The associated value shows the nesting depth limit that was reached.
    #[error("Reached the maximum nesting depth allowed - {0}")]
    DepthLimitExceeded(usize),

    /// `LoaderGraph` error.
    ///
    /// Errors related to dependency graph analysis and metadata loading
    /// order resolution. This can occur when circular dependencies are
    /// detected or when the dependency graph cannot be properly constructed.
    #[error("{0}")]
    GraphError(String),

    /// SSA construction error.
    ///
    /// Errors related to Static Single Assignment form construction,
    /// including stack simulation failures and phi node placement issues.
    #[error("SSA error: {0}")]
    SsaError(String),

    /// Cannot modify replaced table.
    ///
    /// This error occurs when attempting to apply sparse modifications
    /// to a table that has been completely replaced.
    #[error("Cannot modify replaced table")]
    CannotModifyReplacedTable,

    /// Invalid modification operation.
    ///
    /// This error occurs when attempting an operation that is not
    /// valid for the current state or context.
    #[error("Invalid modification: {0}")]
    ModificationInvalid(String),

    /// Invalid RID for table during validation.
    ///
    /// This error occurs when a RID is invalid for the target table,
    /// such as zero-valued RIDs or RIDs exceeding table bounds.
    #[error("Invalid RID {rid} for table {table:?}")]
    InvalidRid {
        /// The table with the invalid RID
        table: TableId,
        /// The invalid RID
        rid: u32,
    },

    /// Cross-reference validation failed.
    ///
    /// This error occurs when validation detects broken cross-references
    /// between metadata tables.
    #[error("Cross-reference error: {0}")]
    CrossReferenceError(String),

    /// Heap bounds validation failed.
    ///
    /// This error occurs when metadata heap indices are out of bounds
    /// for the target heap.
    #[error("Heap bounds error: {heap} index {index}")]
    HeapBoundsError {
        /// The type of heap (strings, blobs, etc.)
        heap: String,
        /// The out-of-bounds index
        index: u32,
    },

    /// Conflict resolution failed.
    ///
    /// This error occurs when the conflict resolution system cannot
    /// automatically resolve detected conflicts.
    #[error("Conflict resolution failed: {0}")]
    ConflictResolution(String),

    /// Stage 1 (raw) validation failed, preventing Stage 2 execution.
    ///
    /// This error occurs when the first stage of validation (raw metadata validation)
    /// fails, causing the unified validation engine to terminate early without
    /// proceeding to Stage 2 (owned validation).
    #[error("Validation Stage 1 failed: {message}")]
    ValidationStage1Failed {
        /// The underlying error that caused Stage 1 to fail
        #[source]
        source: Box<Error>,
        /// Details about the Stage 1 failure
        message: String,
    },

    /// Stage 2 (owned) validation failed with multiple errors.
    ///
    /// This error occurs when Stage 2 validation (owned metadata validation)
    /// encounters multiple validation failures during parallel execution.
    #[error("Validation Stage 2 failed with {error_count} errors: {summary}")]
    ValidationStage2Failed {
        /// All validation errors collected during Stage 2
        errors: Vec<Error>,
        /// Number of errors for quick reference
        error_count: usize,
        /// Summary of the validation failures
        summary: String,
    },

    /// Raw validation failed for a specific validator.
    ///
    /// This error occurs when a specific raw validator (Stage 1) fails during
    /// the validation process on CilAssemblyView data.
    #[error("Raw validation failed in {validator}: {message}")]
    ValidationRawFailed {
        /// Name of the validator that failed
        validator: String,
        /// Details about the validation failure
        message: String,
    },

    /// Owned validation failed for a specific validator.
    ///
    /// This error occurs when a specific owned validator (Stage 2) fails during
    /// the validation process on CilObject data.
    #[error("Owned validation failed in {validator}: {message}")]
    ValidationOwnedFailed {
        /// Name of the validator that failed
        validator: String,
        /// Details about the validation failure
        message: String,
    },

    /// Validation engine initialization failed.
    ///
    /// This error occurs when the unified validation engine cannot be properly
    /// initialized due to invalid configuration or missing dependencies.
    #[error("Validation engine initialization failed: {message}")]
    ValidationEngineInitFailed {
        /// Details about the initialization failure
        message: String,
    },

    /// Invalid token or token reference.
    ///
    /// This error occurs when token format or cross-reference validation fails
    /// during either raw or owned validation stages.
    #[error("Invalid token {token}: {message}")]
    InvalidToken {
        /// The token that failed validation
        token: Token,
        /// Details about the token validation failure
        message: String,
    },

    /// Layout planning failed during binary generation.
    ///
    /// This error occurs when the write planner cannot determine a valid
    /// layout for the output file, such as when the file would exceed
    /// configured size limits.
    #[error("Layout failed: {0}")]
    LayoutFailed(String),

    /// Memory mapping failed during binary reading or writing.
    ///
    /// This error occurs when memory-mapped file operations fail,
    /// either for creating new mappings or accessing existing ones.
    #[error("Memory mapping failed: {0}")]
    MmapFailed(String),

    /// File finalization failed during binary writing.
    ///
    /// This error occurs when the final step of writing (such as flushing,
    /// syncing, or closing the output file) fails.
    #[error("Finalization failed: {0}")]
    FinalizationFailed(String),

    /// Invalid instruction mnemonic.
    ///
    /// This error occurs when attempting to encode an instruction with
    /// a mnemonic that is not recognized in the CIL instruction set.
    #[error("Invalid instruction mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Wrong operand type for instruction.
    ///
    /// This error occurs when the provided operand type doesn't match
    /// the expected operand type for the instruction being encoded.
    #[error("Wrong operand type for instruction - expected {expected}")]
    WrongOperandType {
        /// The expected operand type
        expected: String,
    },

    /// Unexpected operand provided.
    ///
    /// This error occurs when an operand is provided for an instruction
    /// that doesn't expect any operand.
    #[error("Unexpected operand provided for instruction that expects none")]
    UnexpectedOperand,

    /// Invalid branch instruction or operand.
    ///
    /// This error occurs when:
    /// - Attempting to use the branch instruction encoding method with a non-branch instruction
    /// - A branch instruction has an operand type not valid for branch offset encoding
    /// - An invalid offset size is specified for branch instruction encoding
    #[error("Invalid branch: {0}")]
    InvalidBranch(String),

    /// Undefined label referenced.
    ///
    /// This error occurs when attempting to finalize encoding with
    /// unresolved label references.
    #[error("Undefined label referenced: {0}")]
    UndefinedLabel(String),

    /// Duplicate label definition.
    ///
    /// This error occurs when attempting to define a label that has
    /// already been defined in the current encoding context.
    #[error("Duplicate label definition: {0}")]
    DuplicateLabel(String),

    /// Lock or synchronization error.
    ///
    /// This error occurs when synchronization primitives like barriers, locks,
    /// or cache locks fail during concurrent operations.
    ///
    /// # Examples
    ///
    /// - Barrier wait failures during parallel loading
    /// - Lock acquisition failures for cache updates
    /// - Thread synchronization failures
    #[error("Lock error: {0}")]
    LockError(String),

    /// Configuration or setup error.
    ///
    /// This error occurs when there are issues with configuration, project setup,
    /// file paths, or other setup-related operations.
    ///
    /// # Examples
    ///
    /// - Missing primary file specification
    /// - Invalid search paths
    /// - Duplicate assembly identities
    #[error("Configuration error: {0}")]
    Configuration(String),
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            // Handle non-cloneable variants by converting to string representation
            Error::Io(io_err) => Error::Other(io_err.to_string()),
            Error::Goblin(goblin_err) => Error::Other(goblin_err.to_string()),
            // For validation errors that have Box<Error> sources, clone them recursively
            Error::ValidationStage1Failed { source, message } => Error::ValidationStage1Failed {
                source: source.clone(),
                message: message.clone(),
            },
            Error::ValidationRawFailed { validator, message } => Error::ValidationRawFailed {
                validator: validator.clone(),
                message: message.clone(),
            },
            Error::ValidationOwnedFailed { validator, message } => Error::ValidationOwnedFailed {
                validator: validator.clone(),
                message: message.clone(),
            },
            // For all other variants, convert to their string representation and use Other
            other => Error::Other(other.to_string()),
        }
    }
}
