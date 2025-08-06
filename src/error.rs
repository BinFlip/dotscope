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
/// This error enum is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain thread-safe types.
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

    // Assembly Modification Errors
    /// RID already exists during table modification.
    ///
    /// This error occurs when attempting to insert a row with a RID that
    /// already exists in the target metadata table.
    #[error("Modification error: RID {rid} already exists in table {table:?}")]
    ModificationRidAlreadyExists {
        /// The table where the conflict occurred
        table: TableId,
        /// The conflicting RID
        rid: u32,
    },

    /// RID not found during table modification.
    ///
    /// This error occurs when attempting to update or delete a row that
    /// doesn't exist in the target metadata table.
    #[error("Modification error: RID {rid} not found in table {table:?}")]
    ModificationRidNotFound {
        /// The table where the RID was not found
        table: TableId,
        /// The missing RID
        rid: u32,
    },

    /// Cannot modify replaced table.
    ///
    /// This error occurs when attempting to apply sparse modifications
    /// to a table that has been completely replaced.
    #[error("Modification error: Cannot modify replaced table - convert to sparse first")]
    ModificationCannotModifyReplacedTable,

    /// Operation conflicts detected during modification.
    ///
    /// This error occurs when multiple conflicting operations target
    /// the same RID and cannot be automatically resolved.
    #[error("Modification error: Operation conflicts detected - {details}")]
    ModificationConflictDetected {
        /// Details about the conflict
        details: String,
    },

    /// Invalid modification operation.
    ///
    /// This error occurs when attempting an operation that is not
    /// valid for the current state or context.
    #[error("Modification error: Invalid operation - {details}")]
    ModificationInvalidOperation {
        /// Details about why the operation is invalid
        details: String,
    },

    /// Table schema validation failed.
    ///
    /// This error occurs when table row data doesn't conform to the
    /// expected schema for the target table type.
    #[error("Modification error: Table schema validation failed - {details}")]
    ModificationSchemaValidationFailed {
        /// Details about the schema validation failure
        details: String,
    },

    // Assembly Validation Errors
    /// Invalid RID for table during validation.
    ///
    /// This error occurs when a RID is invalid for the target table,
    /// such as zero-valued RIDs or RIDs exceeding table bounds.
    #[error("Validation error: Invalid RID {rid} for table {table:?}")]
    ValidationInvalidRid {
        /// The table with the invalid RID
        table: TableId,
        /// The invalid RID
        rid: u32,
    },

    /// Cannot update non-existent row during validation.
    ///
    /// This error occurs when validation detects an attempt to update
    /// a row that doesn't exist in the original table.
    #[error("Validation error: Cannot update non-existent row {rid} in table {table:?}")]
    ValidationUpdateNonExistentRow {
        /// The table where the update was attempted
        table: TableId,
        /// The non-existent RID
        rid: u32,
    },

    /// Cannot delete non-existent row during validation.
    ///
    /// This error occurs when validation detects an attempt to delete
    /// a row that doesn't exist in the original table.
    #[error("Validation error: Cannot delete non-existent row {rid} in table {table:?}")]
    ValidationDeleteNonExistentRow {
        /// The table where the deletion was attempted
        table: TableId,
        /// The non-existent RID
        rid: u32,
    },

    /// Cannot delete referenced row during validation.
    ///
    /// This error occurs when attempting to delete a row that is
    /// referenced by other metadata tables, which would break
    /// referential integrity.
    #[error("Validation error: Cannot delete referenced row {rid} in table {table:?} - {reason}")]
    ValidationCannotDeleteReferencedRow {
        /// The table containing the referenced row
        table: TableId,
        /// The RID of the referenced row
        rid: u32,
        /// The reason why deletion is not allowed
        reason: String,
    },

    /// Row type mismatch during validation.
    ///
    /// This error occurs when the provided row data type doesn't
    /// match the expected type for the target table.
    #[error("Validation error: Row type mismatch for table {table:?} - expected table-specific type, got {actual_type}")]
    ValidationRowTypeMismatch {
        /// The target table
        table: TableId,
        /// The actual type that was provided
        actual_type: String,
    },

    /// Table schema validation mismatch.
    ///
    /// This error occurs when table data doesn't conform to the expected
    /// schema for the target table type.
    #[error("Validation error: Table schema mismatch for table {table:?} - expected {expected}, got {actual}")]
    ValidationTableSchemaMismatch {
        /// The target table
        table: TableId,
        /// The expected schema type
        expected: String,
        /// The actual type that was provided
        actual: String,
    },

    /// Cross-reference validation failed.
    ///
    /// This error occurs when validation detects broken cross-references
    /// between metadata tables.
    #[error("Validation error: Cross-reference validation failed - {message}")]
    ValidationCrossReferenceError {
        /// Details about the cross-reference failure
        message: String,
    },

    /// Referential integrity validation failed.
    ///
    /// This error occurs when validation detects operations that would
    /// violate referential integrity constraints.
    #[error("Validation error: Referential integrity constraint violated - {message}")]
    ValidationReferentialIntegrity {
        /// Details about the referential integrity violation
        message: String,
    },

    /// Heap bounds validation failed.
    ///
    /// This error occurs when metadata heap indices are out of bounds
    /// for the target heap.
    #[error(
        "Validation error: Heap bounds validation failed - {heap_type} index {index} out of bounds"
    )]
    ValidationHeapBoundsError {
        /// The type of heap (strings, blobs, etc.)
        heap_type: String,
        /// The out-of-bounds index
        index: u32,
    },

    /// Conflict resolution failed.
    ///
    /// This error occurs when the conflict resolution system cannot
    /// automatically resolve detected conflicts.
    #[error("Conflict resolution error: {details}")]
    ConflictResolutionError {
        /// Details about why conflict resolution failed
        details: String,
    },

    // Unified Validation Framework Errors
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
    ValidationRawValidatorFailed {
        /// Name of the validator that failed
        validator: String,
        /// Details about the validation failure
        message: String,
        /// The underlying error that caused the failure
        #[source]
        source: Option<Box<Error>>,
    },

    /// Owned validation failed for a specific validator.
    ///
    /// This error occurs when a specific owned validator (Stage 2) fails during
    /// the validation process on CilObject data.
    #[error("Owned validation failed in {validator}: {message}")]
    ValidationOwnedValidatorFailed {
        /// Name of the validator that failed
        validator: String,
        /// Details about the validation failure
        message: String,
        /// The underlying error that caused the failure
        #[source]
        source: Option<Box<Error>>,
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

    /// Validation context creation failed.
    ///
    /// This error occurs when the validation context cannot be created for
    /// either raw or owned validation stages.
    #[error("Validation context creation failed for {stage}: {message}")]
    ValidationContextCreationFailed {
        /// The validation stage (Raw or Owned)
        stage: String,
        /// Details about the context creation failure
        message: String,
    },

    /// Token validation failed.
    ///
    /// This error occurs when token format or cross-reference validation fails
    /// during either raw or owned validation stages.
    #[error("Token validation failed for {token}: {message}")]
    ValidationTokenError {
        /// The token that failed validation
        token: Token,
        /// Details about the token validation failure
        message: String,
    },

    /// Semantic validation failed.
    ///
    /// This error occurs when semantic validation rules fail during owned
    /// validation, such as inheritance rules or interface constraints.
    #[error("Semantic validation failed: {message}")]
    ValidationSemanticError {
        /// Details about the semantic validation failure
        message: String,
        /// Optional token context for the failure
        token: Option<Token>,
    },

    /// Method validation failed.
    ///
    /// This error occurs when method-specific validation fails, such as
    /// constructor validation or method signature validation.
    #[error("Method validation failed for {method_token}: {message}")]
    ValidationMethodError {
        /// The method token that failed validation
        method_token: Token,
        /// Details about the method validation failure
        message: String,
    },

    /// Field validation failed.
    ///
    /// This error occurs when field layout validation fails, such as
    /// field overlap detection or layout validation.
    #[error("Field validation failed: {message}")]
    ValidationFieldError {
        /// Details about the field validation failure
        message: String,
        /// Optional field token context
        field_token: Option<Token>,
    },

    /// Type system validation failed.
    ///
    /// This error occurs when type system consistency validation fails,
    /// such as layout validation or constraint validation.
    #[error("Type system validation failed: {message}")]
    ValidationTypeSystemError {
        /// Details about the type system validation failure
        message: String,
        /// Optional type token context
        type_token: Option<Token>,
    },

    /// Nested class validation failed.
    ///
    /// This error occurs when nested class hierarchy validation fails,
    /// such as circular reference detection or nesting depth validation.
    #[error("Nested class validation failed: {message}")]
    ValidationNestedClassError {
        /// Details about the nested class validation failure
        message: String,
        /// The nested class token that failed validation
        nested_class_token: Option<Token>,
    },

    /// PE structure validation failed.
    ///
    /// This error occurs when PE format validation fails during raw validation,
    /// such as section alignment or RVA validation.
    #[error("PE structure validation failed: {message}")]
    ValidationPeStructureError {
        /// Details about the PE structure validation failure
        message: String,
    },

    /// Signature validation failed.
    ///
    /// This error occurs when method or field signature validation fails
    /// during blob signature parsing and validation.
    #[error("Signature validation failed: {message}")]
    ValidationSignatureError {
        /// Details about the signature validation failure
        message: String,
        /// Optional signature blob data for debugging
        signature_data: Option<Vec<u8>>,
    },

    // Binary Writing Errors
    /// Assembly validation failed before writing.
    ///
    /// This error occurs when pre-write validation detects issues that
    /// would prevent successful binary generation.
    #[error("Binary write validation failed: {message}")]
    WriteValidationFailed {
        /// Details about the validation failure
        message: String,
    },

    /// Layout planning failed during binary generation.
    ///
    /// This error occurs when the write planner cannot determine a valid
    /// layout for the output file, such as when the file would exceed
    /// configured size limits.
    #[error("Binary write layout planning failed: {message}")]
    WriteLayoutFailed {
        /// Details about the layout failure
        message: String,
    },

    /// Memory mapping failed during binary writing.
    ///
    /// This error occurs when the memory-mapped file cannot be created
    /// or accessed for writing the output assembly.
    #[error("Binary write memory mapping failed: {message}")]
    WriteMmapFailed {
        /// Details about the memory mapping failure
        message: String,
    },

    /// Heap writing failed during binary generation.
    ///
    /// This error occurs when writing metadata heaps (strings, blobs, etc.)
    /// to the output file fails.
    #[error("Binary write heap writing failed: {message}")]
    WriteHeapFailed {
        /// Details about the heap writing failure
        message: String,
    },

    /// Table writing failed during binary generation.
    ///
    /// This error occurs when writing metadata tables to the output file fails.
    #[error("Binary write table writing failed: {message}")]
    WriteTableFailed {
        /// Details about the table writing failure
        message: String,
    },

    /// PE structure writing failed during binary generation.
    ///
    /// This error occurs when writing PE headers, sections, or other
    /// PE-specific structures to the output file fails.
    #[error("Binary write PE structure writing failed: {message}")]
    WritePeFailed {
        /// Details about the PE writing failure
        message: String,
    },

    /// File finalization failed during binary writing.
    ///
    /// This error occurs when the final step of writing (such as flushing,
    /// syncing, or closing the output file) fails.
    #[error("Binary write finalization failed: {message}")]
    WriteFinalizationFailed {
        /// Details about the finalization failure
        message: String,
    },

    /// Binary writing configuration is invalid.
    ///
    /// This error occurs when the provided writer configuration contains
    /// invalid or conflicting settings.
    #[error("Binary write configuration invalid: {message}")]
    WriteInvalidConfig {
        /// Details about the configuration error
        message: String,
    },

    /// File size would exceed configured limits.
    ///
    /// This error occurs when the planned output file size exceeds the
    /// maximum allowed size set in the writer configuration.
    #[error("Binary write file size {actual} exceeds maximum allowed size {max}")]
    WriteFileSizeExceeded {
        /// The actual file size that would be generated
        actual: u64,
        /// The maximum allowed file size
        max: u64,
    },

    /// Required metadata is missing or invalid for binary writing.
    ///
    /// This error occurs when the assembly is missing metadata required
    /// for binary generation, or when the metadata is in an invalid state.
    #[error("Binary write missing required metadata: {message}")]
    WriteMissingMetadata {
        /// Details about the missing metadata
        message: String,
    },

    /// Internal error during binary writing.
    ///
    /// This error represents an internal inconsistency or bug in the
    /// binary writing logic that should not occur under normal conditions.
    #[error("Binary write internal error: {message}")]
    WriteInternalError {
        /// Details about the internal error
        message: String,
    },

    // Assembly Encoding Errors
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

    /// Invalid branch instruction.
    ///
    /// This error occurs when attempting to use the branch instruction
    /// encoding method with a non-branch instruction mnemonic.
    #[error("Invalid branch instruction: {0}")]
    InvalidBranchInstruction(String),

    /// Invalid branch operand type.
    ///
    /// This error occurs when a branch instruction has an operand type
    /// that is not valid for branch offset encoding.
    #[error("Invalid branch operand type - must be Int8, Int16, or Int32")]
    InvalidBranchOperandType,

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

    /// Branch offset out of range.
    ///
    /// This error occurs when a calculated branch offset exceeds the
    /// maximum range for the instruction's offset size.
    #[error("Branch offset {offset} out of range for {instruction_size}-byte instruction")]
    BranchOffsetOutOfRange {
        /// The calculated offset
        offset: i32,
        /// The instruction offset size in bytes
        instruction_size: u8,
    },

    /// Invalid branch offset size.
    ///
    /// This error occurs when an invalid offset size is specified
    /// for branch instruction encoding.
    #[error("Invalid branch offset size: {0} bytes")]
    InvalidBranchOffsetSize(u8),
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            // Handle non-cloneable variants by converting to string representation
            Error::FileError(io_err) => Error::Error(io_err.to_string()),
            Error::GoblinErr(goblin_err) => Error::Error(goblin_err.to_string()),
            // For validation errors that have Box<Error> sources, clone them recursively
            Error::ValidationStage1Failed { source, message } => Error::ValidationStage1Failed {
                source: source.clone(),
                message: message.clone(),
            },
            Error::ValidationRawValidatorFailed {
                validator,
                message,
                source,
            } => Error::ValidationRawValidatorFailed {
                validator: validator.clone(),
                message: message.clone(),
                source: source.clone(),
            },
            Error::ValidationOwnedValidatorFailed {
                validator,
                message,
                source,
            } => Error::ValidationOwnedValidatorFailed {
                validator: validator.clone(),
                message: message.clone(),
                source: source.clone(),
            },
            // For all other variants, convert to their string representation and use GeneralError
            other => Error::Error(other.to_string()),
        }
    }
}
