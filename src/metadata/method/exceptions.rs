//! Exception handler representation for CIL methods in .NET assemblies.
//!
//! This module provides types and flags for decoding and analyzing try/catch/finally/fault regions
//! in CIL method bodies, as specified by ECMA-335. Used for control flow analysis and decompilation.

use bitflags::bitflags;

use crate::metadata::typesystem::CilTypeRc;

bitflags! {
    /// Exception handler flags defining the type of exception handling clause.
    ///
    /// These flags determine how the exception handler processes exceptions and
    /// control flow within try/catch/finally blocks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExceptionHandlerFlags: u16 {
        /// A typed exception clause.
        ///
        /// The `class_token` field contains the metadata token of the exception type
        /// that this handler catches. This is the most common exception handler type.
        const EXCEPTION = 0x0000;

        /// An exception filter and handler clause.
        ///
        /// Uses a filter expression to determine whether to handle the exception.
        /// The filter code is executed before the handler to test the exception.
        const FILTER = 0x0001;

        /// A finally clause.
        ///
        /// Code that executes regardless of whether an exception occurs. Finally
        /// blocks are guaranteed to run during normal execution and exception handling.
        const FINALLY = 0x0002;

        /// A fault clause (finally that executes only on exception).
        ///
        /// Similar to finally, but only executes when an exception is thrown,
        /// not during normal execution flow.
        const FAULT = 0x0004;
    }
}

/// Exception handler defining try/catch/finally blocks within a method.
///
/// Exception handlers define regions of IL code that handle exceptions, implement
/// finally blocks, or provide fault handling. Each handler specifies the protected
/// region (try block) and the handling code location.
///
/// # Handler Types
/// - **Exception Handlers** - Catch specific exception types
/// - **Filter Handlers** - Use custom filter logic to determine handling
/// - **Finally Handlers** - Execute regardless of exception occurrence  
/// - **Fault Handlers** - Execute only when exceptions occur
///
/// # Layout in IL
///
/// ```text
/// try {
///     // try_offset -> try_offset + try_length
///     // Protected code region
/// }
/// catch (ExceptionType) {
///     // handler_offset -> handler_offset + handler_length  
///     // Exception handling code
/// }
/// ```
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{CilObject, metadata::method::ExceptionHandlerFlags};
///
/// let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
/// let methods = assembly.methods();
///
/// for entry in methods.iter() {
///     let (token, method) = (entry.key(), entry.value());
///     if let Some(body) = method.body.get() {
///         for handler in &body.exception_handlers {
///             match handler.flags {
///                 ExceptionHandlerFlags::EXCEPTION => {
///                     println!("Exception handler for type token: 0x{:08X}", handler.filter_offset);
///                 },
///                 ExceptionHandlerFlags::FINALLY => {
///                     println!("Finally block at offset: 0x{:04X}", handler.handler_offset);
///                 },
///                 _ => println!("Other handler type: {:?}", handler.flags),
///             }
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # References
/// - ECMA-335 6th Edition, Partition II, Section 25.4.6 - Exception Handling
pub struct ExceptionHandler {
    /// Flags describing the type of exception handler (catch, filter, finally, fault).
    pub flags: ExceptionHandlerFlags,
    /// Offset in bytes of try block from start of method body.
    pub try_offset: u32,
    /// Length in bytes of the try block.
    pub try_length: u32,
    /// Location of the handler for this try block.
    pub handler_offset: u32,
    /// Size of the handler code in bytes.
    pub handler_length: u32,
    /// If flags == EXCEPTION, then this type will handle the exception.
    pub handler: Option<CilTypeRc>,
    /// Offset in method body for filter-based exception handler.
    pub filter_offset: u32,
}
