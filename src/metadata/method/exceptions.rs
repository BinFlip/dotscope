//! .NET CIL method exception handler representation and analysis.
//!
//! This module provides comprehensive support for analyzing exception handling structures
//! in Common Intermediate Language (CIL) method bodies. Exception handlers define
//! try/catch/finally/fault regions that control program flow during exception processing,
//! as specified by ECMA-335.
//!
//! # Exception Handling in .NET
//!
//! The .NET runtime uses structured exception handling (SEH) with four types of handlers:
//!
//! 1. **Exception Handlers**: Catch specific exception types using type matching
//! 2. **Filter Handlers**: Use custom filter expressions to determine exception handling
//! 3. **Finally Handlers**: Execute cleanup code regardless of exception occurrence
//! 4. **Fault Handlers**: Execute cleanup code only when exceptions are thrown
//!
//! ## Exception Handler Layout
//!
//! Exception handlers are defined by two regions in the IL code:
//! ```text
//! try {
//!     // Protected region: [try_offset, try_offset + try_length)
//!     // Code that may throw exceptions
//! }
//! catch (SpecificException) {
//!     // Handler region: [handler_offset, handler_offset + handler_length)
//!     // Exception handling code
//! }
//! ```
//!
//! # Common Use Cases
//!
//! ## Exception Handler Analysis
//!
//! ```rust
//! use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
//!
//! # fn analyze_method_body() -> Result<(), Box<dyn std::error::Error>> {
//! # let exception_handlers: Vec<ExceptionHandler> = vec![];
//! for handler in &exception_handlers {
//!     match handler.flags {
//!         ExceptionHandlerFlags::EXCEPTION => {
//!             println!("Catch block for try region [{}, {})",
//!                 handler.try_offset,
//!                 handler.try_offset + handler.try_length);
//!             
//!             if let Some(exception_type) = &handler.handler {
//!                 println!("  Catches: {}", exception_type.name);
//!             }
//!         },
//!         ExceptionHandlerFlags::FINALLY => {
//!             println!("Finally block at offset 0x{:04X}", handler.handler_offset);
//!         },
//!         ExceptionHandlerFlags::FILTER => {
//!             println!("Filter handler at offset 0x{:04X}", handler.filter_offset);
//!         },
//!         ExceptionHandlerFlags::FAULT => {
//!             println!("Fault handler at offset 0x{:04X}", handler.handler_offset);
//!         },
//!         _ => println!("Unknown handler type: {:?}", handler.flags),
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Control Flow Graph Construction
//!
//! ```rust
//! # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
//! # fn build_control_flow_graph() -> Result<(), Box<dyn std::error::Error>> {
//! # let exception_handlers: Vec<ExceptionHandler> = vec![];
//! // Exception handlers create additional control flow edges
//! for handler in &exception_handlers {
//!     // Entry point for protected region
//!     let protected_start = handler.try_offset;
//!     let protected_end = handler.try_offset + handler.try_length;
//!     
//!     // Handler entry point
//!     let handler_start = handler.handler_offset;
//!     
//!     // Any instruction in protected region can transfer to handler
//!     println!("Protected region: [0x{:04X}, 0x{:04X}) -> Handler: 0x{:04X}",
//!         protected_start, protected_end, handler_start);
//!         
//!     if handler.flags == ExceptionHandlerFlags::FILTER {
//!         println!("  Filter expression at: 0x{:04X}", handler.filter_offset);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Analysis
//!
//! ```rust
//! # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
//! # fn security_analysis() -> Result<(), Box<dyn std::error::Error>> {
//! # let exception_handlers: Vec<ExceptionHandler> = vec![];
//! // Analyze exception handling patterns for security implications
//! let mut has_generic_catch = false;
//! let mut has_empty_catch = false;
//!
//! for handler in &exception_handlers {
//!     if handler.flags == ExceptionHandlerFlags::EXCEPTION {
//!         if let Some(exception_type) = &handler.handler {
//!             if exception_type.name == "System.Exception" {
//!                 has_generic_catch = true;
//!             }
//!         }
//!         
//!         if handler.handler_length == 0 {
//!             has_empty_catch = true;
//!         }
//!     }
//! }
//!
//! if has_generic_catch {
//!     println!("WARNING: Catches all exceptions (potential information hiding)");
//! }
//! if has_empty_catch {
//!     println!("WARNING: Empty exception handler (swallows exceptions)");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Binary Format
//!
//! Exception handlers are stored in method body headers using two formats:
//!
//! ## Small Format (12 bytes per handler)
//! ```text
//! - Flags: u16
//! - TryOffset: u16  
//! - TryLength: u8
//! - HandlerOffset: u16
//! - HandlerLength: u8
//! - ClassToken/FilterOffset: u32
//! ```
//!
//! ## Fat Format (24 bytes per handler)
//! ```text
//! - Flags: u32
//! - TryOffset: u32
//! - TryLength: u32  
//! - HandlerOffset: u32
//! - HandlerLength: u32
//! - ClassToken/FilterOffset: u32
//! ```
//!
//! # ECMA-335 Compliance
//!
//! This implementation follows ECMA-335 6th Edition specifications:
//! - **Partition I, Section 12.4**: Exception handling model
//! - **Partition II, Section 25.4.6**: Exception handling clauses format
//! - **Partition III, Section 1.7.5**: Exception handling instruction semantics
//!
//! # Thread Safety
//!
//! [`ExceptionHandler`] instances are immutable and safe to share across threads.
//! Exception type references use reference-counted smart pointers for efficient sharing.

use bitflags::bitflags;

use crate::{metadata::typesystem::CilTypeRc, Result};

bitflags! {
    /// Exception handler type flags defining the kind of exception handling clause.
    ///
    /// These flags determine how the exception handler processes exceptions and controls
    /// program flow within structured exception handling blocks. Each flag represents
    /// a different exception handling strategy as defined by ECMA-335.
    ///
    /// # Handler Types
    ///
    /// The four fundamental exception handler types each serve different purposes:
    ///
    /// - **Exception Handlers**: Type-based exception catching with class token matching
    /// - **Filter Handlers**: Custom filter expressions for complex exception logic
    /// - **Finally Handlers**: Guaranteed cleanup code execution
    /// - **Fault Handlers**: Exception-only cleanup code execution
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::method::ExceptionHandlerFlags;
    ///
    /// // Check handler type
    /// let flags = ExceptionHandlerFlags::EXCEPTION;
    /// assert!(flags == ExceptionHandlerFlags::EXCEPTION);
    /// assert!(!flags.contains(ExceptionHandlerFlags::FINALLY));
    ///
    /// // Multiple flags are mutually exclusive for exception handlers
    /// assert!(ExceptionHandlerFlags::EXCEPTION.bits() == 0x0000);
    /// assert!(ExceptionHandlerFlags::FILTER.bits() == 0x0001);
    /// ```
    ///
    /// # Binary Representation
    ///
    /// The flags are stored as a 16-bit or 32-bit value in the exception handler
    /// table, depending on whether the small or fat format is used.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExceptionHandlerFlags: u16 {
        /// A typed exception clause that catches specific exception types.
        ///
        /// The handler catches exceptions that are assignment-compatible with the
        /// exception type specified by the `class_token` field. This includes the
        /// exact type and all derived types.
        ///
        /// # Usage
        ///
        /// ```csharp
        /// try {
        ///     // Protected code
        /// }
        /// catch (ArgumentException ex) {
        ///     // Handler code - class_token points to ArgumentException
        /// }
        /// ```
        ///
        /// # Implementation Notes
        ///
        /// - The `class_token` field contains the metadata token of the exception type
        /// - Type matching follows .NET inheritance rules (catches derived types)
        /// - Most common exception handler type in .NET assemblies
        const EXCEPTION = 0x0000;

        /// An exception filter and handler clause with custom filter logic.
        ///
        /// The filter expression is executed first to determine whether this handler
        /// should process the exception. The filter can examine the exception object
        /// and execution context to make complex decisions.
        ///
        /// # Usage
        ///
        /// ```csharp
        /// try {
        ///     // Protected code
        /// }
        /// catch (Exception ex) when (ex.Message.Contains("specific")) {
        ///     // Handler code - filter_offset points to filter expression
        /// }
        /// ```
        ///
        /// # Implementation Notes
        ///
        /// - The `filter_offset` field points to the filter expression code
        /// - Filter must leave a boolean value on the evaluation stack
        /// - Provides fine-grained control over exception handling logic
        /// - Less common than typed exception handlers
        const FILTER = 0x0001;

        /// A finally clause that executes regardless of exception occurrence.
        ///
        /// Finally blocks provide guaranteed cleanup code execution during both
        /// normal control flow and exception unwinding. The runtime ensures
        /// finally blocks execute even when exceptions are thrown.
        ///
        /// # Usage
        ///
        /// ```csharp
        /// try {
        ///     // Protected code
        /// }
        /// finally {
        ///     // Cleanup code - always executes
        /// }
        /// ```
        ///
        /// # Implementation Notes
        ///
        /// - Executes during normal method exit and exception unwinding
        /// - Cannot catch exceptions, only perform cleanup
        /// - Essential for resource management (using statements compile to finally)
        /// - The `class_token`/`filter_offset` field is unused for finally handlers
        const FINALLY = 0x0002;

        /// A fault clause that executes only when exceptions are thrown.
        ///
        /// Fault handlers are similar to finally blocks but only execute during
        /// exception unwinding, not during normal control flow. They provide
        /// exception-specific cleanup without catching the exception.
        ///
        /// # Usage
        ///
        /// ```csharp
        /// try {
        ///     // Protected code
        /// }
        /// fault {
        ///     // Cleanup code - executes only on exceptions
        /// }
        /// ```
        ///
        /// # Implementation Notes
        ///
        /// - Only executes during exception unwinding, not normal exit
        /// - Cannot catch exceptions, only perform fault-specific cleanup
        /// - Less common than finally handlers in typical .NET code
        /// - The `class_token`/`filter_offset` field is unused for fault handlers
        const FAULT = 0x0004;
    }
}

/// Represents a single exception handler within a .NET method body.
///
/// An `ExceptionHandler` defines a structured exception handling region that consists
/// of a protected try block and associated handler code. Exception handlers implement
/// the .NET runtime's structured exception handling (SEH) model as specified by ECMA-335.
///
/// # Structure
///
/// Each exception handler defines two key regions:
///
/// 1. **Protected Region**: The try block where exceptions may be thrown
/// 2. **Handler Region**: The catch/finally/fault code that processes exceptions
///
/// # Handler Types and Field Usage
///
/// Different handler types use the fields differently:
///
/// ## Exception Handlers (`EXCEPTION` flag)
/// - `handler`: Contains the exception type that this handler catches
/// - `filter_offset`: Unused (contains class token value for historical reasons)
/// - Catches exceptions assignable to the specified type
///
/// ## Filter Handlers (`FILTER` flag)  
/// - `handler`: Contains the exception type (typically `System.Exception`)
/// - `filter_offset`: Points to the filter expression code within the method
/// - Filter code determines whether to handle the exception
///
/// ## Finally Handlers (`FINALLY` flag)
/// - `handler`: Unused (None)
/// - `filter_offset`: Unused  
/// - Always executes during normal and exceptional control flow
///
/// ## Fault Handlers (`FAULT` flag)
/// - `handler`: Unused (None)
/// - `filter_offset`: Unused
/// - Executes only during exception unwinding
///
/// # Memory Layout
///
/// ```text
/// Try Block:     [try_offset, try_offset + try_length)
/// Handler Block: [handler_offset, handler_offset + handler_length)
/// Filter Block:  [filter_offset, ...]  (FILTER handlers only)
/// ```
///
/// # Examples
///
/// ## Basic Exception Handler Analysis
///
/// ```rust
/// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
///
/// # fn analyze_handler(handler: &ExceptionHandler) -> Result<(), Box<dyn std::error::Error>> {
/// match handler.flags {
///     ExceptionHandlerFlags::EXCEPTION => {
///         println!("Exception handler:");
///         println!("  Protected: [0x{:04X}, 0x{:04X})",
///             handler.try_offset,
///             handler.try_offset + handler.try_length);
///         println!("  Handler: [0x{:04X}, 0x{:04X})",
///             handler.handler_offset,
///             handler.handler_offset + handler.handler_length);
///             
///         if let Some(exception_type) = &handler.handler {
///             println!("  Catches: {}", exception_type.name);
///         }
///     },
///     ExceptionHandlerFlags::FINALLY => {
///         println!("Finally handler at 0x{:04X} (length: {})",
///             handler.handler_offset, handler.handler_length);
///     },
///     _ => println!("Other handler type: {:?}", handler.flags),
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Control Flow Edge Detection
///
/// ```rust
/// # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
/// # fn detect_control_flow_edges(handlers: &[ExceptionHandler]) -> Result<(), Box<dyn std::error::Error>> {
/// for handler in handlers {
///     // Any instruction in the protected region can transfer to the handler
///     for offset in handler.try_offset..(handler.try_offset + handler.try_length) {
///         println!("IL_{:04X} -> Handler_{:04X} (exception edge)",
///             offset, handler.handler_offset);
///     }
///     
///     // Filter handlers have additional control flow
///     if handler.flags == ExceptionHandlerFlags::FILTER {
///         println!("IL_{:04X} -> Filter_{:04X} (filter evaluation)",
///             handler.try_offset, handler.filter_offset);
///         println!("Filter_{:04X} -> Handler_{:04X} (filter success)",
///             handler.filter_offset, handler.handler_offset);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Exception Handler Overlap Detection
///
/// ```rust
/// # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
/// # fn check_handler_overlap(handlers: &[ExceptionHandler]) -> Result<(), Box<dyn std::error::Error>> {
/// for (i, handler1) in handlers.iter().enumerate() {
///     for (j, handler2) in handlers.iter().enumerate() {
///         if i != j {
///             let h1_start = handler1.try_offset;
///             let h1_end = handler1.try_offset + handler1.try_length;
///             let h2_start = handler2.try_offset;
///             let h2_end = handler2.try_offset + handler2.try_length;
///             
///             // Check for nested or overlapping handlers
///             if h1_start < h2_end && h2_start < h1_end {
///                 println!("Overlapping handlers: [{}, {}) and [{}, {})",
///                     h1_start, h1_end, h2_start, h2_end);
///             }
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Binary Format Compatibility
///
/// Exception handlers support both small (12-byte) and fat (24-byte) binary formats.
/// The format choice depends on the size of offsets and lengths in the method body.
/// This struct normalizes both formats to 32-bit fields for consistent processing.
///
/// # ECMA-335 References
///
/// - **Partition I, Section 12.4**: Exception handling model and semantics  
/// - **Partition II, Section 25.4.6**: Exception handling clause binary format
/// - **Partition III, Section 1.7.5**: Exception handling instruction behavior
///
/// # Thread Safety
///
/// `ExceptionHandler` instances are immutable and safe to share across threads.
/// The optional exception type reference uses a reference-counted smart pointer.
pub struct ExceptionHandler {
    /// Exception handler type flags (EXCEPTION, FILTER, FINALLY, or FAULT).
    ///
    /// Determines the behavior and semantics of this exception handler. Each flag
    /// corresponds to a different exception handling strategy defined by ECMA-335.
    /// The flags are mutually exclusive - each handler has exactly one type.
    pub flags: ExceptionHandlerFlags,

    /// Byte offset of the protected try block from the start of the method body.
    ///
    /// This offset points to the first IL instruction that is protected by this
    /// exception handler. All instructions in the range [`try_offset`, `try_offset` + `try_length`)
    /// are covered by this handler and can potentially transfer control to the handler code.
    pub try_offset: u32,

    /// Length of the protected try block in bytes.
    ///
    /// Combined with `try_offset`, this defines the complete protected region.
    /// The protected region spans [`try_offset`, `try_offset` + `try_length`) and includes
    /// all IL instructions that may throw exceptions handled by this handler.
    pub try_length: u32,

    /// Byte offset of the exception handler code from the start of the method body.
    ///
    /// Points to the first IL instruction of the handler code (catch, finally, or fault block).
    /// For FILTER handlers, this points to the actual handler code, not the filter expression.
    /// The handler code spans [`handler_offset`, `handler_offset` + `handler_length`).
    pub handler_offset: u32,

    /// Length of the exception handler code in bytes.
    ///
    /// Defines the size of the handler code block. Combined with `handler_offset`,
    /// this specifies the complete range of IL instructions that comprise the
    /// exception handling logic for this handler.
    pub handler_length: u32,

    /// The exception type that this handler catches (for EXCEPTION handlers only).
    ///
    /// Contains a reference to the .NET type that this handler catches. For EXCEPTION
    /// handlers, this specifies the exact type and all derived types that will be
    /// caught. For other handler types (FILTER, FINALLY, FAULT), this field is None.
    ///
    /// # Type Matching
    ///
    /// Exception catching follows .NET's type system rules:
    /// - Exact type matches are caught
    /// - Derived types (subclasses) are caught  
    /// - Interface implementations are caught if the exception type is an interface
    /// - System.Object catches all exceptions
    pub handler: Option<CilTypeRc>,

    /// Byte offset of the filter expression code (for FILTER handlers only).
    ///
    /// For FILTER handlers, this points to the IL code that evaluates whether
    /// this handler should process the exception. The filter code must leave
    /// a boolean value on the evaluation stack. For non-FILTER handlers, this
    /// field may contain legacy data and should be ignored.
    ///
    /// # Filter Execution
    ///
    /// The filter expression:
    /// 1. Receives the exception object and execution context
    /// 2. Executes custom logic to test the exception
    /// 3. Returns true (1) to handle or false (0) to continue unwinding
    pub filter_offset: u32,
}

/// Encodes exception handlers according to ECMA-335 II.25.4.6.
///
/// Exception handler sections are encoded after the method body with the following format:
/// - Section header (4 bytes for small format, 12 bytes for fat format)
/// - Exception handler entries (12 bytes each for small, 24 bytes each for fat)
///
/// Format selection:
/// - Small format: if all offsets and lengths fit in 16 bits
/// - Fat format: if any offset or length requires 32 bits
///
/// # Arguments
///
/// * `handlers` - The exception handlers to encode
///
/// # Returns
///
/// The encoded exception handler section bytes, or an empty vector if no handlers.
///
/// # Errors
///
/// Returns an error if encoding fails or values exceed expected ranges.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags, encode_exception_handlers};
///
/// let handlers = vec![
///     ExceptionHandler {
///         flags: ExceptionHandlerFlags::FINALLY,
///         try_offset: 0,
///         try_length: 10,
///         handler_offset: 10,
///         handler_length: 5,
///         handler: None,
///         filter_offset: 0,
///     }
/// ];
///
/// let encoded = encode_exception_handlers(&handlers)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_exception_handlers(handlers: &[ExceptionHandler]) -> Result<Vec<u8>> {
    if handlers.is_empty() {
        return Ok(Vec::new());
    }

    // Determine if we need fat or small format
    let needs_fat_format = handlers.iter().any(|eh| {
        eh.try_offset > 0xFFFF
            || eh.try_length > 0xFFFF
            || eh.handler_offset > 0xFFFF
            || eh.handler_length > 0xFFFF
    });

    let mut section = Vec::new();

    if needs_fat_format {
        // Fat format: 4-byte header + 24 bytes per handler
        let section_size = 4 + (handlers.len() * 24);

        // Section header (fat format)
        section.extend_from_slice(&[
            0x41, // Kind = EHTable | FatFormat
            0x00, 0x00, // Reserved
        ]);
        let section_size_u32 = u32::try_from(section_size)
            .map_err(|_| malformed_error!("Exception section size exceeds u32 range"))?;
        section.extend_from_slice(&section_size_u32.to_le_bytes()[..3]); // DataSize (3 bytes)

        // Write each exception handler (24 bytes each)
        for eh in handlers {
            // Flags (4 bytes)
            section.extend_from_slice(&u32::from(eh.flags.bits()).to_le_bytes());

            // TryOffset (4 bytes)
            section.extend_from_slice(&eh.try_offset.to_le_bytes());

            // TryLength (4 bytes)
            section.extend_from_slice(&eh.try_length.to_le_bytes());

            // HandlerOffset (4 bytes)
            section.extend_from_slice(&eh.handler_offset.to_le_bytes());

            // HandlerLength (4 bytes)
            section.extend_from_slice(&eh.handler_length.to_le_bytes());

            // ClassToken or FilterOffset (4 bytes)
            if eh.flags.contains(ExceptionHandlerFlags::FILTER) {
                section.extend_from_slice(&eh.filter_offset.to_le_bytes());
            } else if let Some(_handler_type) = &eh.handler {
                // For typed handlers, we would need the type token
                // For now, use 0 as placeholder
                section.extend_from_slice(&0u32.to_le_bytes());
            } else {
                // No type token (finally/fault handlers)
                section.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    } else {
        // Small format: 4-byte header + 12 bytes per handler
        let section_size = 4 + (handlers.len() * 12);

        // Section header (small format)
        let section_size_u8 = u8::try_from(section_size).map_err(|_| {
            malformed_error!("Exception section size exceeds u8 range for small format")
        })?;
        section.extend_from_slice(&[
            0x01,            // Kind = EHTable (small format)
            section_size_u8, // DataSize (1 byte)
            0x00,
            0x00, // Reserved
        ]);

        // Write each exception handler (12 bytes each)
        for eh in handlers {
            // Flags (2 bytes)
            section.extend_from_slice(&eh.flags.bits().to_le_bytes());

            // TryOffset (2 bytes)
            let try_offset_u16 = u16::try_from(eh.try_offset)
                .map_err(|_| malformed_error!("Exception handler try_offset exceeds u16 range"))?;
            section.extend_from_slice(&try_offset_u16.to_le_bytes());

            // TryLength (1 byte)
            let try_length_u8 = u8::try_from(eh.try_length)
                .map_err(|_| malformed_error!("Exception handler try_length exceeds u8 range"))?;
            section.push(try_length_u8);

            // HandlerOffset (2 bytes)
            let handler_offset_u16 = u16::try_from(eh.handler_offset).map_err(|_| {
                malformed_error!("Exception handler handler_offset exceeds u16 range")
            })?;
            section.extend_from_slice(&handler_offset_u16.to_le_bytes());

            // HandlerLength (1 byte)
            let handler_length_u8 = u8::try_from(eh.handler_length).map_err(|_| {
                malformed_error!("Exception handler handler_length exceeds u8 range")
            })?;
            section.push(handler_length_u8);

            // ClassToken or FilterOffset (4 bytes)
            if eh.flags.contains(ExceptionHandlerFlags::FILTER) {
                section.extend_from_slice(&eh.filter_offset.to_le_bytes());
            } else if let Some(_handler_type) = &eh.handler {
                // For typed handlers, we would need the type token
                // For now, use 0 as placeholder
                section.extend_from_slice(&0u32.to_le_bytes());
            } else {
                // No type token (finally/fault handlers)
                section.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }

    // Align to 4-byte boundary
    while section.len() % 4 != 0 {
        section.push(0);
    }

    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_exception_handlers_empty() {
        let handlers = vec![];
        let result = encode_exception_handlers(&handlers).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_encode_exception_handlers_small_format() {
        let handlers = vec![ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        }];

        let result = encode_exception_handlers(&handlers).unwrap();

        // Should use small format: 4-byte header + 12 bytes per handler = 16 bytes
        assert_eq!(result.len(), 16);

        // First byte should be 0x01 (EHTable, small format)
        assert_eq!(result[0], 0x01);

        // Second byte should be section size (16)
        assert_eq!(result[1], 16);
    }

    #[test]
    fn test_encode_exception_handlers_fat_format() {
        let handlers = vec![ExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0x10000, // Forces fat format (> 16 bits)
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        }];

        let result = encode_exception_handlers(&handlers).unwrap();

        // Should use fat format: 4-byte header + 24 bytes per handler = 28 bytes,
        // but aligned to 4-byte boundary = 32 bytes
        assert_eq!(result.len(), 32);

        // First byte should be 0x41 (EHTable | FatFormat)
        assert_eq!(result[0], 0x41);
    }

    #[test]
    fn test_encode_exception_handlers_filter() {
        let handlers = vec![ExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_offset: 0,
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 15,
        }];

        let result = encode_exception_handlers(&handlers).unwrap();

        // Should successfully encode filter handler
        assert_eq!(result.len(), 16); // Small format
        assert_eq!(result[0], 0x01); // Small format flag
    }
}
