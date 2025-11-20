//! Representation and parsing of CIL method bodies in .NET assemblies.
//!
//! This module provides types and logic for decoding method headers, CIL bytecode, local variable
//! signatures, and exception handling regions from .NET metadata. Supports both tiny and fat method
//! headers as specified by ECMA-335.
//!
//! # Method Body Format
//!
//! .NET methods can have two types of headers:
//!
//! ## Tiny Headers
//! - **Size**: 1 byte
//! - **Code Size**: Up to 63 bytes
//! - **Max Stack**: Fixed at 8
//! - **Local Variables**: None allowed
//! - **Exception Handling**: Not supported
//! - **Use Case**: Simple methods with minimal bytecode
//!
//! ## Fat Headers
//! - **Size**: 12 bytes minimum
//! - **Code Size**: Up to 4GB
//! - **Max Stack**: Configurable up to 65535
//! - **Local Variables**: Supported with signature token
//! - **Exception Handling**: Full support with multiple handlers
//! - **Use Case**: Complex methods with significant bytecode
//!
//! # Exception Handling
//!
//! Fat method headers can include exception handling sections with:
//! - **Try Blocks**: Protected code regions
//! - **Handler Types**: Exception, finally, fault, and filter handlers
//! - **Multiple Handlers**: Support for nested and sequential exception handling
//! - **Section Formats**: Both tiny (12-byte) and fat (24-byte) handler entries
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe:
//! - **`MethodBody`**: Immutable after construction
//! - **Parsing**: No shared state during parsing operations
//! - **Exception Handlers**: Read-only data structures
//!
//! # Usage Patterns
//!
//! ## Basic Method Information
//! ```rust,ignore
//! use dotscope::metadata::method::MethodBody;
//!
//! let method_data = /* ... method body bytes ... */;
//! let body = MethodBody::from(method_data)?;
//!
//! println!("Method has {} bytes of IL code", body.size_code);
//! println!("Header type: {}", if body.is_fat { "Fat" } else { "Tiny" });
//! ```
//!
//! ## Local Variable Analysis
//! ```rust,ignore
//! if body.local_var_sig_token != 0 {
//!     println!("Method has local variables (signature token: 0x{:08X})",
//!              body.local_var_sig_token);
//!     if body.is_init_local {
//!         println!("Local variables are zero-initialized");
//!     }
//! }
//! ```
//!
//! ## Exception Handler Processing
//! ```rust,ignore
//! if body.is_exception_data {
//!     println!("Method has {} exception handlers", body.exception_handlers.len());
//!     for (i, handler) in body.exception_handlers.iter().enumerate() {
//!         println!("Handler {}: try=[{:#x}..{:#x}], handler=[{:#x}..{:#x}]",
//!                  i, handler.try_offset,
//!                  handler.try_offset + handler.try_length,
//!                  handler.handler_offset,
//!                  handler.handler_offset + handler.handler_length);
//!     }
//! }
//! ```
//!
//! # Examples
//!
//! ```rust,ignore
//! use dotscope::{CilObject, metadata::method::MethodBody};
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//! let methods = assembly.methods();
//!
//! for entry in methods.iter() {
//!     let (token, method) = (entry.key(), entry.value());
//!     if let Some(body) = method.body.get() {
//!         println!("Method {}: {} bytes of IL code", method.name, body.size_code);
//!         println!("  Max stack: {}", body.max_stack);
//!         println!("  Header type: {}", if body.is_fat { "Fat" } else { "Tiny" });
//!         if body.local_var_sig_token != 0 {
//!             println!("  Has local variables (token: 0x{:08X})", body.local_var_sig_token);
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//! - ECMA-335 6th Edition, Partition II, Section 25.4 - Method Header Format
//! - ECMA-335 6th Edition, Partition II, Section 25.4.6 - Exception Handling Data Sections

use crate::{
    metadata::method::{ExceptionHandler, ExceptionHandlerFlags, MethodBodyFlags, SectionFlags},
    utils::{read_le, read_le_at},
    Result,
};

/// Describes one method that has been compiled to CIL bytecode.
///
/// The `MethodBody` struct represents the parsed body of a .NET method, including header information,
/// code size, stack requirements, local variable signature, and exception handling regions.
///
/// # Header Format Detection
///
/// The structure automatically detects whether the method uses a tiny or fat header format
/// based on the first byte(s) of the method body data:
/// - **Tiny Format**: Single byte header for methods with ≤63 bytes of code
/// - **Fat Format**: 12-byte header for complex methods with extensive metadata
///
/// # Field Organization
///
/// ## Size Information
/// - [`Self::size_code`]: Length of the actual CIL instructions in bytes
/// - [`Self::size_header`]: Length of the method header (1 for tiny, 12+ for fat)
///
/// ## Stack and Variables
/// - [`Self::max_stack`]: Maximum operand stack depth during execution
/// - [`Self::local_var_sig_token`]: Metadata token for local variable type signature
/// - [`Self::is_init_local`]: Whether local variables are zero-initialized
///
/// ## Format and Features
/// - [`Self::is_fat`]: Whether this method uses the fat header format
/// - [`Self::is_exception_data`]: Whether exception handling data is present
/// - [`Self::exception_handlers`]: Collection of exception handling regions
///
/// # Memory Layout
///
/// ```text
/// Tiny Header (1 byte):
/// ┌─────────────────────────────────────┐
/// │ Size(6) │ Reserved(2) │ Format(2)   │
/// └─────────────────────────────────────┘
///
/// Fat Header (12 bytes):
/// ┌─────────────────────────────────────┐
/// │ Flags(12) │ Size(4) │ Format(2)     │  (bytes 0-1)
/// ├─────────────────────────────────────┤
/// │ MaxStack (16 bits)                  │  (bytes 2-3)
/// ├─────────────────────────────────────┤
/// │ CodeSize (32 bits)                  │  (bytes 4-7)
/// ├─────────────────────────────────────┤
/// │ LocalVarSigTok (32 bits)            │  (bytes 8-11)
/// └─────────────────────────────────────┘
/// ```
///
/// # Thread Safety
///
/// `MethodBody` is fully thread-safe:
/// - All fields are immutable after construction
/// - No interior mutability or shared state
/// - Safe to share across threads without synchronization
pub struct MethodBody {
    /// Size of the method code (length of all CIL instructions, excluding the header) in bytes
    pub size_code: usize,
    /// Size of the method header in bytes (1 for tiny format, 12+ for fat format)
    pub size_header: usize,
    /// Metadata token for a signature describing the layout of local variables (0 = no locals)
    pub local_var_sig_token: u32,
    /// Maximum number of items on the operand stack during method execution
    pub max_stack: usize,
    /// Flag indicating the method header format (false = tiny, true = fat)
    pub is_fat: bool,
    /// Flag indicating whether to zero-initialize all local variables before method execution
    pub is_init_local: bool,
    /// Flag indicating whether this method has exception handling data sections
    pub is_exception_data: bool,
    /// Collection of exception handlers for this method (empty if no exception handling)
    pub exception_handlers: Vec<ExceptionHandler>,
}

impl MethodBody {
    /// Create a `MethodBody` object from a sequence of bytes.
    ///
    /// Parses a complete .NET method body including header, CIL instructions, and optional
    /// exception handling sections. Automatically detects and handles both tiny and fat
    /// header formats according to ECMA-335 specifications.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the complete method body data, starting with
    ///   the method header and including all CIL instructions and exception handling sections
    ///
    /// # Returns
    ///
    /// * [`Ok`]([`MethodBody`]) - Successfully parsed method body with all metadata
    /// * [`Err`]([`crate::Error`]) - Parsing failed due to invalid format, insufficient data, or corruption
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    /// - **Empty Data**: The provided byte slice is empty
    /// - **Invalid Format**: Header format bits don't match tiny or fat patterns
    /// - **Insufficient Data**: Not enough bytes for the declared header or code size
    /// - **Malformed Sections**: Exception handling sections have invalid structure
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodBody;
    ///
    /// let method_data = &[0x16, 0x00, 0x2A]; // Simple method: ldarg.0, ret
    /// let body = MethodBody::from(method_data)?;
    ///
    /// assert!(!body.is_fat);
    /// assert_eq!(body.size_code, 5);
    /// assert_eq!(body.max_stack, 8); // Tiny format default
    /// ```
    pub fn from(data: &[u8]) -> Result<MethodBody> {
        if data.is_empty() {
            return Err(malformed_error!("Provided data for body parsing is empty"));
        }

        let first_byte = read_le::<u8>(data)?;
        match MethodBodyFlags::from_bits_truncate(u16::from(first_byte & 0b_00000011_u8)) {
            MethodBodyFlags::TINY_FORMAT => {
                let size_code = (first_byte >> 2) as usize;
                if size_code + 1 > data.len() {
                    return Err(out_of_bounds_error!());
                }

                Ok(MethodBody {
                    size_code,
                    size_header: 1,
                    local_var_sig_token: 0,
                    max_stack: 8,
                    is_fat: false,
                    is_init_local: false,
                    is_exception_data: false,
                    exception_handlers: Vec::new(),
                })
            }
            MethodBodyFlags::FAT_FORMAT => {
                if data.len() < 12 {
                    return Err(out_of_bounds_error!());
                }

                let first_duo = read_le::<u16>(data)?;

                let size_header = (first_duo >> 12) * 4;
                let size_code = read_le::<u32>(&data[4..])?;
                if data.len() < (size_code as usize + size_header as usize) {
                    return Err(out_of_bounds_error!());
                }

                let local_var_sig_token = read_le::<u32>(&data[8..])?;
                let flags_header =
                    MethodBodyFlags::from_bits_truncate(first_duo & 0b_0000111111111111_u16);
                let max_stack = read_le::<u16>(&data[2..])? as usize;

                let is_init_local = flags_header.contains(MethodBodyFlags::INIT_LOCALS);

                // Exception Handling -> II.25.4.6
                // The extra sections currently can only contain exception handling data
                let mut exception_handlers = Vec::new();
                if flags_header.contains(MethodBodyFlags::MORE_SECTS) {
                    // Set cursor to the end of the header + body, to process exception tables
                    let mut cursor = size_header as usize + size_code as usize;
                    cursor = (cursor + 3) & !3;

                    while data.len() > (cursor + 4) {
                        let method_data_section_flags =
                            SectionFlags::from_bits_truncate(read_le::<u8>(&data[cursor..])?);
                        if !method_data_section_flags.contains(SectionFlags::EHTABLE) {
                            break;
                        }

                        if method_data_section_flags.contains(SectionFlags::FAT_FORMAT) {
                            let method_data_section_size =
                                read_le::<u32>(&data[cursor + 1..])? & 0x00FF_FFFF;
                            if method_data_section_size < 4
                                || data.len() < (cursor + method_data_section_size as usize)
                            {
                                break;
                            }

                            cursor += 4;

                            for _ in 0..(method_data_section_size - 4) / 24 {
                                exception_handlers.push(ExceptionHandler {
                                    // Intentionally truncating u32 to u16 for exception handler flags
                                    #[allow(clippy::cast_possible_truncation)]
                                    flags: ExceptionHandlerFlags::from_bits_truncate(read_le_at::<
                                        u32,
                                    >(
                                        data,
                                        &mut cursor,
                                    )?
                                        as u16),
                                    try_offset: read_le_at::<u32>(data, &mut cursor)?,
                                    try_length: read_le_at::<u32>(data, &mut cursor)?,
                                    handler_offset: read_le_at::<u32>(data, &mut cursor)?,
                                    handler_length: read_le_at::<u32>(data, &mut cursor)?,
                                    filter_offset: read_le_at::<u32>(data, &mut cursor)?,
                                    handler: None,
                                });
                            }
                        } else {
                            let method_data_section_size =
                                u32::from(read_le::<u8>(&data[cursor + 1..])?);
                            if method_data_section_size < 4
                                || data.len() < (cursor + method_data_section_size as usize)
                            {
                                break;
                            }

                            cursor += 4;
                            for _ in 0..(method_data_section_size - 4) / 12 {
                                exception_handlers.push(ExceptionHandler {
                                    flags: ExceptionHandlerFlags::from_bits_truncate(read_le_at::<
                                        u16,
                                    >(
                                        data,
                                        &mut cursor,
                                    )?),
                                    try_offset: u32::from(read_le_at::<u16>(data, &mut cursor)?),
                                    try_length: u32::from(read_le_at::<u8>(data, &mut cursor)?),
                                    handler_offset: u32::from(read_le_at::<u16>(
                                        data,
                                        &mut cursor,
                                    )?),
                                    handler_length: u32::from(read_le_at::<u8>(data, &mut cursor)?),
                                    filter_offset: read_le_at::<u32>(data, &mut cursor)?,
                                    handler: None,
                                });
                            }
                        }

                        if !method_data_section_flags.contains(SectionFlags::MORE_SECTS) {
                            break;
                        }
                    }
                }

                Ok(MethodBody {
                    size_code: size_code as usize,
                    size_header: size_header as usize,
                    local_var_sig_token,
                    max_stack,
                    is_fat: true,
                    is_init_local,
                    is_exception_data: !exception_handlers.is_empty(),
                    exception_handlers,
                })
            }
            _ => Err(malformed_error!(
                "MethodHeader is neither FAT nor TINY - {}",
                first_byte
            )),
        }
    }

    /// Get the full size of this method including header and code.
    ///
    /// Returns the total size in bytes by combining the header size and code size.
    /// This represents the complete footprint of the method in the assembly file.
    ///
    /// # Returns
    ///
    /// The total size in bytes (header + code). Note that exception handling
    /// sections are stored separately and not included in this size.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let body = MethodBody::from(method_data)?;
    /// let total_size = body.size();
    /// assert_eq!(total_size, body.size_header + body.size_code);
    /// ```
    #[must_use]
    pub fn size(&self) -> usize {
        self.size_code + self.size_header
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::method::ExceptionHandlerFlags;

    use super::*;

    #[test]
    fn tiny() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF7358
        HeaderOffset:       0xF7358
        MaxStack:           8
        LocalVarSigToken:   0
        Locals:             0
        ExceptionHandlers:  0
        Instructions:       4
        CodeSize:           17
        Size:               18
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_TINY_0600032D.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(!method_header.is_fat);
        assert!(!method_header.is_exception_data);
        assert!(!method_header.is_init_local);
        assert_eq!(method_header.max_stack, 8);
        assert_eq!(method_header.size_code, 18);
        assert_eq!(method_header.size_header, 1);
        assert_eq!(method_header.size(), 19);
        assert_eq!(method_header.local_var_sig_token, 0);
    }

    #[test]
    fn fat() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF77D8
        HeaderOffset:       0xF77D8
        MaxStack:           5
        LocalVarSigToken:   0x11000059
        Locals:             4
        ExceptionHandlers:  0
        Instructions:       79
        CodeSize:           0x9B
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_0600033E.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(!method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 5);
        assert_eq!(method_header.size_code, 0x9B);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 167);
        assert_eq!(method_header.local_var_sig_token, 0x11000059);
    }

    #[test]
    fn fat_exceptions_1() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF7898
        HeaderOffset:       0xF7898
        MaxStack:           1
        LocalVarSigToken:   0x11000003
        Locals:             1
        ExceptionHandlers:  1
        Instructions:       15
        CodeSize:           0x1C
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_06000341.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 1);
        assert_eq!(method_header.size_code, 30);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 42);
        assert_eq!(method_header.local_var_sig_token, 0x11000003);
        assert_eq!(method_header.exception_handlers.len(), 1);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::EXCEPTION));
        assert_eq!(method_header.exception_handlers[0].try_offset, 0);
        assert_eq!(method_header.exception_handlers[0].try_length, 0xF);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 0xF);
        assert_eq!(method_header.exception_handlers[0].handler_length, 0xD);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0x100003F);
    }

    #[test]
    fn fat_exceptions_tiny_section_2() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xECC4C
        HeaderOffset:       0xECC4C
        MaxStack:           3
        LocalVarSigToken:   0x1100001A
        Locals:             2
        ExceptionHandlers:  1
        Instructions:       18
        CodeSize:           0x2D
        Flags:
            - InitLocals
        */

        let data = include_bytes!(
            "../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N1_2LOCALS_060001AA.bin"
        );

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 3);
        assert_eq!(method_header.size_code, 0x2E);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 58);
        assert_eq!(method_header.local_var_sig_token, 0x1100001A);
        assert_eq!(method_header.exception_handlers.len(), 1);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[0].try_offset, 0x8);
        assert_eq!(method_header.exception_handlers[0].try_length, 0x1B);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 0x23);
        assert_eq!(method_header.exception_handlers[0].handler_length, 0xA);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0);
    }

    #[test]
    fn fat_exceptions_fat_section_3() {
        /*
        WindowsBase.dll

        HeaderRVA:          0xF9839
        HeaderOffset:       0xF9839
        MaxStack:           5
        LocalVarSigToken:   0x11000070
        Locals:             10
        ExceptionHandlers:  2
        Instructions:       156
        CodeSize:           0x19F
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000421.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 5);
        assert_eq!(method_header.size_code, 0x19F);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 427);
        assert_eq!(method_header.local_var_sig_token, 0x11000070);
        assert_eq!(method_header.exception_handlers.len(), 2);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[0].try_offset, 0x145);
        assert_eq!(method_header.exception_handlers[0].try_length, 0x28);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 0x16D);
        assert_eq!(method_header.exception_handlers[0].handler_length, 0xE);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0);
        assert!(method_header.exception_handlers[1]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[1].try_offset, 0x9);
        assert_eq!(method_header.exception_handlers[1].try_length, 0x18A);
        assert_eq!(method_header.exception_handlers[1].handler_offset, 0x193);
        assert_eq!(method_header.exception_handlers[1].handler_length, 0xA);
        assert_eq!(method_header.exception_handlers[1].filter_offset, 0);
    }

    #[test]
    fn fat_exceptions_multiple() {
        /*
        WindowsBase.dll

        HeaderRVA:          0x114140
        HeaderOffset:       0x114140
        MaxStack:           3
        LocalVarSigToken:   0x1100007C
        Locals:             2
        ExceptionHandlers:  2
        Instructions:       32
        CodeSize:           0x51
        Flags:
            - InitLocals
        */

        let data = include_bytes!("../../../tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000D54.bin");

        let method_header = MethodBody::from(data).unwrap();

        assert!(method_header.is_fat);
        assert!(method_header.is_exception_data);
        assert!(method_header.is_init_local);
        assert_eq!(method_header.max_stack, 3);
        assert_eq!(method_header.size_code, 81);
        assert_eq!(method_header.size_header, 12);
        assert_eq!(method_header.size(), 93);
        assert_eq!(method_header.local_var_sig_token, 0x1100007C);

        assert_eq!(method_header.exception_handlers.len(), 2);
        assert!(method_header.exception_handlers[0]
            .flags
            .contains(ExceptionHandlerFlags::FINALLY));
        assert_eq!(method_header.exception_handlers[0].try_offset, 17);
        assert_eq!(method_header.exception_handlers[0].try_length, 48);
        assert_eq!(method_header.exception_handlers[0].handler_offset, 65);
        assert_eq!(method_header.exception_handlers[0].handler_length, 10);
        assert_eq!(method_header.exception_handlers[0].filter_offset, 0);

        assert!(method_header.exception_handlers[1]
            .flags
            .contains(ExceptionHandlerFlags::EXCEPTION));
        assert_eq!(method_header.exception_handlers[1].try_offset, 0);
        assert_eq!(method_header.exception_handlers[1].try_length, 77);
        assert_eq!(method_header.exception_handlers[1].handler_offset, 77);
        assert_eq!(method_header.exception_handlers[1].handler_length, 3);
        assert_eq!(method_header.exception_handlers[1].filter_offset, 0x100001D);
    }
}
