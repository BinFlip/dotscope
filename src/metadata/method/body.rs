//! Representation and parsing of CIL method bodies in .NET assemblies.
//!
//! This module provides types and logic for decoding method headers, CIL bytecode, local variable
//! signatures, and exception handling regions from .NET metadata. Supports both tiny and fat method
//! headers as specified by ECMA-335.
//!
//! # Examples
//!
//! ```rust,no_run
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

use crate::{
    file::io::{read_le, read_le_at},
    metadata::method::{ExceptionHandler, ExceptionHandlerFlags, MethodBodyFlags, SectionFlags},
    Error::OutOfBounds,
    Result,
};

/// Describes one method that has been compiled to CIL bytecode.
///
/// The `MethodBody` struct represents the parsed body of a .NET method, including header information,
/// code size, stack requirements, local variable signature, and exception handling regions.
pub struct MethodBody {
    /// Size of the method (length of all instructions, not counting the header) in bytes
    pub size_code: usize,
    /// Size of the method header in bytes
    pub size_header: usize,
    /// `MetaData` token for a signature describing the layout of the local variables for the method. 0 == no local variables
    pub local_var_sig_token: u32,
    /// Maximum number of items on the operand stack
    pub max_stack: usize,
    /// Flag, indicating the type of the method header
    pub is_fat: bool,
    /// Flag, indicating to call default constructor on all local variables
    pub is_init_local: bool,
    /// Flag, indicating if this method does have exception handlers
    pub is_exception_data: bool,
    /// A list of exception handlers this method has
    pub exception_handlers: Vec<ExceptionHandler>,
}

impl MethodBody {
    /// Create a `MethodHeader` object from a sequence of bytes.
    ///
    /// # Arguments
    /// * `data` - The byte slice from which this object shall be created
    ///
    /// # Errors
    /// Returns an error if the data is empty, out of bounds, or malformed.
    pub fn from(data: &[u8]) -> Result<MethodBody> {
        if data.is_empty() {
            return Err(malformed_error!("Provided data for body parsing is empty"));
        }

        let first_byte = read_le::<u8>(data)?;
        match MethodBodyFlags::from_bits_truncate(u16::from(first_byte & 0b_00000011_u8)) {
            MethodBodyFlags::TINY_FORMAT => {
                let size_code = (first_byte >> 2) as usize;
                if size_code + 1 > data.len() {
                    return Err(OutOfBounds);
                }

                Ok(MethodBody {
                    size_code,
                    size_header: 1,
                    local_var_sig_token: 0,
                    max_stack: 0,
                    is_fat: false,
                    is_init_local: false,
                    is_exception_data: false,
                    exception_handlers: Vec::new(),
                })
            }
            MethodBodyFlags::FAT_FORMAT => {
                if data.len() < 12 {
                    return Err(OutOfBounds);
                }

                let first_duo = read_le::<u16>(data)?;

                let size_header = (first_duo >> 12) * 4;
                let size_code = read_le::<u32>(&data[4..])?;
                if data.len() < (size_code as usize + size_header as usize) {
                    return Err(OutOfBounds);
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

    /// Get the full size of this method
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
        assert_eq!(method_header.max_stack, 0);
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
