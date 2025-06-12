//! Type marshalling for native code invocations and COM interop in .NET assemblies.
//!
//! This module provides constants, types, and logic for parsing and representing native type marshalling
//! as defined in ECMA-335 II.23.2.9 and extended by CoreCLR. It supports marshalling for P/Invoke, COM interop,
//! and other native interop scenarios.
//!
//! # Key Components
//! - [`NATIVE_TYPE`] - Constants for all native types used in marshalling
//! - [`MarshalDescriptor`] - Parsed marshalling descriptor for a field or parameter
//!
//! # Example
//! ```rust,no_run
//! use dotscope::metadata::marshalling::NATIVE_TYPE;
//! let native_type = NATIVE_TYPE::LPSTR;
//! ```

use crate::{file::parser::Parser, Error::RecursionLimit, Result};

#[allow(non_snake_case, dead_code, missing_docs)]
/// Native type constants as defined in ECMA-335 II.23.2.9 + `CoreCLR`, some are not mentioned in the standard
/// but still show up in dlls from Microsoft, some are for COM interfacing and not 'native'
///
/// This implementation includes all native types from the `CoreCLR` runtime, including newer
/// `WinRT` types (IINSPECTABLE, HSTRING) and UTF-8 string marshalling (LPUTF8STR).
pub mod NATIVE_TYPE {
    pub const END: u8 = 0x00;
    pub const VOID: u8 = 0x01;
    pub const BOOLEAN: u8 = 0x02;
    pub const I1: u8 = 0x03;
    pub const U1: u8 = 0x04;
    pub const I2: u8 = 0x05;
    pub const U2: u8 = 0x06;
    pub const I4: u8 = 0x07;
    pub const U4: u8 = 0x08;
    pub const I8: u8 = 0x09;
    pub const U8: u8 = 0x0a;
    pub const R4: u8 = 0x0b;
    pub const R8: u8 = 0x0c;
    pub const SYSCHAR: u8 = 0x0d;
    pub const VARIANT: u8 = 0x0e;
    pub const CURRENCY: u8 = 0x0f;
    pub const PTR: u8 = 0x10;
    pub const DECIMAL: u8 = 0x11;
    pub const DATE: u8 = 0x12;
    pub const BSTR: u8 = 0x13;
    pub const LPSTR: u8 = 0x14;
    pub const LPWSTR: u8 = 0x15;
    pub const LPTSTR: u8 = 0x16;
    pub const FIXEDSYSSTRING: u8 = 0x17;
    pub const OBJECTREF: u8 = 0x18;
    pub const IUNKNOWN: u8 = 0x19;
    pub const IDISPATCH: u8 = 0x1a;
    pub const STRUCT: u8 = 0x1b;
    pub const INTF: u8 = 0x1c;
    pub const SAFEARRAY: u8 = 0x1d;
    pub const FIXEDARRAY: u8 = 0x1e;
    pub const INT: u8 = 0x1f;
    pub const UINT: u8 = 0x20;
    pub const NESTEDSTRUCT: u8 = 0x21;
    pub const BYVALSTR: u8 = 0x22;
    pub const ANSIBSTR: u8 = 0x23;
    pub const TBSTR: u8 = 0x24;
    pub const VARIANTBOOL: u8 = 0x25;
    pub const FUNC: u8 = 0x26;
    pub const ASANY: u8 = 0x28;
    pub const ARRAY: u8 = 0x2a;
    pub const LPSTRUCT: u8 = 0x2b;
    pub const CUSTOMMARSHALER: u8 = 0x2c;
    pub const ERROR: u8 = 0x2d;
    pub const IINSPECTABLE: u8 = 0x2e;
    pub const HSTRING: u8 = 0x2f;
    pub const LPUTF8STR: u8 = 0x30;
    pub const MAX: u8 = 0x50;
}

#[allow(non_snake_case, dead_code, missing_docs)]
/// VARTYPE from COM interop
pub mod VARIANT_TYPE {
    pub const EMPTY: u16 = 0;
    pub const NULL: u16 = 1;
    pub const I2: u16 = 2;
    pub const I4: u16 = 3;
    pub const R4: u16 = 4;
    pub const R8: u16 = 5;
    pub const CY: u16 = 6;
    pub const DATE: u16 = 7;
    pub const BSTR: u16 = 8;
    pub const DISPATCH: u16 = 9;
    pub const ERROR: u16 = 10;
    pub const BOOL: u16 = 11;
    pub const VARIANT: u16 = 12;
    pub const UNKNOWN: u16 = 13;
    pub const DECIMAL: u16 = 14;
    pub const I1: u16 = 16;
    pub const UI1: u16 = 17;
    pub const UI2: u16 = 18;
    pub const UI4: u16 = 19;
    pub const I8: u16 = 20;
    pub const UI8: u16 = 21;
    pub const INT: u16 = 22;
    pub const UINT: u16 = 23;
    pub const VOID: u16 = 24;
    pub const HRESULT: u16 = 25;
    pub const PTR: u16 = 26;
    pub const SAFEARRAY: u16 = 27;
    pub const CARRAY: u16 = 28;
    pub const USERDEFINED: u16 = 29;
    pub const LPSTR: u16 = 30;
    pub const LPWSTR: u16 = 31;
    pub const RECORD: u16 = 36;
    pub const INT_PTR: u16 = 37;
    pub const UINT_PTR: u16 = 38;

    pub const FILETIME: u16 = 64;
    pub const BLOB: u16 = 65;
    pub const STREAM: u16 = 66;
    pub const STORAGE: u16 = 67;
    pub const STREAMED_OBJECT: u16 = 68;
    pub const STORED_OBJECT: u16 = 69;
    pub const BLOB_OBJECT: u16 = 70;
    pub const CF: u16 = 71;
    pub const CLSID: u16 = 72;

    pub const VECTOR: u16 = 0x1000;
    pub const ARRAY: u16 = 0x2000;
    pub const BYREF: u16 = 0x4000;
    pub const TYPEMASK: u16 = 0xfff;
}

/// Represents a complete marshaling descriptor
#[derive(Debug, PartialEq, Clone)]
pub struct MarshallingInfo {
    /// The primary type
    pub primary_type: NativeType,
    /// Additional information for more complex types
    pub additional_types: Vec<NativeType>,
}

/// Parses a marshaling descriptor from bytes
///
/// ## Arguments
/// * `data` - The data slice to parse the descriptor from
///
/// # Errors
/// Returns an error if the marshalling descriptor is malformed or cannot be parsed
pub fn parse_marshalling_descriptor(data: &[u8]) -> Result<MarshallingInfo> {
    let mut parser = MarshallingParser::new(data);
    parser.parse_descriptor()
}

#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone)]
/// Represents a native type for marshalling
pub enum NativeType {
    // Basic types
    Void,
    Boolean,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    SysChar,
    Variant,
    Currency,
    Decimal,
    Date,
    Int,
    UInt,
    Error,

    // String types
    BStr,
    LPStr {
        size_param_index: Option<u32>,
    },
    LPWStr {
        size_param_index: Option<u32>,
    },
    LPTStr {
        size_param_index: Option<u32>,
    },
    LPUtf8Str {
        size_param_index: Option<u32>,
    },
    FixedSysString {
        size: u32,
    },
    AnsiBStr,
    TBStr,
    ByValStr {
        size: u32,
    },
    VariantBool,

    // Array types
    FixedArray {
        size: u32,
        element_type: Option<Box<NativeType>>,
    },
    Array {
        element_type: Box<NativeType>,
        num_param: Option<u32>,
        num_element: Option<u32>,
    },
    SafeArray {
        variant_type: u16,
        user_defined_name: Option<String>,
    },

    // Pointer types
    Ptr {
        ref_type: Option<Box<NativeType>>,
    },

    // Interface types
    IUnknown,
    IDispatch,
    IInspectable,
    Interface {
        iid_param_index: Option<u32>,
    },

    // Structured types
    Struct {
        packing_size: Option<u8>,
        class_size: Option<u32>,
    },
    NestedStruct,
    LPStruct,

    // Custom marshaling
    CustomMarshaler {
        guid: String,
        native_type_name: String,
        cookie: String,
        type_reference: String,
    },

    // Special types
    ObjectRef,
    Func,
    AsAny,
    HString,

    // End marker
    End,
}

impl NativeType {
    /// Returns true if this type requires additional parameter data
    #[must_use]
    pub fn has_parameters(&self) -> bool {
        matches!(
            self,
            NativeType::LPStr { .. }
                | NativeType::LPWStr { .. }
                | NativeType::LPTStr { .. }
                | NativeType::LPUtf8Str { .. }
                | NativeType::FixedSysString { .. }
                | NativeType::ByValStr { .. }
                | NativeType::FixedArray { .. }
                | NativeType::Array { .. }
                | NativeType::SafeArray { .. }
                | NativeType::Ptr { .. }
                | NativeType::Interface { .. }
                | NativeType::Struct { .. }
                | NativeType::CustomMarshaler { .. }
        )
    }
}

/// Maximum recursion depth for parsing marshaling descriptors
const MAX_RECURSION_DEPTH: usize = 50;

/// Parser for marshaling descriptors
pub struct MarshallingParser<'a> {
    parser: Parser<'a>,
    depth: usize,
}

impl<'a> MarshallingParser<'a> {
    /// Creates a new parser for the given data
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        MarshallingParser {
            parser: Parser::new(data),
            depth: 0,
        }
    }

    /// Parses a single native type from the current position
    ///
    /// # Errors
    /// Returns an error if the native type cannot be parsed or recursion limit is exceeded
    pub fn parse_native_type(&mut self) -> Result<NativeType> {
        self.depth += 1;
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        let head_byte = self.parser.read_le::<u8>()?;
        match head_byte {
            NATIVE_TYPE::END | NATIVE_TYPE::MAX => Ok(NativeType::End),
            NATIVE_TYPE::VOID => Ok(NativeType::Void),
            NATIVE_TYPE::BOOLEAN => Ok(NativeType::Boolean),
            NATIVE_TYPE::I1 => Ok(NativeType::I1),
            NATIVE_TYPE::U1 => Ok(NativeType::U1),
            NATIVE_TYPE::I2 => Ok(NativeType::I2),
            NATIVE_TYPE::U2 => Ok(NativeType::U2),
            NATIVE_TYPE::I4 => Ok(NativeType::I4),
            NATIVE_TYPE::U4 => Ok(NativeType::U4),
            NATIVE_TYPE::I8 => Ok(NativeType::I8),
            NATIVE_TYPE::U8 => Ok(NativeType::U8),
            NATIVE_TYPE::R4 => Ok(NativeType::R4),
            NATIVE_TYPE::R8 => Ok(NativeType::R8),
            NATIVE_TYPE::SYSCHAR => Ok(NativeType::SysChar),
            NATIVE_TYPE::VARIANT => Ok(NativeType::Variant),
            NATIVE_TYPE::CURRENCY => Ok(NativeType::Currency),
            NATIVE_TYPE::DECIMAL => Ok(NativeType::Decimal),
            NATIVE_TYPE::DATE => Ok(NativeType::Date),
            NATIVE_TYPE::INT => Ok(NativeType::Int),
            NATIVE_TYPE::UINT => Ok(NativeType::UInt),
            NATIVE_TYPE::ERROR => Ok(NativeType::Error),
            NATIVE_TYPE::BSTR => Ok(NativeType::BStr),
            NATIVE_TYPE::LPSTR => {
                let size_param_index = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };
                Ok(NativeType::LPStr { size_param_index })
            }
            NATIVE_TYPE::LPWSTR => {
                let size_param_index = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };
                Ok(NativeType::LPWStr { size_param_index })
            }
            NATIVE_TYPE::LPTSTR => {
                let size_param_index = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };
                Ok(NativeType::LPTStr { size_param_index })
            }
            NATIVE_TYPE::LPUTF8STR => {
                let size_param_index = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };
                Ok(NativeType::LPUtf8Str { size_param_index })
            }
            NATIVE_TYPE::FIXEDSYSSTRING => {
                let size = self.parser.read_compressed_uint()?;
                Ok(NativeType::FixedSysString { size })
            }
            NATIVE_TYPE::OBJECTREF => Ok(NativeType::ObjectRef),
            NATIVE_TYPE::IUNKNOWN => Ok(NativeType::IUnknown),
            NATIVE_TYPE::IDISPATCH => Ok(NativeType::IDispatch),
            NATIVE_TYPE::IINSPECTABLE => Ok(NativeType::IInspectable),
            NATIVE_TYPE::STRUCT => {
                // Optional packing size
                let packing_size = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_le::<u8>()?)
                } else {
                    None
                };
                // Optional class size
                let class_size = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };
                Ok(NativeType::Struct {
                    packing_size,
                    class_size,
                })
            }
            NATIVE_TYPE::INTF => {
                let iid_param_index = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };
                Ok(NativeType::Interface { iid_param_index })
            }
            NATIVE_TYPE::SAFEARRAY => {
                // Optional<Element_Type> -> VT_TYPE; If none, VT_EMPTY
                // Optional<String> -> User defined name/string

                let variant_type = if self.parser.has_more_data() {
                    u16::from(self.parser.read_le::<u8>()?) & VARIANT_TYPE::TYPEMASK
                } else {
                    VARIANT_TYPE::EMPTY
                };

                let user_defined_name = if self.parser.has_more_data() {
                    Some(String::new())
                } else {
                    None
                };

                Ok(NativeType::SafeArray {
                    variant_type,
                    user_defined_name,
                })
            }
            NATIVE_TYPE::FIXEDARRAY => {
                let size = self.parser.read_compressed_uint()?;
                // Optional element type
                let element_type = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(Box::new(self.parse_native_type()?))
                } else {
                    None
                };
                Ok(NativeType::FixedArray { size, element_type })
            }
            NATIVE_TYPE::ARRAY => {
                // ARRAY Type Opt<ParamNumber> Opt<NumElement>
                let array_type = self.parse_native_type()?;

                // Optional ParamNum
                let num_param = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };

                // Optional NumElement
                let num_element = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(self.parser.read_compressed_uint()?)
                } else {
                    None
                };

                Ok(NativeType::Array {
                    element_type: Box::new(array_type),
                    num_param,
                    num_element,
                })
            }
            NATIVE_TYPE::NESTEDSTRUCT => Ok(NativeType::NestedStruct),
            NATIVE_TYPE::BYVALSTR => {
                let size = self.parser.read_compressed_uint()?;
                Ok(NativeType::ByValStr { size })
            }
            NATIVE_TYPE::ANSIBSTR => Ok(NativeType::AnsiBStr),
            NATIVE_TYPE::TBSTR => Ok(NativeType::TBStr),
            NATIVE_TYPE::VARIANTBOOL => Ok(NativeType::VariantBool),
            NATIVE_TYPE::FUNC => Ok(NativeType::Func),
            NATIVE_TYPE::ASANY => Ok(NativeType::AsAny),
            NATIVE_TYPE::LPSTRUCT => Ok(NativeType::LPStruct),
            NATIVE_TYPE::CUSTOMMARSHALER => {
                let guid = self.parser.read_string_utf8()?;
                let native_type_name = self.parser.read_string_utf8()?;
                let cookie = self.parser.read_string_utf8()?;
                let type_reference = self.parser.read_string_utf8()?;

                Ok(NativeType::CustomMarshaler {
                    guid,
                    native_type_name,
                    cookie,
                    type_reference,
                })
            }
            NATIVE_TYPE::HSTRING => Ok(NativeType::HString),
            NATIVE_TYPE::PTR => {
                // Optional referenced type
                let ref_type = if self.parser.has_more_data()
                    && self.parser.peek_byte()? != NATIVE_TYPE::END
                {
                    Some(Box::new(self.parse_native_type()?))
                } else {
                    None
                };
                Ok(NativeType::Ptr { ref_type })
            }
            _ => Err(malformed_error!("Invalid NATIVE_TYPE byte - {}", head_byte)),
        }
    }

    /// Parses a complete marshaling descriptor
    ///
    /// # Errors
    /// Returns an error if the marshalling descriptor is malformed or cannot be parsed
    pub fn parse_descriptor(&mut self) -> Result<MarshallingInfo> {
        let native_type = self.parse_native_type()?;

        let mut descriptor = MarshallingInfo {
            primary_type: native_type,
            additional_types: Vec::new(),
        };

        // Parse additional types if present
        while self.parser.has_more_data() {
            if self.parser.peek_byte()? == NATIVE_TYPE::END {
                self.parser.read_le::<u8>()?; // Consume the end marker
                break;
            }

            let additional_type = self.parse_native_type()?;
            descriptor.additional_types.push(additional_type);
        }

        Ok(descriptor)
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;

    use super::*;

    #[test]
    fn test_parse_simple_types() {
        let test_cases = vec![
            (vec![NATIVE_TYPE::VOID], NativeType::Void),
            (vec![NATIVE_TYPE::BOOLEAN], NativeType::Boolean),
            (vec![NATIVE_TYPE::I1], NativeType::I1),
            (vec![NATIVE_TYPE::U1], NativeType::U1),
            (vec![NATIVE_TYPE::I2], NativeType::I2),
            (vec![NATIVE_TYPE::U2], NativeType::U2),
            (vec![NATIVE_TYPE::I4], NativeType::I4),
            (vec![NATIVE_TYPE::U4], NativeType::U4),
            (vec![NATIVE_TYPE::I8], NativeType::I8),
            (vec![NATIVE_TYPE::U8], NativeType::U8),
            (vec![NATIVE_TYPE::R4], NativeType::R4),
            (vec![NATIVE_TYPE::R8], NativeType::R8),
            (vec![NATIVE_TYPE::INT], NativeType::Int),
            (vec![NATIVE_TYPE::UINT], NativeType::UInt),
            (vec![NATIVE_TYPE::VARIANTBOOL], NativeType::VariantBool),
            (vec![NATIVE_TYPE::IINSPECTABLE], NativeType::IInspectable),
            (vec![NATIVE_TYPE::HSTRING], NativeType::HString),
        ];

        for (input, expected) in test_cases {
            let mut parser = MarshallingParser::new(&input);
            let result = parser.parse_native_type().unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_parse_lpstr() {
        // LPSTR with size parameter
        let input = vec![NATIVE_TYPE::LPSTR, 0x05];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPStr {
                size_param_index: Some(5)
            }
        );

        // LPSTR without size parameter
        let input = vec![NATIVE_TYPE::LPSTR, NATIVE_TYPE::END];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPStr {
                size_param_index: None
            }
        );
    }

    #[test]
    fn test_parse_lputf8str() {
        // LPUTF8STR with size parameter
        let input = vec![NATIVE_TYPE::LPUTF8STR, 0x10];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPUtf8Str {
                size_param_index: Some(16)
            }
        );

        // LPUTF8STR without size parameter
        let input = vec![NATIVE_TYPE::LPUTF8STR, NATIVE_TYPE::END];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPUtf8Str {
                size_param_index: None
            }
        );
    }

    #[test]
    fn test_parse_array() {
        // Array with Type, Opt<num_param>, Opt<num_element>
        let input = vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03, 0x01];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_element: Some(1),
                num_param: Some(3)
            }
        );

        // Array with Type, Opt<num_param>, NONE
        let input = vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_element: None,
                num_param: Some(3)
            }
        );

        // Array with Type, None , None
        let input = vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_element: None,
                num_param: None
            }
        );
    }

    #[test]
    fn test_parse_fixed_array() {
        // Fixed array with size and element type
        let input = vec![NATIVE_TYPE::FIXEDARRAY, 0x0A, NATIVE_TYPE::I4];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::FixedArray {
                size: 10,
                element_type: Some(Box::new(NativeType::I4))
            }
        );

        // Fixed array with size but no element type
        let input = vec![NATIVE_TYPE::FIXEDARRAY, 0x0A, NATIVE_TYPE::END];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::FixedArray {
                size: 10,
                element_type: None
            }
        );
    }

    #[test]
    fn test_parse_complete_descriptor() {
        // Simple descriptor with just one type
        let input = vec![NATIVE_TYPE::I4, NATIVE_TYPE::END];
        let descriptor = parse_marshalling_descriptor(&input).unwrap();
        assert_eq!(descriptor.primary_type, NativeType::I4);
        assert_eq!(descriptor.additional_types.len(), 0);

        // Descriptor with primary type and additional types
        let input = vec![
            NATIVE_TYPE::LPSTR,
            0x01,                 // LPSTR with size param 1
            NATIVE_TYPE::BOOLEAN, // Additional type Boolean
            NATIVE_TYPE::END,     // End marker
        ];
        let descriptor = parse_marshalling_descriptor(&input).unwrap();
        assert_eq!(
            descriptor.primary_type,
            NativeType::LPStr {
                size_param_index: Some(1)
            }
        );
        assert_eq!(descriptor.additional_types.len(), 1);
        assert_eq!(descriptor.additional_types[0], NativeType::Boolean);

        // Descriptor with only END marker
        let input = vec![NATIVE_TYPE::END];
        let descriptor = parse_marshalling_descriptor(&input).unwrap();
        assert_eq!(descriptor.primary_type, NativeType::End);
        assert_eq!(descriptor.additional_types.len(), 0);
    }

    #[test]
    fn test_error_conditions() {
        // Test unexpected end of data
        let input: Vec<u8> = vec![];
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::OutOfBounds));

        // Test unknown native type
        let input = vec![0xFF];
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());

        // Test invalid compressed integer
        let input = vec![NATIVE_TYPE::LPSTR, 0xC0]; // 4-byte format but only one byte available
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::OutOfBounds));
    }

    #[test]
    fn test_parse_struct() {
        // Struct with packing size and class size
        let input = vec![NATIVE_TYPE::STRUCT, 0x04, 0x20, NATIVE_TYPE::END];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Struct {
                packing_size: Some(4),
                class_size: Some(32)
            }
        );

        // Struct with packing size but no class size
        let input = vec![NATIVE_TYPE::STRUCT, 0x04, NATIVE_TYPE::END];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Struct {
                packing_size: Some(4),
                class_size: None
            }
        );

        // Struct with no packing size or class size
        let input = vec![NATIVE_TYPE::STRUCT, NATIVE_TYPE::END];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Struct {
                packing_size: None,
                class_size: None
            }
        );
    }

    #[test]
    fn test_parse_custom_marshaler() {
        // CustomMarshaler with GUID, native type name, cookie, and type reference
        let input = vec![
            NATIVE_TYPE::CUSTOMMARSHALER,
            // GUID
            0x41,
            0x42,
            0x43,
            0x44,
            0x00,
            // Native type name
            0x4E,
            0x61,
            0x74,
            0x69,
            0x76,
            0x65,
            0x00,
            // Cookie
            0x43,
            0x6F,
            0x6F,
            0x6B,
            0x69,
            0x65,
            0x00,
            // Type reference
            0x54,
            0x79,
            0x70,
            0x65,
            0x00,
        ];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::CustomMarshaler {
                guid: "ABCD".to_string(),
                native_type_name: "Native".to_string(),
                cookie: "Cookie".to_string(),
                type_reference: "Type".to_string(),
            }
        );
    }
}
