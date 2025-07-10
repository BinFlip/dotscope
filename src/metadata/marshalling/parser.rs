//! Parser for .NET marshalling descriptors.
//!
//! This module provides parsing functionality for binary marshalling descriptors as defined
//! in ECMA-335 II.23.2.9. It converts raw byte data into structured `MarshallingInfo` and
//! `NativeType` representations.

use crate::{
    file::parser::Parser,
    metadata::marshalling::types::{
        MarshallingInfo, NativeType, MAX_RECURSION_DEPTH, NATIVE_TYPE, VARIANT_TYPE,
    },
    Error::RecursionLimit,
    Result,
};

/// Parses a marshaling descriptor from bytes.
///
/// This is a convenience function that creates a [`MarshallingParser`] and parses a complete
/// marshalling descriptor from the provided byte slice. The function handles the full parsing
/// process including primary type extraction, parameter parsing, and additional type processing.
///
/// # Arguments
///
/// * `data` - The byte slice containing the marshalling descriptor to parse. The format follows
///   ECMA-335 II.23.2.9 with the first byte(s) indicating the native type followed by optional
///   type-specific parameters.
///
/// # Returns
///
/// * [`Ok`]([`MarshallingInfo`]) - Successfully parsed marshalling descriptor
/// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data, unsupported types, or I/O errors
///
/// # Errors
///
/// This function returns an error in the following cases:
/// - **Invalid Format**: Malformed or truncated marshalling descriptor
/// - **Unknown Type**: Unrecognized native type constant
/// - **Recursion Limit**: Nested types exceed the maximum recursion depth for safety
/// - **Data Corruption**: Inconsistent or invalid parameter data
///
/// # Examples
///
/// ## Simple Type Parsing
/// ```rust,ignore
/// use dotscope::metadata::marshalling::{parse_marshalling_descriptor, NATIVE_TYPE};
///
/// // Parse a simple boolean type
/// let bytes = &[NATIVE_TYPE::BOOLEAN];
/// let info = parse_marshalling_descriptor(bytes)?;
/// assert_eq!(info.primary_type, NativeType::Boolean);
/// ```
///
/// ## String Type with Parameters
/// ```rust,ignore
/// // Parse LPSTR with size parameter index 5
/// let bytes = &[NATIVE_TYPE::LPSTR, 0x05];
/// let info = parse_marshalling_descriptor(bytes)?;
///
/// match info.primary_type {
///     NativeType::LPStr { size_param_index: Some(5) } => {
///         println!("LPSTR with size from parameter 5");
///     }
///     _ => unreachable!(),
/// }
/// ```
///
/// ## Complex Array Type
/// ```rust,ignore
/// // Parse array of I4 with parameter and size info
/// let bytes = &[NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03, 0x0A];
/// let info = parse_marshalling_descriptor(bytes)?;
///
/// match info.primary_type {
///     NativeType::Array { element_type, num_param, num_element } => {
///         println!("Array of {:?}, param: {:?}, size: {:?}",
///                  element_type, num_param, num_element);
///     }
///     _ => unreachable!(),
/// }
/// ```
///
pub fn parse_marshalling_descriptor(data: &[u8]) -> Result<MarshallingInfo> {
    let mut parser = MarshallingParser::new(data);
    parser.parse_descriptor()
}

/// Parser for marshaling descriptors.
///
/// The `MarshallingParser` provides stateful parsing of binary marshalling descriptors as defined
/// in ECMA-335 II.23.2.9. It maintains position state and recursion depth tracking to safely
/// parse complex nested type structures.
///
/// # Design
///
/// The parser is built on top of [`crate::file::parser::Parser`] for low-level byte operations
/// and adds marshalling-specific logic for:
/// - **Type Recognition**: Identifying native type constants and their formats
/// - **Parameter Parsing**: Extracting size, index, and other type-specific parameters
/// - **Recursion Control**: Preventing stack overflow from deeply nested types
/// - **Validation**: Ensuring descriptor format compliance and data integrity
///
/// # Usage Pattern
///
/// ```rust,ignore
/// use dotscope::metadata::marshalling::MarshallingParser;
///
/// let descriptor_bytes = &[/* marshalling descriptor data */];
/// let mut parser = MarshallingParser::new(descriptor_bytes);
///
/// // Parse individual types
/// let native_type = parser.parse_native_type()?;
///
/// // Or parse complete descriptor
/// let descriptor = parser.parse_descriptor()?;
/// ```
///
/// # Safety
///
/// The parser includes several safety mechanisms:
/// - **Recursion Limits**: Prevents stack overflow from nested types
/// - **Bounds Checking**: Validates all memory accesses
/// - **Format Validation**: Rejects malformed descriptors
/// - **Type Validation**: Ensures only valid native type constants
///
///
pub struct MarshallingParser<'a> {
    /// Underlying byte parser for low-level operations
    parser: Parser<'a>,
    /// Current recursion depth for stack overflow prevention
    depth: usize,
}

impl<'a> MarshallingParser<'a> {
    /// Creates a new parser for the given data.
    ///
    /// Initializes a fresh parser state with zero recursion depth and positions
    /// the parser at the beginning of the provided data slice.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the marshalling descriptor to parse
    ///
    /// # Returns
    ///
    /// A new [`MarshallingParser`] ready to parse the provided data.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::marshalling::MarshallingParser;
    ///
    /// let descriptor_bytes = &[0x14, 0x05]; // LPSTR with size param 5
    /// let mut parser = MarshallingParser::new(descriptor_bytes);
    /// let native_type = parser.parse_native_type()?;
    /// ```
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
            NATIVE_TYPE::INTERFACE => {
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

                let mut variant_type = VARIANT_TYPE::EMPTY;
                let mut user_defined_name = None;

                // Always try to read variant type if there's more data
                // The variant type can be 0 (EMPTY), which is different from END marker context
                if self.parser.has_more_data() {
                    variant_type = u16::from(self.parser.read_le::<u8>()?) & VARIANT_TYPE::TYPEMASK;

                    // Check if there's more data for a string
                    // Only skip reading if we hit an explicit END marker
                    if self.parser.has_more_data() && self.parser.peek_byte()? != NATIVE_TYPE::END {
                        user_defined_name = Some(self.parser.read_string_utf8()?);
                    }
                }

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
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));

        // Test unknown native type
        let input = vec![0xFF];
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());

        // Test invalid compressed integer
        let input = vec![NATIVE_TYPE::LPSTR, 0xC0]; // 4-byte format but only one byte available
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));
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
