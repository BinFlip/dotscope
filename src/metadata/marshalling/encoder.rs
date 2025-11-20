//! Encoder for .NET marshalling descriptors.
//!
//! This module provides encoding functionality for converting structured `MarshallingInfo` and
//! `NativeType` representations into binary marshalling descriptors as defined in ECMA-335 II.23.2.9.

use crate::{
    metadata::marshalling::types::{
        MarshallingInfo, NativeType, MAX_RECURSION_DEPTH, NATIVE_TYPE, VARIANT_TYPE,
    },
    utils::write_compressed_uint,
    Error::RecursionLimit,
    Result,
};

/// Encodes a marshaling descriptor to bytes.
///
/// This is a convenience function that creates a [`MarshallingEncoder`] and encodes a complete
/// marshalling descriptor to a byte vector. The function handles the full encoding process
/// including primary type encoding, parameter encoding, and additional type processing.
///
/// # Arguments
///
/// * `info` - The marshalling descriptor to encode. This includes the primary native type
///   and any additional types required for complex marshalling scenarios.
///
/// # Returns
///
/// * [`Ok`]([`Vec<u8>`]) - Successfully encoded marshalling descriptor as bytes
/// * [`Err`]([`crate::Error`]) - Encoding failed due to unsupported types or invalid data
///
/// # Errors
///
/// This function returns an error in the following cases:
/// - **Unsupported Type**: Attempt to encode an unsupported or invalid native type
/// - **Invalid Parameters**: Type parameters are inconsistent or out of range
/// - **Recursion Limit**: Nested types exceed the maximum recursion depth for safety
/// - **String Encoding**: Issues encoding UTF-8 strings for custom marshalers
///
/// # Examples
///
/// ## Simple Type Encoding
/// ```rust,ignore
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo};
///
/// // Encode a simple boolean type
/// let info = MarshallingInfo {
///     primary_type: NativeType::Boolean,
///     additional_types: vec![],
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// assert_eq!(bytes, vec![NATIVE_TYPE::BOOLEAN]);
/// ```
///
/// ## String Type with Parameters
/// ```rust,ignore
/// // Encode LPSTR with size parameter index 5
/// let info = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: Some(5) },
///     additional_types: vec![],
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// assert_eq!(bytes, vec![NATIVE_TYPE::LPSTR, 0x05]);
/// ```
///
/// ## Complex Array Type
/// ```rust,ignore
/// // Encode array of I4 with parameter and size info
/// let info = MarshallingInfo {
///     primary_type: NativeType::Array {
///         element_type: Box::new(NativeType::I4),
///         num_param: Some(3),
///         num_element: Some(10),
///     },
///     additional_types: vec![],
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// // Result will be [NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03, 0x0A]
/// ```
///
pub fn encode_marshalling_descriptor(info: &MarshallingInfo) -> Result<Vec<u8>> {
    let mut encoder = MarshallingEncoder::new();
    encoder.encode_descriptor(info)
}

/// Encoder for marshaling descriptors.
///
/// The `MarshallingEncoder` provides stateful encoding of marshalling descriptors from
/// `MarshallingInfo` structures to binary format as defined in ECMA-335 II.23.2.9.
/// It maintains recursion depth tracking to safely encode complex nested type structures.
///
/// # Design
///
/// The encoder converts `NativeType` enum variants to their binary representation with:
/// - **Type Constants**: Maps enum variants to NATIVE_TYPE byte constants
/// - **Parameter Encoding**: Handles size, index, and other type-specific parameters
/// - **Recursion Control**: Prevents stack overflow from deeply nested types
/// - **Binary Format**: Produces ECMA-335 compliant binary descriptors
///
/// # Usage Pattern
///
/// ```rust,ignore
/// use dotscope::metadata::marshalling::{MarshallingEncoder, NativeType, MarshallingInfo};
///
/// let info = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: Some(5) },
///     additional_types: vec![],
/// };
///
/// let mut encoder = MarshallingEncoder::new();
/// let bytes = encoder.encode_descriptor(&info)?;
/// // Result: [NATIVE_TYPE::LPSTR, 0x05]
/// ```
///
/// # Safety
///
/// The encoder includes several safety mechanisms:
/// - **Recursion Limits**: Prevents stack overflow from nested types
/// - **Parameter Validation**: Ensures parameters are within valid ranges
/// - **Format Compliance**: Produces only valid binary descriptors
/// - **Type Validation**: Ensures all types can be properly encoded
///
pub struct MarshallingEncoder {
    /// Buffer for building the encoded descriptor
    buffer: Vec<u8>,
    /// Current recursion depth for stack overflow prevention
    depth: usize,
}

impl MarshallingEncoder {
    /// Creates a new encoder.
    ///
    /// Initializes a fresh encoder state with zero recursion depth and an empty buffer.
    ///
    /// # Returns
    ///
    /// A new [`MarshallingEncoder`] ready to encode marshalling descriptors.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::marshalling::MarshallingEncoder;
    ///
    /// let mut encoder = MarshallingEncoder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        MarshallingEncoder {
            buffer: Vec::new(),
            depth: 0,
        }
    }

    /// Encodes a single native type to the buffer
    ///
    /// # Errors
    /// Returns an error if the native type cannot be encoded or recursion limit is exceeded
    pub fn encode_native_type(&mut self, native_type: &NativeType) -> Result<()> {
        self.depth += 1;
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        match native_type {
            NativeType::End => self.buffer.push(NATIVE_TYPE::END),
            NativeType::Void => self.buffer.push(NATIVE_TYPE::VOID),
            NativeType::Boolean => self.buffer.push(NATIVE_TYPE::BOOLEAN),
            NativeType::I1 => self.buffer.push(NATIVE_TYPE::I1),
            NativeType::U1 => self.buffer.push(NATIVE_TYPE::U1),
            NativeType::I2 => self.buffer.push(NATIVE_TYPE::I2),
            NativeType::U2 => self.buffer.push(NATIVE_TYPE::U2),
            NativeType::I4 => self.buffer.push(NATIVE_TYPE::I4),
            NativeType::U4 => self.buffer.push(NATIVE_TYPE::U4),
            NativeType::I8 => self.buffer.push(NATIVE_TYPE::I8),
            NativeType::U8 => self.buffer.push(NATIVE_TYPE::U8),
            NativeType::R4 => self.buffer.push(NATIVE_TYPE::R4),
            NativeType::R8 => self.buffer.push(NATIVE_TYPE::R8),
            NativeType::SysChar => self.buffer.push(NATIVE_TYPE::SYSCHAR),
            NativeType::Variant => self.buffer.push(NATIVE_TYPE::VARIANT),
            NativeType::Currency => self.buffer.push(NATIVE_TYPE::CURRENCY),
            NativeType::Decimal => self.buffer.push(NATIVE_TYPE::DECIMAL),
            NativeType::Date => self.buffer.push(NATIVE_TYPE::DATE),
            NativeType::Int => self.buffer.push(NATIVE_TYPE::INT),
            NativeType::UInt => self.buffer.push(NATIVE_TYPE::UINT),
            NativeType::Error => self.buffer.push(NATIVE_TYPE::ERROR),
            NativeType::BStr => self.buffer.push(NATIVE_TYPE::BSTR),
            NativeType::LPStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPSTR);
                if let Some(size) = size_param_index {
                    write_compressed_uint(*size, &mut self.buffer);
                }
            }
            NativeType::LPWStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPWSTR);
                if let Some(size) = size_param_index {
                    write_compressed_uint(*size, &mut self.buffer);
                }
            }
            NativeType::LPTStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPTSTR);
                if let Some(size) = size_param_index {
                    write_compressed_uint(*size, &mut self.buffer);
                }
            }
            NativeType::LPUtf8Str { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPUTF8STR);
                if let Some(size) = size_param_index {
                    write_compressed_uint(*size, &mut self.buffer);
                }
            }
            NativeType::FixedSysString { size } => {
                self.buffer.push(NATIVE_TYPE::FIXEDSYSSTRING);
                write_compressed_uint(*size, &mut self.buffer);
            }
            NativeType::ObjectRef => self.buffer.push(NATIVE_TYPE::OBJECTREF),
            NativeType::IUnknown => self.buffer.push(NATIVE_TYPE::IUNKNOWN),
            NativeType::IDispatch => self.buffer.push(NATIVE_TYPE::IDISPATCH),
            NativeType::IInspectable => self.buffer.push(NATIVE_TYPE::IINSPECTABLE),
            NativeType::Struct {
                packing_size,
                class_size,
            } => {
                self.buffer.push(NATIVE_TYPE::STRUCT);
                if let Some(packing) = packing_size {
                    self.buffer.push(*packing);
                }
                if let Some(size) = class_size {
                    write_compressed_uint(*size, &mut self.buffer);
                }
            }
            NativeType::Interface { iid_param_index } => {
                self.buffer.push(NATIVE_TYPE::INTERFACE);
                if let Some(iid) = iid_param_index {
                    write_compressed_uint(*iid, &mut self.buffer);
                }
            }
            NativeType::SafeArray {
                variant_type,
                user_defined_name,
            } => {
                self.buffer.push(NATIVE_TYPE::SAFEARRAY);

                // Always encode variant type if we have a user-defined name, even if EMPTY
                // This helps with parsing disambiguation
                if user_defined_name.is_some() || *variant_type != VARIANT_TYPE::EMPTY {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        self.buffer
                            .push((*variant_type & VARIANT_TYPE::TYPEMASK) as u8);
                    }
                }

                if let Some(user_defined_name) = user_defined_name {
                    self.buffer.extend_from_slice(user_defined_name.as_bytes());
                    self.buffer.push(0);
                }
            }
            NativeType::FixedArray { size, element_type } => {
                self.buffer.push(NATIVE_TYPE::FIXEDARRAY);
                write_compressed_uint(*size, &mut self.buffer);
                if let Some(elem_type) = element_type {
                    self.encode_native_type(elem_type)?;
                }
            }
            NativeType::Array {
                element_type,
                num_param,
                num_element,
            } => {
                self.buffer.push(NATIVE_TYPE::ARRAY);
                self.encode_native_type(element_type)?;
                if let Some(param) = num_param {
                    write_compressed_uint(*param, &mut self.buffer);
                }
                if let Some(element) = num_element {
                    write_compressed_uint(*element, &mut self.buffer);
                }
            }
            NativeType::NestedStruct => self.buffer.push(NATIVE_TYPE::NESTEDSTRUCT),
            NativeType::ByValStr { size } => {
                self.buffer.push(NATIVE_TYPE::BYVALSTR);
                write_compressed_uint(*size, &mut self.buffer);
            }
            NativeType::AnsiBStr => self.buffer.push(NATIVE_TYPE::ANSIBSTR),
            NativeType::TBStr => self.buffer.push(NATIVE_TYPE::TBSTR),
            NativeType::VariantBool => self.buffer.push(NATIVE_TYPE::VARIANTBOOL),
            NativeType::Func => self.buffer.push(NATIVE_TYPE::FUNC),
            NativeType::AsAny => self.buffer.push(NATIVE_TYPE::ASANY),
            NativeType::LPStruct => self.buffer.push(NATIVE_TYPE::LPSTRUCT),
            NativeType::CustomMarshaler {
                guid,
                native_type_name,
                cookie,
                type_reference,
            } => {
                self.buffer.push(NATIVE_TYPE::CUSTOMMARSHALER);
                // Encode the four strings as null-terminated UTF-8
                self.buffer.extend_from_slice(guid.as_bytes());
                self.buffer.push(0);
                self.buffer.extend_from_slice(native_type_name.as_bytes());
                self.buffer.push(0);
                self.buffer.extend_from_slice(cookie.as_bytes());
                self.buffer.push(0);
                self.buffer.extend_from_slice(type_reference.as_bytes());
                self.buffer.push(0);
            }
            NativeType::HString => self.buffer.push(NATIVE_TYPE::HSTRING),
            NativeType::Ptr { ref_type } => {
                self.buffer.push(NATIVE_TYPE::PTR);
                if let Some(ref_type) = ref_type {
                    self.encode_native_type(ref_type)?;
                }
            }
        }

        self.depth -= 1;
        Ok(())
    }

    /// Encodes a complete marshaling descriptor
    ///
    /// # Errors
    /// Returns an error if the marshalling descriptor is malformed or cannot be encoded
    pub fn encode_descriptor(&mut self, info: &MarshallingInfo) -> Result<Vec<u8>> {
        self.buffer.clear();
        self.depth = 0;

        self.encode_native_type(&info.primary_type)?;

        for additional_type in &info.additional_types {
            self.encode_native_type(additional_type)?;
        }

        if !info.additional_types.is_empty() {
            self.buffer.push(NATIVE_TYPE::END);
        }

        Ok(self.buffer.clone())
    }
}

impl Default for MarshallingEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::marshalling::parse_marshalling_descriptor;

    #[test]
    fn test_roundtrip_simple_types() {
        let test_cases = vec![
            NativeType::Void,
            NativeType::Boolean,
            NativeType::I1,
            NativeType::U1,
            NativeType::I2,
            NativeType::U2,
            NativeType::I4,
            NativeType::U4,
            NativeType::I8,
            NativeType::U8,
            NativeType::R4,
            NativeType::R8,
            NativeType::Int,
            NativeType::UInt,
            NativeType::VariantBool,
            NativeType::IInspectable,
            NativeType::HString,
            NativeType::BStr,
            NativeType::AnsiBStr,
            NativeType::TBStr,
            NativeType::IUnknown,
            NativeType::IDispatch,
            NativeType::NestedStruct,
            NativeType::LPStruct,
            NativeType::ObjectRef,
            NativeType::Func,
            NativeType::AsAny,
            NativeType::SysChar,
            NativeType::Variant,
            NativeType::Currency,
            NativeType::Decimal,
            NativeType::Date,
            NativeType::Error,
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_string_types_with_parameters() {
        let test_cases = vec![
            NativeType::LPStr {
                size_param_index: None,
            },
            NativeType::LPStr {
                size_param_index: Some(5),
            },
            NativeType::LPWStr {
                size_param_index: None,
            },
            NativeType::LPWStr {
                size_param_index: Some(10),
            },
            NativeType::LPTStr {
                size_param_index: None,
            },
            NativeType::LPTStr {
                size_param_index: Some(3),
            },
            NativeType::LPUtf8Str {
                size_param_index: None,
            },
            NativeType::LPUtf8Str {
                size_param_index: Some(16),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_fixed_types_with_size() {
        let test_cases = vec![
            NativeType::FixedSysString { size: 32 },
            NativeType::FixedSysString { size: 128 },
            NativeType::ByValStr { size: 64 },
            NativeType::ByValStr { size: 256 },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_struct_types() {
        let test_cases = vec![
            NativeType::Struct {
                packing_size: None,
                class_size: None,
            },
            NativeType::Struct {
                packing_size: Some(4),
                class_size: None,
            },
            NativeType::Struct {
                packing_size: Some(8),
                class_size: Some(128),
            },
            NativeType::Struct {
                packing_size: Some(1),
                class_size: Some(64),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_interface_types() {
        let test_cases = vec![
            NativeType::Interface {
                iid_param_index: None,
            },
            NativeType::Interface {
                iid_param_index: Some(1),
            },
            NativeType::Interface {
                iid_param_index: Some(5),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_safe_array_encoding_debug() {
        // Test parsing a simple case first
        let simple_case = NativeType::SafeArray {
            variant_type: VARIANT_TYPE::I4,
            user_defined_name: None,
        };

        let info = MarshallingInfo {
            primary_type: simple_case.clone(),
            additional_types: vec![],
        };

        let encoded = encode_marshalling_descriptor(&info).unwrap();
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();
        assert_eq!(parsed.primary_type, simple_case);

        // Now test the complex case with user-defined name
        let complex_case = NativeType::SafeArray {
            variant_type: VARIANT_TYPE::EMPTY,
            user_defined_name: Some("CustomStruct".to_string()),
        };

        let info = MarshallingInfo {
            primary_type: complex_case.clone(),
            additional_types: vec![],
        };

        let encoded = encode_marshalling_descriptor(&info).unwrap();
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();
        assert_eq!(parsed.primary_type, complex_case);
    }

    #[test]
    fn test_roundtrip_safe_array_types() {
        let test_cases = vec![
            // SafeArray with no variant type and no user-defined name
            NativeType::SafeArray {
                variant_type: VARIANT_TYPE::EMPTY,
                user_defined_name: None,
            },
            // SafeArray with variant type but no user-defined name
            NativeType::SafeArray {
                variant_type: VARIANT_TYPE::I4,
                user_defined_name: None,
            },
            NativeType::SafeArray {
                variant_type: VARIANT_TYPE::BSTR,
                user_defined_name: None,
            },
            // SafeArray with both variant type and user-defined name
            NativeType::SafeArray {
                variant_type: VARIANT_TYPE::I4,
                user_defined_name: Some("MyCustomType".to_string()),
            },
            NativeType::SafeArray {
                variant_type: VARIANT_TYPE::BSTR,
                user_defined_name: Some("System.String".to_string()),
            },
            // SafeArray with only user-defined name (no variant type)
            NativeType::SafeArray {
                variant_type: VARIANT_TYPE::EMPTY,
                user_defined_name: Some("CustomStruct".to_string()),
            },
        ];

        for (i, original_type) in test_cases.into_iter().enumerate() {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify - Now we can do full verification
            assert_eq!(parsed.primary_type, original_type, "Test case {i} failed");
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_fixed_array_types() {
        let test_cases = vec![
            NativeType::FixedArray {
                size: 10,
                element_type: None,
            },
            NativeType::FixedArray {
                size: 32,
                element_type: Some(Box::new(NativeType::I4)),
            },
            NativeType::FixedArray {
                size: 64,
                element_type: Some(Box::new(NativeType::Boolean)),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_variable_array_types() {
        let test_cases = vec![
            NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_param: None,
                num_element: None,
            },
            NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_param: Some(3),
                num_element: None,
            },
            NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_param: Some(3),
                num_element: Some(10),
            },
            NativeType::Array {
                element_type: Box::new(NativeType::Boolean),
                num_param: Some(5),
                num_element: None,
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_pointer_types() {
        let test_cases = vec![
            NativeType::Ptr { ref_type: None },
            NativeType::Ptr {
                ref_type: Some(Box::new(NativeType::I4)),
            },
            NativeType::Ptr {
                ref_type: Some(Box::new(NativeType::Void)),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
                additional_types: vec![],
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
            assert_eq!(parsed.additional_types.len(), 0);
        }
    }

    #[test]
    fn test_roundtrip_custom_marshaler() {
        let original_type = NativeType::CustomMarshaler {
            guid: "ABCD1234-5678-90EF".to_string(),
            native_type_name: "MyNativeType".to_string(),
            cookie: "cookie_data".to_string(),
            type_reference: "MyAssembly.MyMarshaler".to_string(),
        };

        let info = MarshallingInfo {
            primary_type: original_type.clone(),
            additional_types: vec![],
        };

        // Encode
        let encoded = encode_marshalling_descriptor(&info).unwrap();

        // Parse back
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();

        // Verify
        assert_eq!(parsed.primary_type, original_type);
        assert_eq!(parsed.additional_types.len(), 0);
    }

    #[test]
    fn test_roundtrip_complex_nested_types() {
        // Test nested pointer to array
        let complex_type = NativeType::Ptr {
            ref_type: Some(Box::new(NativeType::Array {
                element_type: Box::new(NativeType::LPWStr {
                    size_param_index: Some(5),
                }),
                num_param: Some(2),
                num_element: Some(10),
            })),
        };

        let info = MarshallingInfo {
            primary_type: complex_type.clone(),
            additional_types: vec![],
        };

        // Encode
        let encoded = encode_marshalling_descriptor(&info).unwrap();

        // Parse back
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();

        // Verify
        assert_eq!(parsed.primary_type, complex_type);
        assert_eq!(parsed.additional_types.len(), 0);
    }

    #[test]
    fn test_roundtrip_descriptors_with_additional_types() {
        let info = MarshallingInfo {
            primary_type: NativeType::LPStr {
                size_param_index: Some(1),
            },
            additional_types: vec![NativeType::Boolean, NativeType::I4],
        };

        // Encode
        let encoded = encode_marshalling_descriptor(&info).unwrap();

        // Parse back
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();

        // Verify
        assert_eq!(parsed.primary_type, info.primary_type);
        assert_eq!(parsed.additional_types.len(), 2);
        assert_eq!(parsed.additional_types[0], NativeType::Boolean);
        assert_eq!(parsed.additional_types[1], NativeType::I4);
    }

    #[test]
    fn test_roundtrip_comprehensive_scenarios() {
        // Test realistic P/Invoke scenarios
        let pinvoke_scenarios = vec![
            // Win32 API: BOOL CreateDirectory(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
            MarshallingInfo {
                primary_type: NativeType::I4, // BOOL return
                additional_types: vec![],
            },
            // Parameter 1: LPCWSTR
            MarshallingInfo {
                primary_type: NativeType::LPWStr {
                    size_param_index: None,
                },
                additional_types: vec![],
            },
            // Parameter 2: LPSECURITY_ATTRIBUTES
            MarshallingInfo {
                primary_type: NativeType::Ptr {
                    ref_type: Some(Box::new(NativeType::Struct {
                        packing_size: None,
                        class_size: None,
                    })),
                },
                additional_types: vec![],
            },
        ];

        for scenario in pinvoke_scenarios {
            // Encode
            let encoded = encode_marshalling_descriptor(&scenario).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, scenario.primary_type);
            assert_eq!(
                parsed.additional_types.len(),
                scenario.additional_types.len()
            );
            for (i, expected) in scenario.additional_types.iter().enumerate() {
                assert_eq!(parsed.additional_types[i], *expected);
            }
        }
    }
}
