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
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo, NATIVE_TYPE};
///
/// // Encode a simple boolean type
/// let info = MarshallingInfo {
///     primary_type: NativeType::Boolean,
///     additional_types: vec![],
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// assert_eq!(bytes, vec![NATIVE_TYPE::BOOLEAN]);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## String Type with Parameters
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo, NATIVE_TYPE};
///
/// // Encode LPSTR with size parameter index 5
/// let info = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: Some(5) },
///     additional_types: vec![],
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// assert_eq!(bytes, vec![NATIVE_TYPE::LPSTR, 0x05]);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Complex Array Type
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo};
///
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
/// # Ok::<(), dotscope::Error>(())
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
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{MarshallingEncoder, NativeType, MarshallingInfo};
///
/// let info = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: Some(5) },
///     additional_types: vec![],
/// };
///
/// let mut encoder = MarshallingEncoder::new();
/// let bytes = encoder.encode_descriptor(&info)?;
/// # Ok::<(), dotscope::Error>(())
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
    /// ```rust,no_run
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

    /// Writes an optional compressed uint to the buffer if value is Some.
    ///
    /// This helper method reduces code duplication for writing optional
    /// size parameters, indices, and counts.
    fn write_optional_compressed_uint(&mut self, value: Option<u32>) {
        if let Some(v) = value {
            write_compressed_uint(v, &mut self.buffer);
        }
    }

    /// Encodes a single native type to the internal buffer.
    ///
    /// This method encodes a single `NativeType` variant to its binary representation
    /// according to ECMA-335 II.23.2.9. For nested types (arrays, pointers), this method
    /// is called recursively with depth tracking to prevent stack overflow.
    ///
    /// # Arguments
    ///
    /// * `native_type` - The native type to encode
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The recursion depth exceeds [`MAX_RECURSION_DEPTH`]
    /// - A nested type fails to encode
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
                self.write_optional_compressed_uint(*size_param_index);
            }
            NativeType::LPWStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPWSTR);
                self.write_optional_compressed_uint(*size_param_index);
            }
            NativeType::LPTStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPTSTR);
                self.write_optional_compressed_uint(*size_param_index);
            }
            NativeType::LPUtf8Str { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPUTF8STR);
                self.write_optional_compressed_uint(*size_param_index);
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
                self.write_optional_compressed_uint(*class_size);
            }
            NativeType::Interface { iid_param_index } => {
                self.buffer.push(NATIVE_TYPE::INTERFACE);
                self.write_optional_compressed_uint(*iid_param_index);
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
                self.write_optional_compressed_uint(*num_param);
                self.write_optional_compressed_uint(*num_element);
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

    /// Encodes a complete marshaling descriptor to a new byte vector.
    ///
    /// This method encodes the primary type and any additional types from the
    /// `MarshallingInfo` structure into a binary marshalling descriptor. The descriptor
    /// is validated before encoding to catch invalid type combinations early.
    ///
    /// # Arguments
    ///
    /// * `info` - The marshalling descriptor containing the primary type and optional
    ///   additional types to encode
    ///
    /// # Returns
    ///
    /// A new `Vec<u8>` containing the encoded marshalling descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The marshalling descriptor fails validation (invalid type combinations)
    /// - A type cannot be encoded
    /// - The recursion depth exceeds [`MAX_RECURSION_DEPTH`]
    pub fn encode_descriptor(&mut self, info: &MarshallingInfo) -> Result<Vec<u8>> {
        info.validate()?;

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

    /// Encodes a marshaling descriptor into the provided output buffer.
    ///
    /// This is an optimization method for high-frequency encoding scenarios where
    /// buffer reuse is important. Instead of allocating a new `Vec<u8>`, this method
    /// appends the encoded data to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `info` - The marshalling descriptor to encode
    /// * `output` - The buffer to append encoded data to
    ///
    /// # Errors
    ///
    /// Returns an error if the marshalling descriptor is invalid or cannot be encoded.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::marshalling::{MarshallingEncoder, MarshallingInfo, NativeType};
    ///
    /// let mut encoder = MarshallingEncoder::new();
    /// let mut buffer = Vec::with_capacity(1024);
    ///
    /// let info = MarshallingInfo {
    ///     primary_type: NativeType::I4,
    ///     additional_types: vec![],
    /// };
    ///
    /// encoder.encode_descriptor_into(&info, &mut buffer)?;
    /// // buffer now contains the encoded marshalling descriptor
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode_descriptor_into(
        &mut self,
        info: &MarshallingInfo,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        info.validate()?;

        self.buffer.clear();
        self.depth = 0;

        self.encode_native_type(&info.primary_type)?;

        for additional_type in &info.additional_types {
            self.encode_native_type(additional_type)?;
        }

        if !info.additional_types.is_empty() {
            self.buffer.push(NATIVE_TYPE::END);
        }

        output.extend_from_slice(&self.buffer);
        Ok(())
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

    #[test]
    fn test_validation_struct_class_size_without_packing() {
        // Invalid: class_size without packing_size
        let invalid = MarshallingInfo {
            primary_type: NativeType::Struct {
                packing_size: None,
                class_size: Some(128),
            },
            additional_types: vec![],
        };

        let result = encode_marshalling_descriptor(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_array_num_element_without_num_param() {
        // Invalid: num_element without num_param
        let invalid = MarshallingInfo {
            primary_type: NativeType::Array {
                element_type: Box::new(NativeType::I4),
                num_param: None,
                num_element: Some(10),
            },
            additional_types: vec![],
        };

        let result = encode_marshalling_descriptor(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_nested_invalid() {
        // Invalid nested type: Ptr to invalid Struct
        let invalid = MarshallingInfo {
            primary_type: NativeType::Ptr {
                ref_type: Some(Box::new(NativeType::Struct {
                    packing_size: None,
                    class_size: Some(64),
                })),
            },
            additional_types: vec![],
        };

        let result = encode_marshalling_descriptor(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_descriptor_into() {
        let mut encoder = MarshallingEncoder::new();
        let mut buffer = Vec::with_capacity(64);

        let info = MarshallingInfo {
            primary_type: NativeType::I4,
            additional_types: vec![],
        };

        encoder.encode_descriptor_into(&info, &mut buffer).unwrap();
        assert_eq!(buffer, vec![NATIVE_TYPE::I4]);

        // Encode another one into the same buffer
        let info2 = MarshallingInfo {
            primary_type: NativeType::Boolean,
            additional_types: vec![],
        };

        encoder.encode_descriptor_into(&info2, &mut buffer).unwrap();
        assert_eq!(buffer, vec![NATIVE_TYPE::I4, NATIVE_TYPE::BOOLEAN]);
    }
}
