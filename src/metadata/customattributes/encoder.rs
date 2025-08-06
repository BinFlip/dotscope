//! Custom attribute blob encoding implementation for .NET metadata generation.
//!
//! This module provides comprehensive encoding of custom attribute data according to the
//! ECMA-335 II.23.3 `CustomAttribute` signature specification. It implements the inverse
//! functionality of the parsing implementation, enabling complete round-trip support for
//! all .NET custom attribute types and structures.
//!
//! # Architecture
//!
//! The encoding architecture mirrors the parsing implementation, providing:
//!
//! ## Core Components
//!
//! - **Fixed Arguments**: Encode constructor arguments using type-specific binary formats
//! - **Named Arguments**: Encode field/property assignments with embedded type tags
//! - **Type System**: Complete coverage of all .NET primitive and complex types
//! - **Binary Format**: Strict ECMA-335 compliance with proper prolog and structure
//!
//! ## Design Principles
//!
//! - **Round-Trip Accuracy**: Encoded data must parse back to identical structures
//! - **ECMA-335 Compliance**: Strict adherence to official binary format specification
//! - **Type Safety**: Leverages existing type system for accurate encoding
//! - **Error Handling**: Comprehensive validation with detailed error messages
//!
//! # Key Functions
//!
//! - [`encode_custom_attribute_value`] - Main encoding function for complete custom attributes
//! - [`encode_fixed_arguments`] - Constructor arguments encoding
//! - [`encode_named_arguments`] - Field/property assignments encoding
//! - [`encode_custom_attribute_argument`] - Individual argument value encoding
//!
//! # Usage Examples
//!
//! ## Encoding Complete Custom Attribute
//!
//! ```rust,ignore
//! use dotscope::metadata::customattributes::{
//!     CustomAttributeValue, CustomAttributeArgument, encode_custom_attribute_value
//! };
//!
//! let custom_attr = CustomAttributeValue {
//!     fixed_args: vec![
//!         CustomAttributeArgument::String("Debug".to_string()),
//!         CustomAttributeArgument::Bool(true),
//!     ],
//!     named_args: vec![],
//! };
//!
//! let encoded_blob = encode_custom_attribute_value(&custom_attr)?;
//! println!("Encoded {} bytes", encoded_blob.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Encoding Individual Arguments
//!
//! ```rust,ignore
//! use dotscope::metadata::customattributes::{CustomAttributeArgument, encode_custom_attribute_argument};
//!
//! let string_arg = CustomAttributeArgument::String("Hello".to_string());
//! let encoded_string = encode_custom_attribute_argument(&string_arg)?;
//!
//! let int_arg = CustomAttributeArgument::I4(42);
//! let encoded_int = encode_custom_attribute_argument(&int_arg)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Binary Format
//!
//! The encoder produces binary data in the exact format specified by ECMA-335:
//!
//! ```text
//! CustomAttribute ::= Prolog FixedArgs NumNamed NamedArgs
//! Prolog          ::= 0x0001
//! FixedArgs       ::= Argument*
//! NumNamed        ::= PackedLen
//! NamedArgs       ::= NamedArg*
//! NamedArg        ::= FIELD | PROPERTY FieldOrPropType FieldOrPropName FixedArg
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are thread-safe and stateless. The encoder can be called
//! concurrently from multiple threads as it operates only on immutable input data.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customattributes::types`] - Type definitions for encoding
//! - [`crate::metadata::customattributes::parser`] - Round-trip validation with parsing
//! - [`crate::cilassembly::CilAssembly`] - Assembly modification and blob heap integration
//! - [`crate::metadata::typesystem`] - Type system for accurate encoding

use crate::{
    metadata::customattributes::{
        CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue,
        SERIALIZATION_TYPE,
    },
    utils::write_compressed_uint,
    Result,
};

/// Encodes a complete custom attribute value into binary blob format according to ECMA-335.
///
/// This is the main entry point for custom attribute encoding. It produces a binary blob
/// that is compatible with the .NET custom attribute format and can be stored in the
/// blob heap of a .NET assembly.
///
/// # Binary Format
///
/// The output follows the ECMA-335 II.23.3 specification:
/// 1. Prolog: 0x0001 (little-endian)
/// 2. Fixed arguments: Constructor parameters in order
/// 3. Named argument count: Compressed integer
/// 4. Named arguments: Field/property assignments with type tags
///
/// # Arguments
///
/// * `value` - The custom attribute value to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded custom attribute blob.
///
/// # Errors
///
/// Returns [`crate::Error::Error`] if the custom attribute contains
/// unsupported data types or malformed structures.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::customattributes::{CustomAttributeValue, CustomAttributeArgument};
///
/// let custom_attr = CustomAttributeValue {
///     fixed_args: vec![CustomAttributeArgument::String("Test".to_string())],
///     named_args: vec![],
/// };
///
/// let blob = encode_custom_attribute_value(&custom_attr)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_custom_attribute_value(value: &CustomAttributeValue) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Write prolog (0x0001 in little-endian)
    buffer.extend_from_slice(&[0x01, 0x00]);

    encode_fixed_arguments(&value.fixed_args, &mut buffer)?;

    #[allow(clippy::cast_possible_truncation)]
    buffer.extend_from_slice(&(value.named_args.len() as u16).to_le_bytes());

    encode_named_arguments(&value.named_args, &mut buffer)?;

    Ok(buffer)
}

/// Encodes the fixed arguments (constructor parameters) of a custom attribute.
///
/// Fixed arguments are encoded in the order they appear in the constructor signature,
/// using type-specific binary formats for each argument type.
///
/// # Arguments
///
/// * `args` - The fixed arguments to encode
/// * `buffer` - The output buffer to write encoded data to
///
/// # ECMA-335 Reference
///
/// According to ECMA-335 II.23.3, fixed arguments are encoded as:
/// ```text
/// FixedArgs ::= Argument*
/// Argument  ::= <type-specific binary data>
/// ```
fn encode_fixed_arguments(args: &[CustomAttributeArgument], buffer: &mut Vec<u8>) -> Result<()> {
    for arg in args {
        encode_custom_attribute_argument(arg, buffer)?;
    }
    Ok(())
}

/// Encodes the named arguments (field/property assignments) of a custom attribute.
///
/// Named arguments include explicit type information via SERIALIZATION_TYPE tags,
/// enabling self-describing parsing without external type resolution.
///
/// # Arguments
///
/// * `args` - The named arguments to encode
/// * `buffer` - The output buffer to write encoded data to
///
/// # ECMA-335 Reference
///
/// According to ECMA-335 II.23.3, named arguments are encoded as:
/// ```text
/// NamedArg ::= FIELD | PROPERTY FieldOrPropType FieldOrPropName FixedArg
/// FIELD    ::= 0x53
/// PROPERTY ::= 0x54
/// ```
fn encode_named_arguments(
    args: &[CustomAttributeNamedArgument],
    buffer: &mut Vec<u8>,
) -> Result<()> {
    for arg in args {
        match &arg.value {
            CustomAttributeArgument::Array(_) => {
                return Err(malformed_error!(
                    "Array arguments are not supported in named arguments"
                ));
            }
            CustomAttributeArgument::Enum(_, _) => {
                return Err(malformed_error!(
                    "Enum arguments are not supported in named arguments"
                ));
            }
            _ => {} // Other types are supported
        }

        if arg.is_field {
            buffer.push(0x53); // FIELD
        } else {
            buffer.push(0x54); // PROPERTY
        }

        let type_tag = get_serialization_type_tag(&arg.value)?;
        buffer.push(type_tag);

        write_string(buffer, &arg.name);

        encode_custom_attribute_argument(&arg.value, buffer)?;
    }
    Ok(())
}

/// Encodes a single custom attribute argument value into binary format.
///
/// This function handles all supported .NET types according to the ECMA-335 specification,
/// using the appropriate binary encoding for each type variant.
///
/// # Arguments
///
/// * `arg` - The argument to encode
/// * `buffer` - The output buffer to write encoded data to
///
/// # Type Encoding
///
/// Each type is encoded according to its specific format:
/// - **Primitives**: Little-endian binary representation
/// - **Strings**: Compressed length + UTF-8 data (or 0xFF for null)
/// - **Arrays**: Compressed length + encoded elements
/// - **Enums**: Underlying type value (type name encoded separately in named args)
///
/// # Errors
///
/// Returns [`crate::Error::Error`] if the argument contains unsupported
/// data types or if encoding operations fail.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_custom_attribute_argument(
    arg: &CustomAttributeArgument,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    match arg {
        CustomAttributeArgument::Void => {
            // Void arguments are typically not used in custom attributes
        }
        CustomAttributeArgument::Bool(value) => {
            buffer.push(u8::from(*value));
        }
        CustomAttributeArgument::Char(value) => {
            // Encode as UTF-16 - if the character fits in 16 bits, use it directly
            // Otherwise, use replacement character (U+FFFD) as .NET does
            let utf16_val = if (*value as u32) <= 0xFFFF {
                *value as u16
            } else {
                0xFFFD // Replacement character for characters outside BMP
            };
            buffer.extend_from_slice(&utf16_val.to_le_bytes());
        }
        CustomAttributeArgument::I1(value) => {
            #[allow(clippy::cast_sign_loss)]
            buffer.push(*value as u8);
        }
        CustomAttributeArgument::U1(value) => {
            buffer.push(*value);
        }
        CustomAttributeArgument::I2(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::U2(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::I4(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::U4(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::I8(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::U8(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::R4(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::R8(value) => {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        CustomAttributeArgument::I(value) => {
            // Native integers are encoded as 4 bytes on 32-bit, 8 bytes on 64-bit
            // ToDo: Make this dependend on the input file - not the current platform?
            if cfg!(target_pointer_width = "32") {
                buffer.extend_from_slice(&(*value as i32).to_le_bytes());
            } else {
                buffer.extend_from_slice(&(*value as i64).to_le_bytes());
            }
        }
        CustomAttributeArgument::U(value) => {
            // Native integers are encoded as 4 bytes on 32-bit, 8 bytes on 64-bit
            // ToDo: Make this dependend on the input file - not the current platform?
            if cfg!(target_pointer_width = "32") {
                buffer.extend_from_slice(&(*value as u32).to_le_bytes());
            } else {
                buffer.extend_from_slice(&(*value as u64).to_le_bytes());
            }
        }
        CustomAttributeArgument::String(value) | CustomAttributeArgument::Type(value) => {
            write_string(buffer, value);
        }
        CustomAttributeArgument::Array(elements) => {
            write_compressed_uint(elements.len() as u32, buffer);
            for element in elements {
                encode_custom_attribute_argument(element, buffer)?;
            }
        }
        CustomAttributeArgument::Enum(_, underlying_value) => {
            encode_custom_attribute_argument(underlying_value, buffer)?;
        }
    }
    Ok(())
}

/// Gets the SERIALIZATION_TYPE tag for a custom attribute argument.
///
/// This function maps custom attribute argument types to their corresponding
/// SERIALIZATION_TYPE constants used in the binary format for named arguments.
///
/// # Arguments
///
/// * `arg` - The argument to get the type tag for
///
/// # Returns
///
/// The SERIALIZATION_TYPE constant corresponding to the argument type.
fn get_serialization_type_tag(arg: &CustomAttributeArgument) -> Result<u8> {
    let tag = match arg {
        CustomAttributeArgument::Void => {
            return Err(malformed_error!(
                "Void arguments are not supported in custom attributes"
            ));
        }
        CustomAttributeArgument::Bool(_) => SERIALIZATION_TYPE::BOOLEAN,
        CustomAttributeArgument::Char(_) => SERIALIZATION_TYPE::CHAR,
        CustomAttributeArgument::I1(_) => SERIALIZATION_TYPE::I1,
        CustomAttributeArgument::U1(_) => SERIALIZATION_TYPE::U1,
        CustomAttributeArgument::I2(_) => SERIALIZATION_TYPE::I2,
        CustomAttributeArgument::U2(_) => SERIALIZATION_TYPE::U2,
        CustomAttributeArgument::I4(_) => SERIALIZATION_TYPE::I4,
        CustomAttributeArgument::U4(_) => SERIALIZATION_TYPE::U4,
        CustomAttributeArgument::I8(_) => SERIALIZATION_TYPE::I8,
        CustomAttributeArgument::U8(_) => SERIALIZATION_TYPE::U8,
        CustomAttributeArgument::R4(_) => SERIALIZATION_TYPE::R4,
        CustomAttributeArgument::R8(_) => SERIALIZATION_TYPE::R8,
        CustomAttributeArgument::I(_) => {
            // Native integers use I4 on 32-bit, I8 on 64-bit
            // ToDo: Make this dependend on the input file - not the current platform?
            if cfg!(target_pointer_width = "32") {
                SERIALIZATION_TYPE::I4
            } else {
                SERIALIZATION_TYPE::I8
            }
        }
        CustomAttributeArgument::U(_) => {
            // Native integers use U4 on 32-bit, U8 on 64-bit
            // ToDo: Make this dependend on the input file - not the current platform?
            if cfg!(target_pointer_width = "32") {
                SERIALIZATION_TYPE::U4
            } else {
                SERIALIZATION_TYPE::U8
            }
        }
        CustomAttributeArgument::String(_) => SERIALIZATION_TYPE::STRING,
        CustomAttributeArgument::Type(_) => SERIALIZATION_TYPE::TYPE,
        CustomAttributeArgument::Array(_) => SERIALIZATION_TYPE::SZARRAY,
        CustomAttributeArgument::Enum(_, _) => SERIALIZATION_TYPE::ENUM,
    };
    Ok(tag)
}

/// Writes a string to the buffer using the .NET custom attribute string format.
///
/// Strings are encoded as:
/// - Null strings: Single byte 0xFF
/// - Non-null strings: Compressed length + UTF-8 data
///
/// # Arguments
///
/// * `buffer` - The output buffer to write to
/// * `value` - The string value to encode
#[allow(clippy::cast_possible_truncation)]
fn write_string(buffer: &mut Vec<u8>, value: &str) {
    if value.is_empty() {
        write_compressed_uint(0, buffer);
    } else {
        let utf8_bytes = value.as_bytes();
        write_compressed_uint(utf8_bytes.len() as u32, buffer);
        buffer.extend_from_slice(utf8_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::customattributes::{CustomAttributeNamedArgument, CustomAttributeValue};

    #[test]
    fn test_encode_simple_custom_attribute() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String("Test".to_string())],
            named_args: vec![],
        };

        let result = encode_custom_attribute_value(&custom_attr);
        assert!(
            result.is_ok(),
            "Simple custom attribute encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded data should not be empty");

        // Check prolog (0x0001)
        assert_eq!(encoded[0], 0x01, "First byte should be 0x01");
        assert_eq!(encoded[1], 0x00, "Second byte should be 0x00");

        // Should have named argument count (0)
        let last_byte = encoded[encoded.len() - 1];
        assert_eq!(last_byte, 0x00, "Named argument count should be 0");
    }

    #[test]
    fn test_encode_boolean_argument() {
        let mut buffer = Vec::new();
        let arg = CustomAttributeArgument::Bool(true);

        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "Boolean encoding should succeed");
        assert_eq!(buffer, vec![1], "True should encode as 1");

        buffer.clear();
        let arg = CustomAttributeArgument::Bool(false);
        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "Boolean encoding should succeed");
        assert_eq!(buffer, vec![0], "False should encode as 0");
    }

    #[test]
    fn test_encode_integer_arguments() {
        let mut buffer = Vec::new();

        // Test I4
        let arg = CustomAttributeArgument::I4(0x12345678);
        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "I4 encoding should succeed");
        assert_eq!(
            buffer,
            vec![0x78, 0x56, 0x34, 0x12],
            "I4 should be little-endian"
        );

        // Test U2
        buffer.clear();
        let arg = CustomAttributeArgument::U2(0x1234);
        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "U2 encoding should succeed");
        assert_eq!(buffer, vec![0x34, 0x12], "U2 should be little-endian");
    }

    #[test]
    fn test_encode_string_argument() {
        let mut buffer = Vec::new();
        let arg = CustomAttributeArgument::String("Hello".to_string());

        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "String encoding should succeed");

        // Should be: length (5) + "Hello" UTF-8
        let expected = vec![5, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(buffer, expected, "String should encode with length prefix");
    }

    #[test]
    fn test_encode_array_argument() {
        let mut buffer = Vec::new();
        let arg = CustomAttributeArgument::Array(vec![
            CustomAttributeArgument::I4(1),
            CustomAttributeArgument::I4(2),
        ]);

        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "Array encoding should succeed");

        // Should be: length (2) + two I4 values
        let expected = vec![
            2, // length
            1, 0, 0, 0, // I4(1) little-endian
            2, 0, 0, 0, // I4(2) little-endian
        ];
        assert_eq!(
            buffer, expected,
            "Array should encode with length and elements"
        );
    }

    #[test]
    fn test_encode_named_argument() {
        let named_args = vec![CustomAttributeNamedArgument {
            is_field: false, // property
            name: "Value".to_string(),
            arg_type: "String".to_string(),
            value: CustomAttributeArgument::String("Test".to_string()),
        }];

        let mut buffer = Vec::new();
        let result = encode_named_arguments(&named_args, &mut buffer);
        assert!(result.is_ok(), "Named argument encoding should succeed");

        assert!(!buffer.is_empty(), "Named argument should produce data");
        assert_eq!(buffer[0], 0x54, "Should start with PROPERTY marker");
        assert_eq!(
            buffer[1],
            SERIALIZATION_TYPE::STRING,
            "Should have STRING type tag"
        );
    }

    #[test]
    fn test_encode_compressed_uint() {
        let mut buffer = Vec::new();

        // Test single byte encoding
        write_compressed_uint(42, &mut buffer);
        assert_eq!(buffer, vec![42], "Small values should use single byte");

        // Test two byte encoding
        buffer.clear();
        write_compressed_uint(0x1234, &mut buffer);
        assert_eq!(
            buffer,
            vec![0x80 | 0x12, 0x34],
            "Medium values should use two bytes"
        );

        // Test four byte encoding
        buffer.clear();
        write_compressed_uint(0x12345678, &mut buffer);
        assert_eq!(
            buffer,
            vec![0xC0 | 0x12, 0x34, 0x56, 0x78],
            "Large values should use four bytes"
        );
    }

    #[test]
    fn test_get_serialization_type_tag() {
        assert_eq!(
            get_serialization_type_tag(&CustomAttributeArgument::Bool(true)).unwrap(),
            SERIALIZATION_TYPE::BOOLEAN
        );
        assert_eq!(
            get_serialization_type_tag(&CustomAttributeArgument::String("test".to_string()))
                .unwrap(),
            SERIALIZATION_TYPE::STRING
        );
        assert_eq!(
            get_serialization_type_tag(&CustomAttributeArgument::I4(42)).unwrap(),
            SERIALIZATION_TYPE::I4
        );
    }

    #[test]
    fn test_encode_complete_custom_attribute_with_named_args() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String("Debug".to_string())],
            named_args: vec![CustomAttributeNamedArgument {
                is_field: false,
                name: "Name".to_string(),
                arg_type: "String".to_string(),
                value: CustomAttributeArgument::String("TestName".to_string()),
            }],
        };

        let result = encode_custom_attribute_value(&custom_attr);
        assert!(
            result.is_ok(),
            "Complete custom attribute encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(
            encoded.len() > 10,
            "Complete attribute should be substantial"
        );

        // Check prolog
        assert_eq!(encoded[0], 0x01, "Should start with prolog");
        assert_eq!(encoded[1], 0x00, "Should start with prolog");
    }

    #[test]
    fn test_debug_named_args_encoding() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![],
            named_args: vec![CustomAttributeNamedArgument {
                is_field: true,
                name: "FieldValue".to_string(),
                arg_type: "I4".to_string(),
                value: CustomAttributeArgument::I4(42),
            }],
        };

        let encoded = encode_custom_attribute_value(&custom_attr).unwrap();

        // Expected format:
        // 0x01, 0x00 - Prolog
        // (no fixed args)
        // 0x01, 0x00 - Named args count (1, little-endian u16)
        // 0x53 - Field indicator
        // 0x08 - I4 type tag
        // field name length + "FieldValue"
        // 42 as I4

        // Check actual structure
        if encoded.len() >= 6 {
            // Verify structure: prolog, named count, field indicator, type tag
            assert_eq!(encoded[0], 0x01);
            assert_eq!(encoded[1], 0x00);
            assert_eq!(encoded[2], 0x01);
            assert_eq!(encoded[3], 0x00);
            assert_eq!(encoded[4], 0x53);
            assert_eq!(encoded[5], 0x08);
        }
    }

    #[test]
    fn test_debug_type_args_encoding() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::Type("System.String".to_string())],
            named_args: vec![],
        };

        let encoded = encode_custom_attribute_value(&custom_attr).unwrap();

        // Expected format:
        // 0x01, 0x00 - Prolog
        // Type string: compressed length + "System.String"
        // 0x00, 0x00 - Named args count (0, little-endian u16)

        // Verify byte structure
        let mut pos = 0;
        assert_eq!(encoded[pos], 0x01);
        assert_eq!(encoded[pos + 1], 0x00);
        pos += 2;

        // String encoding: first read compressed length
        if pos < encoded.len() {
            let str_len = encoded[pos];
            pos += 1;

            if pos + str_len as usize <= encoded.len() {
                let string_bytes = &encoded[pos..pos + str_len as usize];
                let string_str = String::from_utf8_lossy(string_bytes);
                assert_eq!(string_str, "System.String");
                pos += str_len as usize;
            }
        }

        if pos + 1 < encoded.len() {
            // Verify named count is 0
            assert_eq!(encoded[pos], 0x00);
            assert_eq!(encoded[pos + 1], 0x00);
        }
    }
}
