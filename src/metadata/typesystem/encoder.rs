//! Binary encoding for .NET type signatures according to ECMA-335.
//!
//! This module provides functionality to encode [`crate::metadata::signatures::TypeSignature`] instances into their
//! binary representation as defined by the ECMA-335 standard. The encoding process
//! converts structured type information into compact binary signatures suitable for
//! storage in metadata blob heaps.
//!
//! # Encoding Format
//!
//! Type signatures are encoded using ECMA-335 element type constants and compressed
//! integer encoding for optimal space efficiency. The encoding supports all .NET
//! type system features including:
//!
//! - **Primitive Types**: Direct element type encoding (I4, String, Boolean, etc.)
//! - **Reference Types**: Element type + TypeDefOrRef coded index
//! - **Generic Types**: GENERICINST + base type + argument count + type arguments
//! - **Array Types**: ARRAY/SZARRAY + element type + dimension information
//! - **Pointer Types**: PTR/BYREF + custom modifiers + pointed-to type
//! - **Function Types**: FNPTR + method signature encoding
//!
//! # Usage
//!
//! ```rust
//! use dotscope::prelude::*;
//!
//! // Encode a simple primitive type
//! let signature = TypeSignature::I4;
//! let encoded = TypeSignatureEncoder::encode(&signature)?;
//! assert_eq!(encoded, vec![0x08]); // ELEMENT_TYPE_I4
//!
//! // Encode a single-dimensional array
//! let array_sig = TypeSignature::SzArray(SignatureSzArray {
//!     base: Box::new(TypeSignature::String),
//!     modifiers: vec![],
//! });
//! let encoded = TypeSignatureEncoder::encode(&array_sig)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    metadata::{
        signatures::{CustomModifier, SignatureMethod, TypeSignature},
        token::Token,
    },
    utils::{write_compressed_int, write_compressed_uint},
    Error, Result,
};

/// Maximum recursion depth for type signature encoding.
///
/// This limit prevents stack overflow from deeply nested or circular type signatures.
/// The value is set to match the signature parser's limit for consistency.
const MAX_RECURSION_DEPTH: usize = 50;

/// Encoder for converting type signatures into binary format.
///
/// `TypeSignatureEncoder` provides methods to convert structured [`crate::metadata::signatures::TypeSignature`]
/// instances into their binary representation according to ECMA-335 standards.
/// The encoder handles all type signature variants and their specific encoding
/// requirements.
///
/// # Encoding Features
///
/// - **Element Type Constants**: Uses standard ECMA-335 element type values
/// - **Compressed Integers**: Variable-length encoding for counts and indices
/// - **Coded Indices**: TypeDefOrRef and other coded index formats
/// - **Custom Modifiers**: Required and optional modifier encoding
/// - **Recursive Encoding**: Proper handling of nested type structures
///
/// # Thread Safety
///
/// All methods are stateless and thread-safe. Multiple threads can safely
/// use the encoder simultaneously without synchronization.
pub struct TypeSignatureEncoder;

impl TypeSignatureEncoder {
    /// Encodes a type signature into binary format.
    ///
    /// Converts a [`crate::metadata::signatures::TypeSignature`] into its binary representation according
    /// to ECMA-335 standards. The encoding process handles all type signature
    /// variants and their specific encoding requirements.
    ///
    /// # Recursion Protection
    ///
    /// This method enforces a maximum recursion depth limit
    /// to prevent stack overflow from deeply nested or circular type signatures.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to encode
    ///
    /// # Returns
    ///
    /// A vector of bytes representing the encoded signature.
    ///
    /// # Errors
    ///
    /// - Unsupported signature type
    /// - Invalid token references
    /// - Encoding format errors
    /// - [`crate::Error::RecursionLimit`]: Maximum recursion depth exceeded
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// // Encode primitive types
    /// let int_sig = TypeSignature::I4;
    /// let encoded = TypeSignatureEncoder::encode(&int_sig)?;
    /// assert_eq!(encoded, vec![0x08]); // ELEMENT_TYPE_I4
    ///
    /// let string_sig = TypeSignature::String;
    /// let encoded = TypeSignatureEncoder::encode(&string_sig)?;
    /// assert_eq!(encoded, vec![0x0E]); // ELEMENT_TYPE_STRING
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode(signature: &TypeSignature) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        Self::encode_type_signature_internal(signature, &mut buffer, 0)?;
        Ok(buffer)
    }

    /// Encodes a type signature into an existing buffer.
    ///
    /// Public wrapper method that calls the internal recursive implementation
    /// with initial depth tracking. This provides a clean public API while
    /// maintaining recursion protection.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    ///
    /// # Errors
    ///
    /// - Unsupported signature type
    /// - Invalid token references
    /// - Recursive encoding errors
    /// - [`crate::Error::RecursionLimit`]: Maximum recursion depth exceeded
    pub fn encode_type_signature(signature: &TypeSignature, buffer: &mut Vec<u8>) -> Result<()> {
        Self::encode_type_signature_internal(signature, buffer, 0)
    }

    /// Internal recursive implementation of type signature encoding.
    ///
    /// Recursively encodes a [`crate::metadata::signatures::TypeSignature`] and all its components into
    /// the provided buffer with depth tracking for recursion protection.
    /// This method handles all type signature variants and their specific
    /// encoding requirements.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    /// * `depth` - Current recursion depth for overflow protection
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::RecursionLimit`]: Maximum recursion depth exceeded
    /// - Unsupported signature type
    /// - Invalid token references
    /// - Recursive encoding errors
    fn encode_type_signature_internal(
        signature: &TypeSignature,
        buffer: &mut Vec<u8>,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_RECURSION_DEPTH {
            return Err(Error::RecursionLimit(MAX_RECURSION_DEPTH));
        }

        match signature {
            // Primitive types - direct element type encoding
            TypeSignature::Void => buffer.push(0x01),
            TypeSignature::Boolean => buffer.push(0x02),
            TypeSignature::Char => buffer.push(0x03),
            TypeSignature::I1 => buffer.push(0x04),
            TypeSignature::U1 => buffer.push(0x05),
            TypeSignature::I2 => buffer.push(0x06),
            TypeSignature::U2 => buffer.push(0x07),
            TypeSignature::I4 => buffer.push(0x08),
            TypeSignature::U4 => buffer.push(0x09),
            TypeSignature::I8 => buffer.push(0x0A),
            TypeSignature::U8 => buffer.push(0x0B),
            TypeSignature::R4 => buffer.push(0x0C),
            TypeSignature::R8 => buffer.push(0x0D),
            TypeSignature::String => buffer.push(0x0E),
            TypeSignature::Object => buffer.push(0x1C),
            TypeSignature::I => buffer.push(0x18),
            TypeSignature::U => buffer.push(0x19),
            TypeSignature::TypedByRef => buffer.push(0x16),

            // Reference types with token encoding
            TypeSignature::ValueType(token) => {
                buffer.push(0x11); // ELEMENT_TYPE_VALUETYPE
                Self::encode_typedefref_token(*token, buffer)?;
            }

            TypeSignature::Class(token) => {
                buffer.push(0x12); // ELEMENT_TYPE_CLASS
                Self::encode_typedefref_token(*token, buffer)?;
            }

            // Generic parameters
            TypeSignature::GenericParamType(index) => {
                buffer.push(0x13); // ELEMENT_TYPE_VAR
                write_compressed_uint(*index, buffer);
            }

            TypeSignature::GenericParamMethod(index) => {
                buffer.push(0x1E); // ELEMENT_TYPE_MVAR
                write_compressed_uint(*index, buffer);
            }

            // Reference and pointer types
            TypeSignature::ByRef(inner) => {
                buffer.push(0x10); // ELEMENT_TYPE_BYREF
                Self::encode_type_signature_internal(inner, buffer, depth + 1)?;
            }

            TypeSignature::Ptr(pointer) => {
                buffer.push(0x0F); // ELEMENT_TYPE_PTR
                                   // Encode custom modifiers
                Self::encode_custom_modifiers(&pointer.modifiers, buffer)?;
                Self::encode_type_signature_internal(&pointer.base, buffer, depth + 1)?;
            }

            TypeSignature::Pinned(inner) => {
                buffer.push(0x45); // ELEMENT_TYPE_PINNED
                Self::encode_type_signature_internal(inner, buffer, depth + 1)?;
            }

            // Array types
            TypeSignature::SzArray(array) => {
                buffer.push(0x1D); // ELEMENT_TYPE_SZARRAY
                                   // Encode custom modifiers
                Self::encode_custom_modifiers(&array.modifiers, buffer)?;
                Self::encode_type_signature_internal(&array.base, buffer, depth + 1)?;
            }

            TypeSignature::Array(array) => {
                buffer.push(0x14); // ELEMENT_TYPE_ARRAY
                Self::encode_type_signature_internal(&array.base, buffer, depth + 1)?;
                write_compressed_uint(array.rank, buffer);

                // Collect sizes and lower bounds from dimensions
                let mut sizes = Vec::new();
                let mut lower_bounds = Vec::new();

                for dimension in &array.dimensions {
                    if let Some(size) = dimension.size {
                        sizes.push(size);
                    }
                    if let Some(lower_bound) = dimension.lower_bound {
                        lower_bounds.push(lower_bound);
                    }
                }

                // Encode NumSizes and Sizes
                write_compressed_uint(
                    u32::try_from(sizes.len()).map_err(|_| {
                        Error::Error(format!("Array sizes length out of range: {}", sizes.len()))
                    })?,
                    buffer,
                );
                for size in sizes {
                    write_compressed_uint(size, buffer);
                }

                // Encode NumLoBounds and LoBounds
                write_compressed_uint(
                    u32::try_from(lower_bounds.len()).map_err(|_| {
                        Error::Error(format!(
                            "Array lower bounds length out of range: {}",
                            lower_bounds.len()
                        ))
                    })?,
                    buffer,
                );
                #[allow(clippy::cast_possible_wrap)]
                // Cast to i32 is correct per ECMA-335 - array lower bounds are signed
                for lower_bound in lower_bounds {
                    write_compressed_int(lower_bound as i32, buffer);
                }
            }

            // Generic type instantiation
            TypeSignature::GenericInst(base_type, type_args) => {
                buffer.push(0x15); // ELEMENT_TYPE_GENERICINST
                Self::encode_type_signature_internal(base_type, buffer, depth + 1)?;
                write_compressed_uint(
                    u32::try_from(type_args.len()).map_err(|_| {
                        Error::Error(format!(
                            "Generic type arguments length out of range: {}",
                            type_args.len()
                        ))
                    })?,
                    buffer,
                );
                for type_arg in type_args {
                    Self::encode_type_signature_internal(type_arg, buffer, depth + 1)?;
                }
            }

            // Function pointer
            TypeSignature::FnPtr(method_sig) => {
                buffer.push(0x1B); // ELEMENT_TYPE_FNPTR
                Self::encode_method_signature(method_sig.as_ref(), buffer)?;
            }

            // Custom modifiers
            TypeSignature::ModifiedRequired(modifiers) => {
                for modifier in modifiers {
                    let modifier_type = if modifier.is_required {
                        0x1F // ELEMENT_TYPE_CMOD_REQD
                    } else {
                        0x20 // ELEMENT_TYPE_CMOD_OPT
                    };
                    buffer.push(modifier_type);
                    Self::encode_typedefref_token(modifier.modifier_type, buffer)?;
                }
            }

            TypeSignature::ModifiedOptional(modifiers) => {
                for modifier in modifiers {
                    let modifier_type = if modifier.is_required {
                        0x1F // ELEMENT_TYPE_CMOD_REQD
                    } else {
                        0x20 // ELEMENT_TYPE_CMOD_OPT
                    };
                    buffer.push(modifier_type);
                    Self::encode_typedefref_token(modifier.modifier_type, buffer)?;
                }
            }

            // Special types for custom attributes and internal use
            TypeSignature::Type => buffer.push(0x50), // Custom attribute type marker
            TypeSignature::Boxed => buffer.push(0x51), // Custom attribute boxed marker
            TypeSignature::Field => {
                return Err(Error::ModificationInvalidOperation {
                    details: "Field signatures should not appear in type specifications"
                        .to_string(),
                });
            }
            TypeSignature::Internal => {
                return Err(Error::ModificationInvalidOperation {
                    details: "Cannot encode internal type signature".to_string(),
                });
            }
            TypeSignature::Modifier => buffer.push(0x22), // Modifier sentinel
            TypeSignature::Sentinel => buffer.push(0x41), // Vararg sentinel
            TypeSignature::Reserved => {
                return Err(Error::ModificationInvalidOperation {
                    details: "Cannot encode reserved type signature".to_string(),
                });
            }

            // Unknown or unsupported types
            TypeSignature::Unknown => {
                return Err(Error::ModificationInvalidOperation {
                    details: "Cannot encode unknown type signature".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Encodes a method signature for function pointers.
    ///
    /// Encodes a method signature structure including calling convention,
    /// parameter count, return type, and parameter types according to
    /// ECMA-335 method signature format.
    ///
    /// # Arguments
    ///
    /// * `method_sig` - The method signature to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    fn encode_method_signature(method_sig: &SignatureMethod, buffer: &mut Vec<u8>) -> Result<()> {
        let mut calling_conv = 0u8;
        if method_sig.has_this {
            calling_conv |= 0x20;
        }
        if method_sig.explicit_this {
            calling_conv |= 0x40;
        }
        if method_sig.default {
            calling_conv |= 0x00;
        }
        if method_sig.vararg {
            calling_conv |= 0x05;
        }
        if method_sig.cdecl {
            calling_conv |= 0x01;
        }
        if method_sig.stdcall {
            calling_conv |= 0x02;
        }
        if method_sig.thiscall {
            calling_conv |= 0x03;
        }
        if method_sig.fastcall {
            calling_conv |= 0x04;
        }

        buffer.push(calling_conv);

        write_compressed_uint(
            u32::try_from(method_sig.params.len()).map_err(|_| {
                Error::Error(format!(
                    "Method parameters length out of range: {}",
                    method_sig.params.len()
                ))
            })?,
            buffer,
        );
        Self::encode_type_signature(&method_sig.return_type.base, buffer)?;

        for param in &method_sig.params {
            Self::encode_type_signature(&param.base, buffer)?;
        }

        Ok(())
    }

    /// Encodes custom modifiers.
    ///
    /// Encodes a list of custom modifier tokens according to ECMA-335
    /// custom modifier format. Each modifier is encoded with its appropriate
    /// element type (required or optional) followed by the token reference.
    ///
    /// # Arguments
    ///
    /// * `modifiers` - List of modifier tokens to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    fn encode_custom_modifiers(modifiers: &[CustomModifier], buffer: &mut Vec<u8>) -> Result<()> {
        for modifier in modifiers {
            let modifier_type = if modifier.is_required {
                0x1F // ELEMENT_TYPE_CMOD_REQD
            } else {
                0x20 // ELEMENT_TYPE_CMOD_OPT
            };
            buffer.push(modifier_type);
            Self::encode_typedefref_token(modifier.modifier_type, buffer)?;
        }
        Ok(())
    }

    /// Encodes a token as a TypeDefOrRef coded index.
    ///
    /// Converts a metadata token into its compressed coded index representation
    /// according to ECMA-335 TypeDefOrRef coded index format. The encoding
    /// depends on the token's table type and row identifier.
    ///
    /// # TypeDefOrRef Coding
    ///
    /// - TypeDef (0x02): `(rid << 2) | 0`
    /// - TypeRef (0x01): `(rid << 2) | 1`
    /// - TypeSpec (0x1B): `(rid << 2) | 2`
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    ///
    /// # Errors
    ///
    /// - Invalid token format
    /// - Unsupported table type for TypeDefOrRef
    fn encode_typedefref_token(token: Token, buffer: &mut Vec<u8>) -> Result<()> {
        let table_id = (token.value() >> 24) & 0xFF;
        let rid = token.value() & 0x00FF_FFFF;

        let coded_index = match table_id {
            0x02 => rid << 2,       // TypeDef
            0x01 => (rid << 2) | 1, // TypeRef
            0x1B => (rid << 2) | 2, // TypeSpec
            _ => {
                return Err(Error::ModificationInvalidOperation {
                    details: format!(
                        "Invalid token for TypeDefOrRef coded index: {:08x}",
                        token.value()
                    ),
                });
            }
        };

        write_compressed_uint(coded_index, buffer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::signatures::{SignatureArray, SignaturePointer, SignatureSzArray};
    use crate::metadata::typesystem::ArrayDimensions;

    #[test]
    fn test_encode_primitive_types() {
        // Test all primitive types
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Void).unwrap(),
            vec![0x01]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Boolean).unwrap(),
            vec![0x02]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Char).unwrap(),
            vec![0x03]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I1).unwrap(),
            vec![0x04]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U1).unwrap(),
            vec![0x05]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I2).unwrap(),
            vec![0x06]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U2).unwrap(),
            vec![0x07]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I4).unwrap(),
            vec![0x08]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U4).unwrap(),
            vec![0x09]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I8).unwrap(),
            vec![0x0A]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U8).unwrap(),
            vec![0x0B]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::R4).unwrap(),
            vec![0x0C]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::R8).unwrap(),
            vec![0x0D]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::String).unwrap(),
            vec![0x0E]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Object).unwrap(),
            vec![0x1C]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I).unwrap(),
            vec![0x18]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U).unwrap(),
            vec![0x19]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::TypedByRef).unwrap(),
            vec![0x16]
        );
    }

    #[test]
    fn test_encode_reference_types() {
        // Test ValueType with token
        let valuetype_token = Token::new(0x02000001); // TypeDef RID 1
        let valuetype_sig = TypeSignature::ValueType(valuetype_token);
        let encoded = TypeSignatureEncoder::encode(&valuetype_sig).unwrap();
        assert_eq!(encoded, vec![0x11, 0x04]); // ELEMENT_TYPE_VALUETYPE + coded index (1 << 2 | 0)

        // Test Class with token
        let class_token = Token::new(0x01000001); // TypeRef RID 1
        let class_sig = TypeSignature::Class(class_token);
        let encoded = TypeSignatureEncoder::encode(&class_sig).unwrap();
        assert_eq!(encoded, vec![0x12, 0x05]); // ELEMENT_TYPE_CLASS + coded index (1 << 2 | 1)
    }

    #[test]
    fn test_encode_generic_parameters() {
        // Test type generic parameter
        let type_param = TypeSignature::GenericParamType(0);
        let encoded = TypeSignatureEncoder::encode(&type_param).unwrap();
        assert_eq!(encoded, vec![0x13, 0x00]); // ELEMENT_TYPE_VAR + index 0

        // Test method generic parameter
        let method_param = TypeSignature::GenericParamMethod(1);
        let encoded = TypeSignatureEncoder::encode(&method_param).unwrap();
        assert_eq!(encoded, vec![0x1E, 0x01]); // ELEMENT_TYPE_MVAR + index 1
    }

    #[test]
    fn test_encode_byref() {
        // Test managed reference
        let byref_sig = TypeSignature::ByRef(Box::new(TypeSignature::I4));
        let encoded = TypeSignatureEncoder::encode(&byref_sig).unwrap();
        assert_eq!(encoded, vec![0x10, 0x08]); // ELEMENT_TYPE_BYREF + ELEMENT_TYPE_I4
    }

    #[test]
    fn test_encode_pointer() {
        // Test unmanaged pointer
        let pointer_sig = TypeSignature::Ptr(SignaturePointer {
            modifiers: vec![],
            base: Box::new(TypeSignature::I4),
        });
        let encoded = TypeSignatureEncoder::encode(&pointer_sig).unwrap();
        assert_eq!(encoded, vec![0x0F, 0x08]); // ELEMENT_TYPE_PTR + ELEMENT_TYPE_I4
    }

    #[test]
    fn test_encode_szarray() {
        // Test single-dimensional array
        let array_sig = TypeSignature::SzArray(SignatureSzArray {
            modifiers: vec![],
            base: Box::new(TypeSignature::String),
        });
        let encoded = TypeSignatureEncoder::encode(&array_sig).unwrap();
        assert_eq!(encoded, vec![0x1D, 0x0E]); // ELEMENT_TYPE_SZARRAY + ELEMENT_TYPE_STRING
    }

    #[test]
    fn test_encode_array() {
        // Test multi-dimensional array
        let array_sig = TypeSignature::Array(SignatureArray {
            base: Box::new(TypeSignature::I4),
            rank: 2,
            dimensions: vec![
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
            ],
        });
        let encoded = TypeSignatureEncoder::encode(&array_sig).unwrap();
        assert_eq!(encoded, vec![0x14, 0x08, 0x02, 0x00, 0x00]); // ELEMENT_TYPE_ARRAY + I4 + rank=2 + no sizes/bounds
    }

    #[test]
    fn test_encode_generic_instantiation() {
        // Test generic instantiation: List<int>
        let list_token = Token::new(0x02000001);
        let generic_sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(list_token)),
            vec![TypeSignature::I4],
        );
        let encoded = TypeSignatureEncoder::encode(&generic_sig).unwrap();
        assert_eq!(encoded, vec![0x15, 0x12, 0x04, 0x01, 0x08]); // GENERICINST + CLASS + token + count=1 + I4
    }

    #[test]
    fn test_encode_complex_nested_generic() {
        // Test Dictionary<string, List<int>>
        let dict_token = Token::new(0x02000001);
        let list_token = Token::new(0x02000002);

        let nested_list = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(list_token)),
            vec![TypeSignature::I4],
        );

        let complex_sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(dict_token)),
            vec![TypeSignature::String, nested_list],
        );

        let encoded = TypeSignatureEncoder::encode(&complex_sig).unwrap();
        // Should start with GENERICINST + CLASS + dict_token + count=2 + STRING + nested generic...
        assert_eq!(encoded[0], 0x15); // ELEMENT_TYPE_GENERICINST
        assert_eq!(encoded[1], 0x12); // ELEMENT_TYPE_CLASS
        assert_eq!(encoded[2], 0x04); // dict_token coded index
        assert_eq!(encoded[3], 0x02); // argument count = 2
        assert_eq!(encoded[4], 0x0E); // ELEMENT_TYPE_STRING
        assert_eq!(encoded[5], 0x15); // Start of nested GENERICINST
    }

    #[test]
    fn test_encode_typedefref_tokens() {
        let mut buffer = Vec::new();

        // Test TypeDef token
        let typedef_token = Token::new(0x02000001);
        TypeSignatureEncoder::encode_typedefref_token(typedef_token, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x04]); // (1 << 2) | 0
        buffer.clear();

        // Test TypeRef token
        let typeref_token = Token::new(0x01000001);
        TypeSignatureEncoder::encode_typedefref_token(typeref_token, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x05]); // (1 << 2) | 1
        buffer.clear();

        // Test TypeSpec token
        let typespec_token = Token::new(0x1B000001);
        TypeSignatureEncoder::encode_typedefref_token(typespec_token, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x06]); // (1 << 2) | 2
    }

    #[test]
    fn test_encode_invalid_token() {
        let mut buffer = Vec::new();
        let invalid_token = Token::new(0x03000001); // FieldDef - not valid for TypeDefOrRef

        let result = TypeSignatureEncoder::encode_typedefref_token(invalid_token, &mut buffer);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid token for TypeDefOrRef"));
    }

    #[test]
    fn test_encode_unknown_signature() {
        let unknown_sig = TypeSignature::Unknown;
        let result = TypeSignatureEncoder::encode(&unknown_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encode unknown type signature"));
    }

    #[test]
    fn test_recursion_protection() {
        // Create a deeply nested type signature that would exceed the recursion limit
        let mut nested_sig = TypeSignature::I4;
        for _ in 0..MAX_RECURSION_DEPTH + 10 {
            nested_sig = TypeSignature::ByRef(Box::new(nested_sig));
        }

        let result = TypeSignatureEncoder::encode(&nested_sig);
        assert!(result.is_err());
        if let Err(err) = result {
            if let crate::Error::RecursionLimit(depth) = err {
                assert_eq!(depth, MAX_RECURSION_DEPTH);
            } else {
                panic!("Expected RecursionLimit error, got: {err:?}");
            }
        }
    }

    #[test]
    fn test_encode_pinned_type() {
        let pinned_sig = TypeSignature::Pinned(Box::new(TypeSignature::I4));
        let encoded = TypeSignatureEncoder::encode(&pinned_sig).unwrap();
        assert_eq!(encoded, vec![0x45, 0x08]); // ELEMENT_TYPE_PINNED + ELEMENT_TYPE_I4
    }

    #[test]
    fn test_encode_special_types() {
        // Test custom attribute special types
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Type).unwrap(),
            vec![0x50]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Boxed).unwrap(),
            vec![0x51]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Modifier).unwrap(),
            vec![0x22]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Sentinel).unwrap(),
            vec![0x41]
        );
    }

    #[test]
    fn test_encode_invalid_types() {
        // Test types that should fail to encode
        let internal_sig = TypeSignature::Internal;
        let result = TypeSignatureEncoder::encode(&internal_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encode internal type signature"));

        let reserved_sig = TypeSignature::Reserved;
        let result = TypeSignatureEncoder::encode(&reserved_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encode reserved type signature"));

        let field_sig = TypeSignature::Field;
        let result = TypeSignatureEncoder::encode(&field_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Field signatures should not appear"));
    }
}
