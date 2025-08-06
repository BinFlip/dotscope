//! Dedicated signature encoders for .NET metadata blob encoding.
//!
//! This module provides specialized encoders for each signature type, built on top
//! of the existing TypeSignatureEncoder foundation. Each encoder implements the
//! specific ECMA-335 binary format for its signature type.
//!
//! # Available Encoders
//!
//! - [`encode_method_signature`] - Method signatures for MethodDef, MemberRef, MethodSpec
//! - [`encode_field_signature`] - Field signatures for Field and MemberRef tables
//! - [`encode_property_signature`] - Property signatures for Property table
//! - [`encode_local_var_signature`] - Local variable signatures for StandAloneSig table
//! - [`encode_typespec_signature`] - Type specification signatures for TypeSpec table
//!
//! # Design Principles
//!
//! - **Separation of Concerns**: Encoding logic is separated from BuilderContext coordination
//! - **Reusable Components**: Encoders can be used independently or through BuilderContext
//! - **ECMA-335 Compliance**: All encoders follow the official binary format specifications
//! - **TypeSignatureEncoder Foundation**: Built on the proven TypeSignatureEncoder base

use crate::{
    metadata::{
        signatures::{
            CustomModifier, SignatureField, SignatureLocalVariables, SignatureMethod,
            SignatureParameter, SignatureProperty, SignatureTypeSpec,
        },
        token::Token,
        typesystem::TypeSignatureEncoder,
    },
    utils::write_compressed_uint,
    Error, Result,
};

/// Encodes a custom modifier token into binary format according to ECMA-335.
///
/// Custom modifiers are encoded as:
/// - Required modifiers: 0x1F (ELEMENT_TYPE_CMOD_REQD) + TypeDefOrRef coded index
/// - Optional modifiers: 0x20 (ELEMENT_TYPE_CMOD_OPT) + TypeDefOrRef coded index
///
/// # Arguments
///
/// * `modifier_token` - The token referencing the modifier type
/// * `is_required` - Whether this is a required (modreq) or optional (modopt) modifier
/// * `buffer` - The output buffer to write the encoded modifier to
///
/// # TypeDefOrRef Coded Index Encoding
///
/// The modifier token is encoded using the TypeDefOrRef coded index format:
/// - TypeDef: `(rid << 2) | 0`
/// - TypeRef: `(rid << 2) | 1`  
/// - TypeSpec: `(rid << 2) | 2`
fn encode_custom_modifier(modifier: &CustomModifier, buffer: &mut Vec<u8>) {
    let modifier_type = if modifier.is_required {
        0x1F // ELEMENT_TYPE_CMOD_REQD
    } else {
        0x20 // ELEMENT_TYPE_CMOD_OPT
    };
    buffer.push(modifier_type);

    let coded_index = encode_type_def_or_ref_coded_index(modifier.modifier_type);
    write_compressed_uint(coded_index, buffer);
}

/// Encodes a token as a TypeDefOrRef coded index according to ECMA-335 §II.24.2.6.
///
/// The TypeDefOrRef coded index encodes tokens from three possible tables:
/// - TypeDef (0x02): `(rid << 2) | 0`
/// - TypeRef (0x01): `(rid << 2) | 1`
/// - TypeSpec (0x1B): `(rid << 2) | 2`
///
/// # Arguments
///
/// * `token` - The metadata token to encode
///
/// # Returns
///
/// The TypeDefOrRef coded index value ready for compressed integer encoding.
fn encode_type_def_or_ref_coded_index(token: Token) -> u32 {
    let table_id = token.table();
    let rid = token.row();

    match table_id {
        0x02 => rid << 2,       // TypeDef
        0x01 => (rid << 2) | 1, // TypeRef
        0x1B => (rid << 2) | 2, // TypeSpec
        _ => {
            // Invalid token type for TypeDefOrRef coded index
            // For now, default to TypeRef encoding to prevent crashes
            // TODO: Return proper error when we add error handling
            (rid << 2) | 1
        }
    }
}

/// Encodes a signature parameter (including custom modifiers and byref flag) according to ECMA-335.
///
/// Parameters are encoded as:
/// - Custom modifiers (if any)
/// - BYREF marker (0x10) if parameter is by-reference
/// - The parameter type
///
/// # Arguments
///
/// * `parameter` - The signature parameter to encode
/// * `buffer` - The output buffer to write the encoded parameter to
///
/// # ECMA-335 Reference
///
/// According to ECMA-335 §II.23.2.1, parameters are encoded as:
/// ```text
/// Param ::= CustomMod* [BYREF] Type
/// ```
fn encode_parameter(parameter: &SignatureParameter, buffer: &mut Vec<u8>) -> Result<()> {
    for modifier in &parameter.modifiers {
        encode_custom_modifier(modifier, buffer);
    }

    // Encode BYREF marker if this is a by-reference parameter
    if parameter.by_ref {
        buffer.push(0x10); // ELEMENT_TYPE_BYREF
    }

    TypeSignatureEncoder::encode_type_signature(&parameter.base, buffer)?;

    Ok(())
}

/// Encodes a method signature into binary format according to ECMA-335.
///
/// Method signatures encode:
/// - Calling convention byte
/// - Parameter count (compressed integer)
/// - Return type (using TypeSignatureEncoder)
/// - Parameter types (using TypeSignatureEncoder for each)
///
/// # Arguments
///
/// * `signature` - The method signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded method signature.
///
/// # Errors
///
/// Returns an error if encoding any parameter or return type fails, typically due to:
/// - Invalid type signature structures
/// - Unsupported type encodings
/// - Issues with type reference tokens
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::signatures::*;
///
/// let signature = MethodSignatureBuilder::new()
///     .calling_convention_default()
///     .returns(TypeSignature::Void)
///     .param(TypeSignature::I4)
///     .build()?;
///
/// let encoded = encode_method_signature(&signature)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_method_signature(signature: &SignatureMethod) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    let mut calling_convention = 0x00; // DEFAULT
    if signature.vararg {
        calling_convention = 0x05; // VARARG
    } else if signature.cdecl {
        calling_convention = 0x01; // C
    } else if signature.default {
        calling_convention = 0x00; // DEFAULT
    }

    // Add HASTHIS flag if this is an instance method
    if signature.has_this {
        calling_convention |= 0x20; // HASTHIS
    }

    // Add EXPLICITTHIS flag if explicit this parameter
    if signature.explicit_this {
        calling_convention |= 0x40; // EXPLICITTHIS
    }

    buffer.push(calling_convention);

    let param_count =
        u32::try_from(signature.params.len()).map_err(|_| Error::ModificationInvalidOperation {
            details: format!(
                "Too many parameters in method signature: {}",
                signature.params.len()
            ),
        })?;
    write_compressed_uint(param_count, &mut buffer);

    encode_parameter(&signature.return_type, &mut buffer)?;
    for param in &signature.params {
        encode_parameter(param, &mut buffer)?;
    }

    Ok(buffer)
}

/// Encodes a field signature into binary format according to ECMA-335.
///
/// Field signatures encode:
/// - Field signature prolog (0x06)
/// - Custom modifiers (if any)
/// - Field type (using TypeSignatureEncoder)
///
/// # Arguments
///
/// * `signature` - The field signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded field signature.
///
/// # Errors
///
/// Returns an error if encoding the field type fails, typically due to:
/// - Invalid type signature structures
/// - Unsupported type encodings
/// - Issues with type reference tokens
pub fn encode_field_signature(signature: &SignatureField) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    buffer.push(0x06); // FIELD signature marker

    // Encode custom modifiers before the field type
    // Custom modifiers are applied in sequence and evaluated right-to-left
    for modifier in &signature.modifiers {
        encode_custom_modifier(modifier, &mut buffer);
    }

    TypeSignatureEncoder::encode_type_signature(&signature.base, &mut buffer)?;

    Ok(buffer)
}

/// Encodes a property signature into binary format according to ECMA-335.
///
/// Property signatures encode:
/// - Property signature prolog (0x08 | HASTHIS if instance property)
/// - Parameter count (compressed integer)
/// - Property type (using TypeSignatureEncoder)
/// - Index parameter types (for indexers)
///
/// # Arguments
///
/// * `signature` - The property signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded property signature.
///
/// # Errors
///
/// Returns an error if encoding the property type or any parameter fails, typically due to:
/// - Invalid type signature structures
/// - Unsupported type encodings
/// - Issues with type reference tokens
/// - Too many parameters (exceeds u32 range)
pub fn encode_property_signature(signature: &SignatureProperty) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    let mut prolog = 0x08; // PROPERTY signature marker
    if signature.has_this {
        prolog |= 0x20; // HASTHIS flag
    }
    buffer.push(prolog);

    let param_count =
        u32::try_from(signature.params.len()).map_err(|_| Error::ModificationInvalidOperation {
            details: format!(
                "Too many parameters in property signature: {}",
                signature.params.len()
            ),
        })?;
    write_compressed_uint(param_count, &mut buffer);

    // Encode custom modifiers before the property type
    // Property signatures can have custom modifiers on the property type itself
    // (similar to field signatures). The encoding follows the same ECMA-335 rules.
    for modifier in &signature.modifiers {
        encode_custom_modifier(modifier, &mut buffer);
    }

    TypeSignatureEncoder::encode_type_signature(&signature.base, &mut buffer)?;

    for param in &signature.params {
        encode_parameter(param, &mut buffer)?;
    }

    Ok(buffer)
}

/// Encodes a local variable signature into binary format according to ECMA-335.
///
/// Local variable signatures encode:
/// - Local variable signature prolog (0x07)
/// - Local variable count (compressed integer)
/// - Local variable types with modifiers
///
/// # Arguments
///
/// * `signature` - The local variable signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded local variable signature.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - Local variable count exceeds u32 range
/// - Type signature encoding fails
pub fn encode_local_var_signature(signature: &SignatureLocalVariables) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    buffer.push(0x07); // LOCAL_SIG signature marker

    write_compressed_uint(
        u32::try_from(signature.locals.len()).map_err(|_| {
            Error::Error(format!(
                "LocalVar signature has too many locals: {}",
                signature.locals.len()
            ))
        })?,
        &mut buffer,
    );

    for local in &signature.locals {
        if local.is_pinned {
            buffer.push(0x45); // PINNED modifier
        }

        if local.is_byref {
            buffer.push(0x10); // BYREF modifier
        }

        TypeSignatureEncoder::encode_type_signature(&local.base, &mut buffer)?;
    }

    Ok(buffer)
}

/// Encodes a type specification signature into binary format according to ECMA-335.
///
/// Type specification signatures directly encode complex type signatures using
/// the existing TypeSignatureEncoder foundation.
///
/// # Arguments
///
/// * `signature` - The type specification signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded type specification signature.
///
/// # Errors
///
/// Returns [`crate::Error`] if type signature encoding fails.
pub fn encode_typespec_signature(signature: &SignatureTypeSpec) -> Result<Vec<u8>> {
    TypeSignatureEncoder::encode(&signature.base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::signatures::{
        FieldSignatureBuilder, LocalVariableSignatureBuilder, MethodSignatureBuilder,
        PropertySignatureBuilder, TypeSignature, TypeSpecSignatureBuilder,
    };

    #[test]
    fn test_encode_method_signature() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .returns(TypeSignature::Void)
            .param(TypeSignature::I4)
            .build()
            .unwrap();

        let result = encode_method_signature(&signature);
        assert!(result.is_ok(), "Method signature encoding should succeed");

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Basic structure check: should have calling convention + param count + return type + param type
        assert!(
            encoded.len() >= 3,
            "Encoded signature should have minimum structure"
        );
    }

    #[test]
    fn test_encode_field_signature() {
        let signature = FieldSignatureBuilder::new()
            .field_type(TypeSignature::String)
            .build()
            .unwrap();

        let result = encode_field_signature(&signature);
        assert!(result.is_ok(), "Field signature encoding should succeed");

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Should start with field signature marker (0x06)
        assert_eq!(encoded[0], 0x06, "Field signature should start with 0x06");
    }

    #[test]
    fn test_encode_property_signature() {
        let signature = PropertySignatureBuilder::new()
            .property_type(TypeSignature::I4)
            .build()
            .unwrap();

        let result = encode_property_signature(&signature);
        assert!(result.is_ok(), "Property signature encoding should succeed");

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Should start with property signature marker (0x08)
        assert_eq!(
            encoded[0], 0x08,
            "Property signature should start with 0x08"
        );
    }

    #[test]
    fn test_encode_local_var_signature() {
        let signature = LocalVariableSignatureBuilder::new()
            .add_local(TypeSignature::I4)
            .add_pinned_local(TypeSignature::String)
            .build()
            .unwrap();

        let result = encode_local_var_signature(&signature);
        assert!(
            result.is_ok(),
            "Local variable signature encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Should start with local signature marker (0x07)
        assert_eq!(
            encoded[0], 0x07,
            "Local variable signature should start with 0x07"
        );
    }

    #[test]
    fn test_encode_typespec_signature() {
        let signature = TypeSpecSignatureBuilder::new()
            .type_signature(TypeSignature::String)
            .build()
            .unwrap();

        let result = encode_typespec_signature(&signature);
        assert!(
            result.is_ok(),
            "Type specification signature encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");
    }

    #[test]
    fn test_encode_custom_modifier() {
        use crate::metadata::signatures::CustomModifier;
        use crate::metadata::token::Token;

        let mut buffer = Vec::new();

        // Test optional modifier encoding
        let optional_modifier = CustomModifier {
            is_required: false,
            modifier_type: Token::new(0x01000001), // TypeRef token (table 0x01, RID 1)
        };
        encode_custom_modifier(&optional_modifier, &mut buffer);

        // Should encode as: 0x20 (ELEMENT_TYPE_CMOD_OPT) + TypeDefOrRef coded index
        assert_eq!(buffer[0], 0x20, "Optional modifier should start with 0x20");
        assert!(buffer.len() > 1, "Modifier should include coded index");

        // Test required modifier encoding
        buffer.clear();
        let required_modifier = CustomModifier {
            is_required: true,
            modifier_type: Token::new(0x01000001),
        };
        encode_custom_modifier(&required_modifier, &mut buffer);

        // Should encode as: 0x1F (ELEMENT_TYPE_CMOD_REQD) + TypeDefOrRef coded index
        assert_eq!(buffer[0], 0x1F, "Required modifier should start with 0x1F");
        assert!(buffer.len() > 1, "Modifier should include coded index");
    }

    #[test]
    fn test_encode_type_def_or_ref_coded_index() {
        use crate::metadata::token::Token;

        // Test TypeDef token (table 0x02)
        let typedef_token = Token::new(0x02000001); // TypeDef table, RID 1
        let coded_index = encode_type_def_or_ref_coded_index(typedef_token);
        assert_eq!(coded_index, 1 << 2, "TypeDef should encode as (rid << 2)");

        // Test TypeRef token (table 0x01)
        let typeref_token = Token::new(0x01000005); // TypeRef table, RID 5
        let coded_index = encode_type_def_or_ref_coded_index(typeref_token);
        assert_eq!(
            coded_index,
            (5 << 2) | 1,
            "TypeRef should encode as (rid << 2) | 1"
        );

        // Test TypeSpec token (table 0x1B)
        let typespec_token = Token::new(0x1B000003); // TypeSpec table, RID 3
        let coded_index = encode_type_def_or_ref_coded_index(typespec_token);
        assert_eq!(
            coded_index,
            (3 << 2) | 2,
            "TypeSpec should encode as (rid << 2) | 2"
        );
    }
}
