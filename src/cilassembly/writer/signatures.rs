//! Signature blob token remapping for metadata generation.
//!
//! This module provides functionality to remap TypeDef and TypeRef tokens embedded
//! within signature blobs. When TypeDef or TypeRef rows are deleted and RIDs shift,
//! the tokens in signatures (StandAloneSig, MethodSig, FieldSig, etc.) become stale
//! and must be updated to reference the correct new RIDs.
//!
//! # Design
//!
//! This module leverages the existing signature parsing and encoding infrastructure:
//! 1. Parse the signature blob using `parse_*_signature()` functions
//! 2. Walk the parsed structure and remap TypeDef/TypeRef tokens
//! 3. Re-encode using `encode_*_signature()` functions
//!
//! This approach is more robust than manual byte manipulation because it uses
//! the same parsing/encoding logic that the rest of the codebase uses.

use std::collections::HashMap;

use crate::{
    metadata::{
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_property_signature, encode_typespec_signature, parse_field_signature,
            parse_local_var_signature, parse_method_signature, parse_property_signature,
            parse_type_spec_signature, CustomModifier, SignatureArray, SignatureField,
            SignatureLocalVariable, SignatureLocalVariables, SignatureMethod, SignatureParameter,
            SignaturePointer, SignatureProperty, SignatureSzArray, SignatureTypeSpec,
            TypeSignature, CALLING_CONVENTION, SIGNATURE_HEADER,
        },
        token::Token,
    },
    Result,
};

/// Remaps TypeDef and TypeRef tokens in a signature blob.
///
/// This function parses the signature blob, finds all embedded TypeDef and TypeRef
/// tokens, and remaps them using the provided RID mappings. The signature is then
/// re-encoded with the updated tokens.
///
/// # Arguments
///
/// * `signature` - The original signature blob bytes
/// * `typedef_remap` - Mapping from old TypeDef RIDs to new RIDs
/// * `typeref_remap` - Mapping from old TypeRef RIDs to new RIDs
///
/// # Returns
///
/// A new `Vec<u8>` containing the remapped signature, or `None` if the signature
/// contains no TypeDef/TypeRef references that need remapping.
///
/// # Errors
///
/// Returns an error if the signature is malformed and cannot be parsed.
pub fn remap_signature_tokens(
    signature: &[u8],
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> Result<Option<Vec<u8>>> {
    if signature.is_empty() || (typedef_remap.is_empty() && typeref_remap.is_empty()) {
        return Ok(None);
    }

    // Determine signature type from header byte
    let header = signature[0];

    // Check for signature type markers
    if header == SIGNATURE_HEADER::LOCAL_SIG {
        // LocalVarSig
        let mut parsed = parse_local_var_signature(signature)?;
        if remap_local_var_signature(&mut parsed, typedef_remap, typeref_remap) {
            return Ok(Some(encode_local_var_signature(&parsed)?));
        }
    } else if header == SIGNATURE_HEADER::FIELD {
        // FieldSig
        let mut parsed = parse_field_signature(signature)?;
        if remap_field_signature(&mut parsed, typedef_remap, typeref_remap) {
            return Ok(Some(encode_field_signature(&parsed)?));
        }
    } else if (header & 0x0F) == SIGNATURE_HEADER::PROPERTY
        || header == SIGNATURE_HEADER::PROPERTY
        || header == (SIGNATURE_HEADER::PROPERTY | CALLING_CONVENTION::HASTHIS)
    {
        // PropertySig (0x08 or 0x28 with HASTHIS)
        let mut parsed = parse_property_signature(signature)?;
        if remap_property_signature(&mut parsed, typedef_remap, typeref_remap) {
            return Ok(Some(encode_property_signature(&parsed)?));
        }
    } else if header == 0x0A {
        // MethodSpec - GENERICINST header
        // MethodSpec signatures are type argument lists, handled via TypeSpec path
        // For now, try parsing as TypeSpec since they're similar
        if let Ok(mut parsed) = parse_type_spec_signature(signature) {
            if remap_type_spec_signature(&mut parsed, typedef_remap, typeref_remap) {
                return Ok(Some(encode_typespec_signature(&parsed)?));
            }
        }
    } else {
        // Try as MethodSig (calling convention in low bits)
        // Method signatures start with calling convention flags
        let calling_convention = header & 0x0F;
        if calling_convention <= 0x05 || (header & CALLING_CONVENTION::GENERIC) != 0 {
            if let Ok(mut parsed) = parse_method_signature(signature) {
                if remap_method_signature(&mut parsed, typedef_remap, typeref_remap) {
                    return Ok(Some(encode_method_signature(&parsed)?));
                }
                // If parsing succeeded but no remapping needed
                return Ok(None);
            }
        }

        // Fall back to TypeSpec parsing for complex types
        if let Ok(mut parsed) = parse_type_spec_signature(signature) {
            if remap_type_spec_signature(&mut parsed, typedef_remap, typeref_remap) {
                return Ok(Some(encode_typespec_signature(&parsed)?));
            }
        }
    }

    Ok(None)
}

/// Remaps tokens in a local variable signature.
/// Returns true if any tokens were remapped.
fn remap_local_var_signature(
    sig: &mut SignatureLocalVariables,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for local in &mut sig.locals {
        if remap_local_variable(local, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    modified
}

/// Remaps tokens in a single local variable.
fn remap_local_variable(
    local: &mut SignatureLocalVariable,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for modifier in &mut local.modifiers {
        if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    if remap_type_signature(&mut local.base, typedef_remap, typeref_remap) {
        modified = true;
    }
    modified
}

/// Remaps tokens in a field signature.
fn remap_field_signature(
    sig: &mut SignatureField,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for modifier in &mut sig.modifiers {
        if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    if remap_type_signature(&mut sig.base, typedef_remap, typeref_remap) {
        modified = true;
    }
    modified
}

/// Remaps tokens in a property signature.
fn remap_property_signature(
    sig: &mut SignatureProperty,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for modifier in &mut sig.modifiers {
        if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    if remap_type_signature(&mut sig.base, typedef_remap, typeref_remap) {
        modified = true;
    }
    for param in &mut sig.params {
        if remap_parameter(param, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    modified
}

/// Remaps tokens in a method signature.
fn remap_method_signature(
    sig: &mut SignatureMethod,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    if remap_parameter(&mut sig.return_type, typedef_remap, typeref_remap) {
        modified = true;
    }
    for param in &mut sig.params {
        if remap_parameter(param, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    modified
}

/// Remaps tokens in a type spec signature.
fn remap_type_spec_signature(
    sig: &mut SignatureTypeSpec,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    remap_type_signature(&mut sig.base, typedef_remap, typeref_remap)
}

/// Remaps tokens in a parameter.
fn remap_parameter(
    param: &mut SignatureParameter,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for modifier in &mut param.modifiers {
        if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    if remap_type_signature(&mut param.base, typedef_remap, typeref_remap) {
        modified = true;
    }
    modified
}

/// Remaps tokens in a custom modifier.
fn remap_custom_modifier(
    modifier: &mut CustomModifier,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    remap_token(&mut modifier.modifier_type, typedef_remap, typeref_remap)
}

/// Remaps tokens in a type signature recursively.
fn remap_type_signature(
    sig: &mut TypeSignature,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    match sig {
        // Types with embedded tokens
        TypeSignature::Class(token) | TypeSignature::ValueType(token) => {
            remap_token(token, typedef_remap, typeref_remap)
        }

        // Recursive types
        TypeSignature::SzArray(arr) => remap_szarray(arr, typedef_remap, typeref_remap),
        TypeSignature::Array(arr) => remap_array(arr, typedef_remap, typeref_remap),
        TypeSignature::Ptr(ptr) => remap_pointer(ptr, typedef_remap, typeref_remap),
        TypeSignature::ByRef(inner) => remap_type_signature(inner, typedef_remap, typeref_remap),
        TypeSignature::Pinned(inner) => remap_type_signature(inner, typedef_remap, typeref_remap),

        // Generic instantiation - base type + type arguments
        TypeSignature::GenericInst(base, args) => {
            let mut modified = remap_type_signature(base, typedef_remap, typeref_remap);
            for arg in args {
                if remap_type_signature(arg, typedef_remap, typeref_remap) {
                    modified = true;
                }
            }
            modified
        }

        // Custom modifiers (just contain modifier tokens, no nested type)
        TypeSignature::ModifiedRequired(modifiers) | TypeSignature::ModifiedOptional(modifiers) => {
            let mut modified = false;
            for modifier in modifiers {
                if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
                    modified = true;
                }
            }
            modified
        }

        // Function pointer - method signature embedded
        TypeSignature::FnPtr(method_sig) => {
            remap_method_signature(method_sig, typedef_remap, typeref_remap)
        }

        // Primitive and simple types - no tokens to remap
        TypeSignature::Void
        | TypeSignature::Boolean
        | TypeSignature::Char
        | TypeSignature::I1
        | TypeSignature::U1
        | TypeSignature::I2
        | TypeSignature::U2
        | TypeSignature::I4
        | TypeSignature::U4
        | TypeSignature::I8
        | TypeSignature::U8
        | TypeSignature::R4
        | TypeSignature::R8
        | TypeSignature::I
        | TypeSignature::U
        | TypeSignature::String
        | TypeSignature::Object
        | TypeSignature::TypedByRef
        | TypeSignature::GenericParamType(_)
        | TypeSignature::GenericParamMethod(_)
        | TypeSignature::Sentinel
        | TypeSignature::Internal
        | TypeSignature::Unknown
        | TypeSignature::Type
        | TypeSignature::Boxed
        | TypeSignature::Field
        | TypeSignature::Modifier
        | TypeSignature::Reserved => false,
    }
}

/// Remaps tokens in an szarray.
fn remap_szarray(
    arr: &mut SignatureSzArray,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for modifier in &mut arr.modifiers {
        if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    if remap_type_signature(&mut arr.base, typedef_remap, typeref_remap) {
        modified = true;
    }
    modified
}

/// Remaps tokens in an array.
fn remap_array(
    arr: &mut SignatureArray,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    remap_type_signature(&mut arr.base, typedef_remap, typeref_remap)
}

/// Remaps tokens in a pointer.
fn remap_pointer(
    ptr: &mut SignaturePointer,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    let mut modified = false;
    for modifier in &mut ptr.modifiers {
        if remap_custom_modifier(modifier, typedef_remap, typeref_remap) {
            modified = true;
        }
    }
    if remap_type_signature(&mut ptr.base, typedef_remap, typeref_remap) {
        modified = true;
    }
    modified
}

/// Remaps a single token if it's a TypeDef or TypeRef that needs remapping.
/// Returns true if the token was modified.
fn remap_token(
    token: &mut Token,
    typedef_remap: &HashMap<u32, u32>,
    typeref_remap: &HashMap<u32, u32>,
) -> bool {
    const TYPEREF_TABLE: u8 = 0x01;
    const TYPEDEF_TABLE: u8 = 0x02;

    let table = token.table();
    let rid = token.row();

    if table == TYPEDEF_TABLE {
        if let Some(&new_rid) = typedef_remap.get(&rid) {
            *token = Token::new((TYPEDEF_TABLE as u32) << 24 | new_rid);
            return true;
        }
    } else if table == TYPEREF_TABLE {
        if let Some(&new_rid) = typeref_remap.get(&rid) {
            *token = Token::new((TYPEREF_TABLE as u32) << 24 | new_rid);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remap_token_typedef() {
        let mut typedef_remap = HashMap::new();
        typedef_remap.insert(5, 3);
        let typeref_remap = HashMap::new();

        // TypeDef token with RID 5
        let mut token = Token::new(0x02000005);
        assert!(remap_token(&mut token, &typedef_remap, &typeref_remap));
        assert_eq!(token.value(), 0x02000003);
    }

    #[test]
    fn test_remap_token_typeref() {
        let typedef_remap = HashMap::new();
        let mut typeref_remap = HashMap::new();
        typeref_remap.insert(5, 3);

        // TypeRef token with RID 5
        let mut token = Token::new(0x01000005);
        assert!(remap_token(&mut token, &typedef_remap, &typeref_remap));
        assert_eq!(token.value(), 0x01000003);
    }

    #[test]
    fn test_remap_token_no_match() {
        let typedef_remap = HashMap::new();
        let typeref_remap = HashMap::new();

        // TypeRef token with RID 5, but no mapping
        let mut token = Token::new(0x01000005);
        assert!(!remap_token(&mut token, &typedef_remap, &typeref_remap));
        assert_eq!(token.value(), 0x01000005);
    }

    #[test]
    fn test_remap_local_var_signature_typedef() {
        // Create a LocalVarSig with a CLASS local referencing TypeDef RID 5
        let mut sig = SignatureLocalVariables {
            locals: vec![SignatureLocalVariable {
                modifiers: vec![],
                is_pinned: false,
                is_byref: false,
                base: TypeSignature::Class(Token::new(0x02000005)),
            }],
        };

        let mut typedef_remap = HashMap::new();
        typedef_remap.insert(5, 3);
        let typeref_remap = HashMap::new();

        assert!(remap_local_var_signature(
            &mut sig,
            &typedef_remap,
            &typeref_remap
        ));

        // Verify the token was remapped
        if let TypeSignature::Class(token) = &sig.locals[0].base {
            assert_eq!(token.row(), 3);
        } else {
            panic!("Expected Class type signature");
        }
    }

    #[test]
    fn test_remap_local_var_signature_typeref() {
        // Create a LocalVarSig with a CLASS local referencing TypeRef RID 10
        let mut sig = SignatureLocalVariables {
            locals: vec![SignatureLocalVariable {
                modifiers: vec![],
                is_pinned: false,
                is_byref: false,
                base: TypeSignature::Class(Token::new(0x0100000A)),
            }],
        };

        let typedef_remap = HashMap::new();
        let mut typeref_remap = HashMap::new();
        typeref_remap.insert(10, 5);

        assert!(remap_local_var_signature(
            &mut sig,
            &typedef_remap,
            &typeref_remap
        ));

        // Verify the token was remapped
        if let TypeSignature::Class(token) = &sig.locals[0].base {
            assert_eq!(token.table(), 0x01); // Still TypeRef
            assert_eq!(token.row(), 5);
        } else {
            panic!("Expected Class type signature");
        }
    }

    #[test]
    fn test_remap_generic_inst() {
        // Create a GenericInst<TypeDef 5, I4>
        let mut sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(Token::new(0x02000005))),
            vec![TypeSignature::I4],
        );

        let mut typedef_remap = HashMap::new();
        typedef_remap.insert(5, 2);
        let typeref_remap = HashMap::new();

        assert!(remap_type_signature(
            &mut sig,
            &typedef_remap,
            &typeref_remap
        ));

        if let TypeSignature::GenericInst(base, _) = &sig {
            if let TypeSignature::Class(token) = base.as_ref() {
                assert_eq!(token.row(), 2);
            } else {
                panic!("Expected Class type signature in GenericInst");
            }
        } else {
            panic!("Expected GenericInst type signature");
        }
    }

    #[test]
    fn test_remap_generic_inst_with_typeref_arg() {
        // Create a GenericInst<TypeDef 5, TypeRef 10>
        let mut sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(Token::new(0x02000005))),
            vec![TypeSignature::Class(Token::new(0x0100000A))],
        );

        let mut typedef_remap = HashMap::new();
        typedef_remap.insert(5, 2);
        let mut typeref_remap = HashMap::new();
        typeref_remap.insert(10, 7);

        assert!(remap_type_signature(
            &mut sig,
            &typedef_remap,
            &typeref_remap
        ));

        if let TypeSignature::GenericInst(base, args) = &sig {
            if let TypeSignature::Class(token) = base.as_ref() {
                assert_eq!(token.table(), 0x02);
                assert_eq!(token.row(), 2);
            } else {
                panic!("Expected Class type signature in GenericInst");
            }
            if let TypeSignature::Class(token) = &args[0] {
                assert_eq!(token.table(), 0x01);
                assert_eq!(token.row(), 7);
            } else {
                panic!("Expected Class type signature in GenericInst arg");
            }
        } else {
            panic!("Expected GenericInst type signature");
        }
    }

    #[test]
    fn test_remap_nested_array() {
        // Create SzArray<Class<TypeDef 10>>
        let mut sig = TypeSignature::SzArray(SignatureSzArray {
            modifiers: vec![],
            base: Box::new(TypeSignature::Class(Token::new(0x0200000A))),
        });

        let mut typedef_remap = HashMap::new();
        typedef_remap.insert(10, 3);
        let typeref_remap = HashMap::new();

        assert!(remap_type_signature(
            &mut sig,
            &typedef_remap,
            &typeref_remap
        ));

        if let TypeSignature::SzArray(arr) = &sig {
            if let TypeSignature::Class(token) = arr.base.as_ref() {
                assert_eq!(token.row(), 3);
            } else {
                panic!("Expected Class in SzArray");
            }
        } else {
            panic!("Expected SzArray");
        }
    }

    #[test]
    fn test_no_remap_needed() {
        // Create a LocalVarSig with only primitive types
        let mut sig = SignatureLocalVariables {
            locals: vec![
                SignatureLocalVariable {
                    modifiers: vec![],
                    is_pinned: false,
                    is_byref: false,
                    base: TypeSignature::I4,
                },
                SignatureLocalVariable {
                    modifiers: vec![],
                    is_pinned: false,
                    is_byref: false,
                    base: TypeSignature::String,
                },
            ],
        };

        let mut typedef_remap = HashMap::new();
        typedef_remap.insert(5, 3);
        let typeref_remap = HashMap::new();

        // No TypeDef tokens, so no remapping should happen
        assert!(!remap_local_var_signature(
            &mut sig,
            &typedef_remap,
            &typeref_remap
        ));
    }
}
