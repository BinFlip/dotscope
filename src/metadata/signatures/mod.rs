//! Method and type signature parsing for .NET metadata.
//!
//! This module provides comprehensive parsing of .NET metadata signatures according to
//! the ECMA-335 standard. Signatures encode type information, method parameters,
//! generic constraints, and calling conventions in a compact binary format.
//!
//! # Signature Types
//!
//! The .NET metadata format defines several signature types, each with specific purposes:
//!
//! - **Method Signatures** - Parameter types, return types, and calling conventions
//! - **Field Signatures** - Field type information and modifiers
//! - **Property Signatures** - Property type and parameter information
//! - **LocalVar Signatures** - Local variable types within method bodies
//! - **TypeSpec Signatures** - Generic type instantiations and complex type references
//!
//! # Binary Format
//!
//! Signatures use a compressed binary encoding with the following characteristics:
//! - Calling conventions encoded as single bytes
//! - Parameter counts using compressed integers
//! - Type references using element type tokens
//! - Generic parameters encoded with positional indices
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::signatures::parse_method_signature;
//!
//! // Parse a method signature from blob data
//! let signature_data = &[0x20, 0x01, 0x01, 0x0E]; // Example signature bytes
//! let method_sig = parse_method_signature(signature_data)?;
//!
//! println!("Method Body {:?}", method_sig);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ```rust,no_run
//! use dotscope::metadata::signatures::parse_local_var_signature;
//!
//! // Parse local variable signature
//! let locals_data = &[0x07, 0x02, 0x08, 0x0E]; // 2 locals: int32, string
//! let locals_sig = parse_local_var_signature(locals_data)?;
//!
//! for (i, local_type) in locals_sig.locals.iter().enumerate() {
//!     println!("Local {}: {:?}", i, local_type);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Implementation Notes
//!
//! - All signatures begin with a calling convention or signature type byte
//! - Complex types (arrays, generics) use recursive encoding
//! - Custom modifiers (modreq/modopt) are encoded inline with type information
//! - Generic type parameters reference their declaring type or method
//!
//! # References
//!
//! - ECMA-335 6th Edition, Partition II, Section 23.2 - Blobs and Signatures
//! - ECMA-335 6th Edition, Partition II, Section 23.1 - Metadata Validation

mod parser;
mod types;

pub use parser::*;
pub use types::*;

use crate::Result;

/// Parse a `MethodSignature` from a byte slice
///
/// ## Arguments
/// * 'data' - The input slice to parse
///
/// # Errors
/// Returns an error if the signature data is malformed or parsing fails
pub fn parse_method_signature(data: &[u8]) -> Result<SignatureMethod> {
    let mut parser = SignatureParser::new(data);
    parser.parse_method_signature()
}

/// Parse a `FieldSignature` from a byte slice
///
/// ## Arguments
/// * 'data' - The input slice to parse
///
/// # Errors
/// Returns an error if the signature data is malformed or parsing fails
pub fn parse_field_signature(data: &[u8]) -> Result<SignatureField> {
    let mut parser = SignatureParser::new(data);
    parser.parse_field_signature()
}

/// Parse a `PropertySignature` from a byte slice
///
/// ## Arguments
/// * 'data' - The input slice to parse
///
/// # Errors
/// Returns an error if the signature data is malformed or parsing fails
pub fn parse_property_signature(data: &[u8]) -> Result<SignatureProperty> {
    let mut parser = SignatureParser::new(data);
    parser.parse_property_signature()
}

/// Parse a `LocalVarSignature` from a byte slice
///
/// ## Arguments
/// * 'data' - The input slice to parse
///
/// # Errors
/// Returns an error if the signature data is malformed or parsing fails
pub fn parse_local_var_signature(data: &[u8]) -> Result<SignatureLocalVariables> {
    let mut parser = SignatureParser::new(data);
    parser.parse_local_var_signature()
}

/// Parse a `TypeSpecSignature` from a byte slice
///
/// ## Arguments
/// * 'data' - The input slice to parse
///
/// # Errors
/// Returns an error if the signature data is malformed or parsing fails
pub fn parse_type_spec_signature(data: &[u8]) -> Result<SignatureTypeSpec> {
    let mut parser = SignatureParser::new(data);
    parser.parse_type_spec_signature()
}

/// Parse a `MethodSpecSignature` from a byte slice
///
/// ## Arguments
/// * 'data' - The input slice to parse
///
/// # Errors
/// Returns an error if the signature data is malformed or parsing fails
pub fn parse_method_spec_signature(data: &[u8]) -> Result<SignatureMethodSpec> {
    let mut parser = SignatureParser::new(data);
    parser.parse_method_spec_signature()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::token::Token;

    #[test]
    fn test_parse_method_signature() {
        // Simple method: void Method()
        let result = parse_method_signature(&[
            0x00, // DEFAULT
            0x00, // 0 parameters
            0x01, // VOID return
        ])
        .unwrap();
        assert_eq!(result.params.len(), 0);
        assert_eq!(result.return_type.base, TypeSignature::Void);
        assert!(!result.has_this);

        // Instance method with parameters: int Method(string s, ref int[] numbers)
        let result = parse_method_signature(&[
            0x20, // HASTHIS
            0x02, // 2 parameters
            0x08, // I4 return
            0x0E, // String (first param)
            0x10, 0x1D, 0x08, // BYREF SZARRAY I4 (second param: ref int[])
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.params.len(), 2);
        // Check return type
        assert_eq!(result.return_type.base, TypeSignature::I4);
        // Check first parameter (string)
        assert_eq!(result.params[0].base, TypeSignature::String);
        assert!(!result.params[0].by_ref);
        // Check second parameter (ref int[])
        assert!(result.params[1].by_ref);
        assert!(matches!(result.params[1].base, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = &result.params[1].base {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // Generic method: T Method<T>(T item)
        let result = parse_method_signature(&[
            0x30, // HASTHIS | GENERIC
            0x01, // 1 generic parameter
            0x01, // 1 method parameter
            0x13, 0x00, // GenericParam(0) - return type is T
            0x13, 0x00, // GenericParam(0) - parameter type is T
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.param_count_generic, 1);
        assert_eq!(result.params.len(), 1);
        // Check return type is T (generic param 0)
        assert_eq!(result.return_type.base, TypeSignature::GenericParamType(0));
        // Check parameter type is also T
        assert_eq!(result.params[0].base, TypeSignature::GenericParamType(0));
    }

    #[test]
    fn test_parse_field_signature() {
        // Simple field: int field
        let result = parse_field_signature(&[
            0x06, // FIELD
            0x08, // I4
        ])
        .unwrap();
        assert_eq!(result.base, TypeSignature::I4);
        assert!(result.modifiers.is_empty());

        // Field with custom modifier: modreq(IsConst) int field
        let result = parse_field_signature(&[
            0x06, // FIELD
            0x1F, 0x42, // CMOD_REQD, token 0x1B000010 (IsConst)
            0x08, // I4
        ])
        .unwrap();
        assert_eq!(result.base, TypeSignature::I4);
        assert_eq!(result.modifiers, vec![Token::new(0x1B000010)]);

        // Array field: string[] field
        let result = parse_field_signature(&[
            0x06, // FIELD
            0x1D, 0x0E, // SZARRAY, String
        ])
        .unwrap();
        assert!(matches!(result.base, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = result.base {
            assert_eq!(*inner.base, TypeSignature::String);
        }
    }

    #[test]
    fn test_parse_property_signature() {
        // Simple property: int Property { get; set; }
        let result = parse_property_signature(&[
            0x28, // PROPERTY | HASTHIS
            0x00, // 0 parameters
            0x08, // I4
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.base, TypeSignature::I4);
        assert!(result.params.is_empty());

        // Indexed property: string this[int index] { get; set; }
        let result = parse_property_signature(&[
            0x28, // PROPERTY | HASTHIS
            0x01, // 1 parameter
            0x0E, // String return type
            0x08, // I4 parameter type
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.base, TypeSignature::String);
        assert_eq!(result.params.len(), 1);
        assert_eq!(result.params[0].base, TypeSignature::I4);
    }

    #[test]
    fn test_parse_local_var_signature() {
        // Local variables: int a; string b;
        let result = parse_local_var_signature(&[
            0x07, // LOCAL_SIG
            0x02, // 2 variables
            0x08, // I4
            0x0E, // String
        ])
        .unwrap();
        assert_eq!(result.locals.len(), 2);
        assert_eq!(result.locals[0].base, TypeSignature::I4);
        assert_eq!(result.locals[1].base, TypeSignature::String);

        // Local variables with byref and pinned: ref int a; pinned string b;
        let result = parse_local_var_signature(&[
            0x07, // LOCAL_SIG
            0x02, // 2 variables
            0x10, 0x08, // BYREF I4
            0x45, 0x0E, // PINNED String
        ])
        .unwrap();
        assert_eq!(result.locals.len(), 2);
        // Check first local is ref int
        assert!(result.locals[0].is_byref);
        assert!(!result.locals[0].is_pinned);
        assert_eq!(result.locals[0].base, TypeSignature::I4);
        // Check second local is pinned string
        assert!(!result.locals[1].is_byref);
        assert!(result.locals[1].is_pinned);
        assert_eq!(result.locals[1].base, TypeSignature::String);
    }

    #[test]
    fn test_parse_type_spec_signature() {
        // TypeSpec: List<int>
        let result = parse_type_spec_signature(&[
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // 1 arg count
            0x08, // I4 type arg
        ])
        .unwrap();
        assert!(matches!(result.base, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = result.base {
            assert!(matches!(*class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_method_spec_signature() {
        // MethodSpec: Method<int, string>
        let result = parse_method_spec_signature(&[
            0x0A, // METHOD_SPEC
            0x02, // 2 type args
            0x08, // I4
            0x0E, // String
        ])
        .unwrap();
        assert_eq!(result.generic_args.len(), 2);
        assert_eq!(result.generic_args[0], TypeSignature::I4);
        assert_eq!(result.generic_args[1], TypeSignature::String);
    }
}
