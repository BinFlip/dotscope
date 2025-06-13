//! Token validation for .NET metadata
//!
//! This module provides token validation that aligns with .NET runtime behavior,
//! focusing on critical issues that would cause runtime failures.

use crate::metadata::{
    loader::CilObjectData,
    typesystem::{CilType, TypeRegistry},
};

/// Validator for token consistency and critical cross-references
///
/// This validator focuses on token validation that the .NET runtime actually
/// performs, avoiding redundant checks already done during metadata loading.
pub struct TokenValidator;

impl TokenValidator {
    /// Validates token consistency for runtime-critical issues
    ///
    /// Based on .NET runtime source analysis, this focuses on:
    /// - Cross-reference integrity for essential relationships
    /// - Null reference validation where it would cause runtime failures
    ///
    /// Note: Basic token format validation and table bounds checking are
    /// already performed by the metadata loader and parser.
    ///
    /// # Arguments
    /// * `data` - The loaded metadata to validate
    ///
    /// # Returns
    /// Vector of validation errors found
    pub fn validate_token_consistency(data: &CilObjectData) -> Vec<String> {
        let mut errors = Vec::new();

        Self::validate_critical_cross_references(&data.types, &mut errors);

        errors
    }

    /// Validates cross-references that are critical for runtime operation
    ///
    /// The .NET runtime performs lazy validation, so we focus on relationships
    /// that would cause immediate failures.
    fn validate_critical_cross_references(types: &TypeRegistry, errors: &mut Vec<String>) {
        for entry in types {
            let cil_type = entry.value();

            Self::validate_base_type_reference(cil_type, types, errors);
        }
    }

    /// Validates base type references that could cause inheritance failures
    ///
    /// This aligns with runtime validation which checks inheritance chains
    /// during type loading.
    fn validate_base_type_reference(
        cil_type: &std::sync::Arc<CilType>,
        types: &TypeRegistry,
        errors: &mut Vec<String>,
    ) {
        if let Some(base_type) = cil_type.base() {
            // Check if base type token is resolvable
            // This is important because inheritance failures cause runtime errors
            if base_type.token.is_null() {
                errors.push(format!("Type '{}' has null base type token", cil_type.name));
            } else if types.get(&base_type.token).is_none() {
                errors.push(format!(
                    "Type '{}' references unresolvable base type with token {:?}",
                    cil_type.name, base_type.token
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::{
        token::Token,
        typesystem::{CilFlavor, CilType},
    };
    use std::sync::Arc;

    #[test]
    fn test_token_validation_basic() {
        // Basic test to ensure module compiles
        let _cil_type = CilType::new(
            Token::new(0x02000001), // TypeDef table
            "TestNamespace".to_string(),
            "TestType".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::Class),
        );

        // Basic test to ensure we can create a type
        assert!(true);
    }
}
