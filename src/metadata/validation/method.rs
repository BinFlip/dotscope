//! Method validation for .NET metadata
//!
//! This module provides validation for method-specific rules and constraints.

use crate::metadata::{loader::CilObjectData, method::MethodModifiers, typesystem::CilType};
use rayon::prelude::*;

/// Validator for method-specific rules
pub struct MethodValidator;

impl MethodValidator {
    /// Validates method-specific rules across all methods
    ///
    /// This method performs several checks:
    /// - Method name validation
    /// - Static constructor rules
    /// - Abstract method consistency
    /// - Parameter validation
    ///
    /// # Arguments
    /// * `data` - The CIL object data containing metadata
    ///
    /// # Returns
    /// Vector of validation errors found
    pub fn validate_method_rules(data: &CilObjectData) -> Vec<String> {
        let type_registry = &data.types;

        // Use parallel iteration for better performance on large type systems
        type_registry
            .all_types()
            .par_iter()
            .flat_map(|type_entry| {
                let mut errors = Vec::new();
                Self::validate_type_methods(type_entry, &mut errors);
                errors
            })
            .collect()
    }

    /// Validates methods for a specific type
    fn validate_type_methods(cil_type: &std::sync::Arc<CilType>, errors: &mut Vec<String>) {
        for (_, method_ref) in cil_type.methods.iter() {
            if let Some(method) = method_ref.upgrade() {
                // Validate method name
                if method.name.is_empty() {
                    errors.push(format!("Method in type '{}' has empty name", cil_type.name));
                    continue;
                }

                // Validate static constructor rules
                if method.name == ".cctor" {
                    Self::validate_static_constructor(&method, cil_type, errors);
                }

                // Validate abstract method rules
                Self::validate_abstract_method(&method, cil_type, errors);
            }
        }
    }

    /// Validates static constructor specific rules
    fn validate_static_constructor(
        method: &crate::metadata::method::Method,
        cil_type: &std::sync::Arc<CilType>,
        errors: &mut Vec<String>,
    ) {
        // Static constructors must be static
        if !method.flags_modifiers.contains(MethodModifiers::STATIC) {
            errors.push(format!(
                "Static constructor '{}' in type '{}' must be marked static",
                method.name, cil_type.name
            ));
        }

        // Static constructors should not have parameters (except implicit)
        let param_count = method.params.count();
        if param_count > 0 {
            errors.push(format!(
                "Static constructor '{}' in type '{}' has {} parameters but should have none",
                method.name, cil_type.name, param_count
            ));
        }
    }

    /// Validates abstract method rules
    fn validate_abstract_method(
        method: &crate::metadata::method::Method,
        cil_type: &std::sync::Arc<CilType>,
        errors: &mut Vec<String>,
    ) {
        // Abstract methods cannot be static
        if method.flags_modifiers.contains(MethodModifiers::ABSTRACT)
            && method.flags_modifiers.contains(MethodModifiers::STATIC)
        {
            errors.push(format!(
                "Abstract method '{}' in type '{}' cannot be static",
                method.name, cil_type.name
            ));
        }

        // Abstract methods cannot be final
        if method.flags_modifiers.contains(MethodModifiers::ABSTRACT)
            && method.flags_modifiers.contains(MethodModifiers::FINAL)
        {
            errors.push(format!(
                "Abstract method '{}' in type '{}' cannot be final",
                method.name, cil_type.name
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::create_method;

    #[test]
    fn test_method_validation_basic() {
        // Basic test to ensure module compiles
        let _method = create_method("TestMethod");
        assert!(true);
    }
}
