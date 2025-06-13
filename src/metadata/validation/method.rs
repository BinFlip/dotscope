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
    use super::*;
    use crate::metadata::method::{MethodAccessFlags, MethodModifiers};
    use crate::metadata::signatures::TypeSignature;
    use crate::test::{CilTypeBuilder, MethodBuilder, MethodSignatureBuilder};

    fn create_int32_type() -> crate::metadata::typesystem::CilTypeRc {
        CilTypeBuilder::new()
            .with_namespace("System")
            .with_name("Int32")
            .with_flavor(crate::metadata::typesystem::CilFlavor::I4)
            .build()
    }

    #[test]
    fn test_static_constructor_validation_valid() {
        // Create a type with a valid static constructor using the convenience method
        let static_ctor = MethodBuilder::static_constructor().build();

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("TestClass")
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_static_constructor(&static_ctor, &test_type, &mut errors);

        // Should have no errors for a properly formed static constructor
        assert!(
            errors.is_empty(),
            "Valid static constructor should not generate errors: {:?}",
            errors
        );
    }

    #[test]
    fn test_static_constructor_validation_not_static() {
        // Create an invalid static constructor that's not marked static
        let invalid_static_ctor = MethodBuilder::new()
            .with_name(".cctor")
            .with_access(MethodAccessFlags::PUBLIC)
            // Missing static modifiers - this makes it invalid
            .build();

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("TestClass")
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_static_constructor(&invalid_static_ctor, &test_type, &mut errors);

        // Should generate an error for non-static static constructor
        assert!(
            !errors.is_empty(),
            "Non-static .cctor should generate validation errors"
        );
        assert!(
            errors[0].contains("must be marked static"),
            "Error should mention static requirement"
        );
    }

    #[test]
    fn test_static_constructor_with_parameters() {
        // Create a test type for the validation context
        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("TestClass")
            .build();

        // Test the validation logic with our enhanced builders that now populate
        // both signature.params and method.params
        let signature = MethodSignatureBuilder::new()
            .add_parameter("param1", TypeSignature::I4)
            .build();

        let invalid_static_ctor = MethodBuilder::static_constructor()
            .with_signature(signature)
            .build();

        // Verify that our builder created the signature correctly
        assert_eq!(
            invalid_static_ctor.signature.params.len(),
            1,
            "Builder should create signature with 1 parameter"
        );
        assert_eq!(
            invalid_static_ctor.params.count(),
            1,
            "Method params table should now be populated by builders"
        );

        // Now we can test the full validation since our builders populate both
        // signature.params and method.params
        let mut errors = Vec::new();
        MethodValidator::validate_static_constructor(&invalid_static_ctor, &test_type, &mut errors);
        assert!(
            !errors.is_empty(),
            "Static constructor with parameters should fail validation"
        );
        assert!(
            errors[0].contains("parameters"),
            "Error should mention parameters issue"
        );
    }

    #[test]
    fn test_abstract_method_validation_valid() {
        // Create a valid abstract method
        let abstract_method = MethodBuilder::new()
            .with_name("AbstractMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(MethodModifiers::ABSTRACT | MethodModifiers::VIRTUAL)
            .build();

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("AbstractClass")
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&abstract_method, &test_type, &mut errors);

        // Should have no errors for a properly formed abstract method
        assert!(
            errors.is_empty(),
            "Valid abstract method should not generate errors: {:?}",
            errors
        );
    }

    #[test]
    fn test_abstract_method_cannot_be_static() {
        // Create an invalid abstract static method
        let invalid_abstract_method = MethodBuilder::new()
            .with_name("InvalidAbstractMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(MethodModifiers::ABSTRACT | MethodModifiers::STATIC)
            .build();

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("AbstractClass")
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(
            &invalid_abstract_method,
            &test_type,
            &mut errors,
        );

        // Should generate an error for abstract static method
        assert!(
            !errors.is_empty(),
            "Abstract static method should generate validation errors"
        );
        assert!(
            errors[0].contains("cannot be static"),
            "Error should mention static restriction"
        );
    }

    #[test]
    fn test_abstract_method_cannot_be_final() {
        // Create an invalid abstract final method
        let invalid_abstract_method = MethodBuilder::new()
            .with_name("InvalidAbstractMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(MethodModifiers::ABSTRACT | MethodModifiers::FINAL)
            .build();

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("AbstractClass")
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(
            &invalid_abstract_method,
            &test_type,
            &mut errors,
        );

        // Should generate an error for abstract final method
        assert!(
            !errors.is_empty(),
            "Abstract final method should generate validation errors"
        );
        assert!(
            errors[0].contains("cannot be final"),
            "Error should mention final restriction"
        );
    }

    #[test]
    fn test_method_validation_realistic_scenarios() {
        // Test various realistic method validation scenarios using convenience methods

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("TestClass")
            .build();

        // Scenario 1: Normal instance method - should be valid
        let instance_method = MethodBuilder::new()
            .with_name("InstanceMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_signature(
                MethodSignatureBuilder::instance_method(TypeSignature::I4)
                    .add_parameter("value", TypeSignature::I4)
                    .build(),
            )
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&instance_method, &test_type, &mut errors);
        assert!(
            errors.is_empty(),
            "Normal instance method should not generate errors"
        );

        // Scenario 2: Static method - should be valid
        let static_method = MethodBuilder::new()
            .with_name("StaticMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(MethodModifiers::STATIC)
            .with_signature(MethodSignatureBuilder::static_method(TypeSignature::I4).build())
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&static_method, &test_type, &mut errors);
        assert!(
            errors.is_empty(),
            "Static method should not generate errors"
        );

        // Scenario 3: Virtual method - should be valid
        let virtual_method = MethodBuilder::new()
            .with_name("VirtualMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(MethodModifiers::VIRTUAL)
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&virtual_method, &test_type, &mut errors);
        assert!(
            errors.is_empty(),
            "Virtual method should not generate errors"
        );
    }

    #[test]
    fn test_complex_method_signatures_validation() {
        // Test methods with complex signatures using our signature builder

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("GenericClass")
            .build();

        // Generic method
        let generic_signature = MethodSignatureBuilder::new()
            .with_generic_params(1)
            .with_return_type(TypeSignature::GenericParamType(0)) // Return type is T
            .add_parameter("input", TypeSignature::GenericParamType(0)) // First param is T
            .add_parameter("list", TypeSignature::I4) // Second param (simplified)
            .build();

        let generic_method = MethodBuilder::new()
            .with_name("GenericMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_signature(generic_signature)
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&generic_method, &test_type, &mut errors);
        assert!(
            errors.is_empty(),
            "Generic method should not generate errors"
        );

        // Method with multiple parameters using fluent API
        let multi_param_signature = MethodSignatureBuilder::instance_method(TypeSignature::Void)
            .add_parameter("param1", TypeSignature::I4)
            .add_parameter("param2", TypeSignature::I4)
            .add_parameter("param3", TypeSignature::String)
            .build();

        let multi_param_method = MethodBuilder::new()
            .with_name("MultiParamMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_signature(multi_param_signature)
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&multi_param_method, &test_type, &mut errors);
        assert!(
            errors.is_empty(),
            "Multi-parameter method should not generate errors"
        );
    }

    #[test]
    fn test_method_validation_edge_cases() {
        // Test edge cases and boundary conditions

        let test_type = CilTypeBuilder::new()
            .with_namespace("Test")
            .with_name("EdgeCaseClass")
            .build();

        // Method with empty name (should be caught by name validation)
        let empty_name_method = MethodBuilder::new()
            .with_name("")
            .with_access(MethodAccessFlags::PUBLIC)
            .build();

        // We can't directly test empty name validation here since it's in validate_type_methods
        // But we can test that our builders handle edge cases properly
        assert_eq!(
            empty_name_method.name, "",
            "Builder should preserve empty name for testing"
        );

        // Method with maximum valid modifiers combination
        let max_modifiers_method = MethodBuilder::new()
            .with_name("MaxModifiersMethod")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(
                MethodModifiers::VIRTUAL | MethodModifiers::FINAL | MethodModifiers::HIDE_BY_SIG,
            )
            .build();

        let mut errors = Vec::new();
        MethodValidator::validate_abstract_method(&max_modifiers_method, &test_type, &mut errors);
        assert!(
            errors.is_empty(),
            "Method with valid modifier combination should not generate errors"
        );
    }

    #[test]
    fn test_builder_integration_comprehensive() {
        // Test the complete integration of our builders with method validation

        let test_type = CilTypeBuilder::new()
            .with_namespace("TestNamespace")
            .with_name("ComprehensiveTestClass")
            .build();

        // Use convenience methods for common patterns
        let constructor = MethodBuilder::constructor().build();
        let static_constructor = MethodBuilder::static_constructor().build();
        let property_getter = MethodBuilder::property_getter("TestProperty").build();
        let property_setter = MethodBuilder::property_setter("TestProperty").build();

        // Validate all methods
        let methods = vec![
            &constructor,
            &static_constructor,
            &property_getter,
            &property_setter,
        ];
        for method in methods {
            let mut errors = Vec::new();

            // Test static constructor specific validation
            if method.name == ".cctor" {
                MethodValidator::validate_static_constructor(method, &test_type, &mut errors);
            }

            // Test abstract method validation
            MethodValidator::validate_abstract_method(method, &test_type, &mut errors);

            assert!(
                errors.is_empty(),
                "Method '{}' should not generate validation errors: {:?}",
                method.name,
                errors
            );
        }
    }

    #[test]
    fn test_realistic_method_scenarios_with_builders() {
        // Test realistic scenarios that might occur in actual .NET assemblies

        let test_type = CilTypeBuilder::new()
            .with_namespace("MyApp.Models")
            .with_name("Person")
            .build();

        // Event handler method
        let event_handler = MethodBuilder::new()
            .with_name("OnPropertyChanged")
            .with_access(MethodAccessFlags::FAMILY)
            .with_modifiers(MethodModifiers::VIRTUAL)
            .with_signature(
                MethodSignatureBuilder::instance_method(TypeSignature::Void)
                    .add_parameter("propertyName", TypeSignature::String)
                    .build(),
            )
            .build();

        // Async method (simplified)
        let async_method = MethodBuilder::new()
            .with_name("GetDataAsync")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_signature(
                MethodSignatureBuilder::instance_method(TypeSignature::Class(
                    create_int32_type().token,
                ))
                .add_parameter("id", TypeSignature::I4)
                .build(),
            )
            .build();

        // Extension method (static with special attribute)
        let extension_method = MethodBuilder::new()
            .with_name("ToJson")
            .with_access(MethodAccessFlags::PUBLIC)
            .with_modifiers(MethodModifiers::STATIC)
            .with_signature(
                MethodSignatureBuilder::static_method(TypeSignature::String)
                    .add_parameter("this", TypeSignature::Object) // 'this' parameter for extension method
                    .build(),
            )
            .build();

        let methods = vec![&event_handler, &async_method, &extension_method];
        for method in methods {
            let mut errors = Vec::new();
            MethodValidator::validate_abstract_method(method, &test_type, &mut errors);

            assert!(
                errors.is_empty(),
                "Realistic method '{}' should not generate validation errors: {:?}",
                method.name,
                errors
            );
        }
    }

    #[test]
    fn test_builder_infrastructure_gap_identified() {
        let method_with_signature = MethodBuilder::new()
            .with_name("TestMethod")
            .with_signature(
                MethodSignatureBuilder::new()
                    .add_parameter("param1", TypeSignature::I4)
                    .add_parameter("param2", TypeSignature::String)
                    .build(),
            )
            .build();

        assert_eq!(
            method_with_signature.signature.params.len(),
            2,
            "Signature params are populated by builders"
        );

        assert_eq!(
            method_with_signature.params.count(),
            2,
            "Method params table is now populated by enhanced builders"
        );
    }
}
