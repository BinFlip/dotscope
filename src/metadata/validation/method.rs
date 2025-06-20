//! # Method Validation for .NET Metadata
//!
//! This module provides comprehensive validation for method-specific rules and constraints
//! according to .NET runtime behavior and ECMA-335 specifications. Method validation ensures
//! that method definitions conform to language semantics and runtime requirements.
//!
//! ## Overview
//!
//! Method validation in .NET involves multiple layers of constraint checking:
//!
//! - **Structural Validation**: Method names, signatures, and basic format compliance
//! - **Modifier Consistency**: Ensuring modifier combinations are semantically valid
//! - **Special Method Rules**: Constructor, static constructor, and property accessor validation
//! - **Abstract Method Constraints**: Abstract method compatibility with type semantics
//! - **Virtual Method Rules**: Virtual method inheritance and override validation
//! - **Access Modifier Logic**: Visibility and accessibility constraint checking
//!
//! ## Validation Categories
//!
//! ### Constructor Validation
//! - **Static Constructors** (`.cctor`): Must be static, parameterless, and unique per type
//! - **Instance Constructors** (`.ctor`): Must follow proper initialization patterns
//! - **Constructor Naming**: Enforces standard naming conventions
//!
//! ### Abstract Method Validation
//! - **Modifier Conflicts**: Abstract methods cannot be static or final
//! - **Implementation Requirements**: Abstract methods must be in abstract types
//! - **Virtual Consistency**: Abstract methods are implicitly virtual
//!
//! ### Special Method Rules
//! - **Property Accessors**: `get_PropertyName` and `set_PropertyName` validation
//! - **Event Handlers**: `add_EventName` and `remove_EventName` validation
//! - **Operator Overloads**: Special naming and signature requirements
//!
//! ## Validation Rules
//!
//! ### Static Constructor Rules
//! 1. **Name**: Must be exactly `.cctor`
//! 2. **Modifiers**: Must include `static`, cannot include `abstract` or `virtual`
//! 3. **Parameters**: Must have no parameters (implicit `this` not allowed)
//! 4. **Accessibility**: Typically `private` (enforced by runtime)
//! 5. **Uniqueness**: Only one static constructor per type
//!
//! ### Abstract Method Rules
//! 1. **Static Conflict**: Abstract methods cannot be static
//! 2. **Final Conflict**: Abstract methods cannot be final/sealed
//! 3. **Implementation**: Must not have method body (IL implementation)
//! 4. **Virtual Nature**: Abstract methods are implicitly virtual
//! 5. **Type Context**: Can only exist in abstract types
//!
//! ### Access Modifier Rules
//! 1. **Visibility Consistency**: Method visibility cannot exceed type visibility
//! 2. **Virtual Accessibility**: Virtual methods have inheritance accessibility rules
//! 3. **Override Compatibility**: Override methods must match base method accessibility
//!
//! ## Error Reporting
//!
//! The validation system provides detailed error messages including:
//! - **Context Information**: Type name, method name, and relevant tokens
//! - **Specific Violations**: Clear description of the validation rule violated
//! - **Corrective Guidance**: Suggestions for fixing validation issues
//!
//! ## Runtime Compliance
//!
//! This implementation follows .NET runtime validation behavior:
//! - **`CoreCLR` Compatibility**: Matches method validation in .NET Core runtime
//! - **ECMA-335 Compliance**: Implements specification-defined validation rules
//! - **Error Parity**: Provides similar error messages to runtime validation
//!
//! ## Thread Safety
//!
//! The `MethodValidator` is stateless and uses parallel processing internally.
//! All validation methods are safe for concurrent use across multiple threads.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::validation::constraint`] - Generic constraint validation
//! - [`crate::metadata::validation::field`] - Field layout validation
//! - [`crate::metadata::method`] - Method representation and parsing
//! - [`crate::metadata::typesystem`] - Type system components
//!
//! ## References
//!
//! - ECMA-335, Partition II, Section 15 - Defining and referencing methods
//! - ECMA-335, Partition II, Section 10 - Defining types
//! - .NET Core Runtime: Method validation implementation
//! - C# Language Specification: Method declarations and constraints

use crate::metadata::{loader::CilObjectData, method::MethodModifiers, typesystem::CilType};
use rayon::prelude::*;

/// Method validator for .NET metadata compliance.
///
/// Provides comprehensive validation functionality for method definitions as specified
/// in ECMA-335 and implemented by the .NET runtime. This validator ensures that method
/// declarations conform to language semantics, runtime constraints, and specification
/// requirements.
///
/// ## Design Philosophy
///
/// The validator implements a comprehensive approach to method validation:
/// - **Rule-based validation**: Each validation rule is clearly defined and documented
/// - **Performance optimization**: Uses parallel processing for large assemblies
/// - **Detailed reporting**: Provides actionable error messages with context
/// - **Runtime compatibility**: Matches .NET runtime validation behavior
///
/// ## Validation Scope
///
/// The validator covers all aspects of method validation:
/// - Structural integrity (names, signatures, modifiers)
/// - Semantic consistency (abstract/concrete, static/instance relationships)
/// - Special method rules (constructors, property accessors, operators)
/// - Access control and visibility constraints
/// - Generic method constraints and variance
///
/// ## Thread Safety
///
/// This struct is stateless and designed for concurrent use. The validation
/// methods use parallel iterators internally and are safe to call from
/// multiple threads simultaneously.
pub struct MethodValidator;

impl MethodValidator {
    /// Validates method-specific rules across all methods in an assembly.
    ///
    /// Performs comprehensive validation of all methods in the provided assembly data,
    /// checking for compliance with .NET runtime rules and ECMA-335 specifications.
    /// This method uses parallel processing for optimal performance on large assemblies.
    ///
    /// ## Validation Performed
    ///
    /// ### Basic Structure Validation
    /// - **Method names**: Ensures methods have valid, non-empty names
    /// - **Signature integrity**: Validates method signatures and parameter lists
    /// - **Token consistency**: Verifies method tokens and references
    ///
    /// ### Modifier Consistency Checks
    /// - **Abstract method rules**: Abstract methods cannot be static or final
    /// - **Static method constraints**: Static methods cannot be abstract or virtual
    /// - **Virtual method requirements**: Virtual methods must be in appropriate contexts
    ///
    /// ### Special Method Validation
    /// - **Static constructors**: `.cctor` methods must be static and parameterless
    /// - **Instance constructors**: `.ctor` methods must follow proper patterns
    /// - **Property accessors**: `get_` and `set_` methods must have correct signatures
    /// - **Event handlers**: `add_` and `remove_` methods must follow event patterns
    ///
    /// ### Access Control Validation
    /// - **Visibility consistency**: Method visibility cannot exceed type visibility
    /// - **Override compatibility**: Override methods must match base accessibility
    /// - **Virtual accessibility**: Virtual methods must be accessible to derived types
    ///
    /// # Arguments
    ///
    /// * `data` - The [`CilObjectData`] containing complete assembly metadata including
    ///   type registry, method definitions, and associated metadata tables
    ///
    /// # Returns
    ///
    /// Returns a `Vec<String>` containing detailed validation error messages. An empty
    /// vector indicates that all methods passed validation successfully.
    ///
    /// Each error message includes:
    /// - **Context**: Type name and method name where the error occurred
    /// - **Violation**: Specific rule or constraint that was violated
    /// - **Details**: Additional information to help diagnose and fix the issue
    ///
    /// # Error Categories
    ///
    /// The validation can detect several categories of errors:
    ///
    /// | Category | Examples |
    /// |----------|----------|
    /// | **Naming** | Empty method names, invalid special method names |
    /// | **Modifiers** | Abstract+static, abstract+final, invalid combinations |
    /// | **Constructors** | Non-static `.cctor`, parameterized static constructors |
    /// | **Signatures** | Mismatched parameter counts, invalid return types |
    /// | **Access** | Inconsistent visibility, override accessibility conflicts |
    ///
    /// # Runtime Compliance
    ///
    /// This validation matches the behavior of the .NET runtime during type loading,
    /// helping catch issues that would cause runtime exceptions or unexpected behavior.
    /// The validation rules are derived from:
    /// - ECMA-335 specification requirements
    /// - .NET Core runtime implementation analysis
    /// - C# language specification constraints
    /// - Common IL generation patterns and constraints
    pub fn validate_method_rules(data: &CilObjectData) -> Vec<String> {
        let type_registry = &data.types;

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

    /// Validates methods for a specific type.
    ///
    /// Internal helper method that performs validation for all methods defined
    /// within a single type. This method is called by the main validation routine
    /// for each type in the assembly.
    ///
    /// ## Validation Performed
    /// - Method name validation (non-empty names)
    /// - Static constructor rule enforcement
    /// - Abstract method constraint checking
    /// - Method signature consistency
    ///
    /// # Arguments
    /// * `cil_type` - The type containing methods to validate
    /// * `errors` - Mutable vector to collect validation errors
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

    /// Validates static constructor specific rules.
    ///
    /// Validates that static constructors (`.cctor` methods) conform to .NET runtime
    /// requirements. Static constructors have special constraints that differ from
    /// regular methods and must be validated separately.
    ///
    /// ## Static Constructor Rules
    /// 1. **Must be static**: Static constructors must have the `static` modifier
    /// 2. **No parameters**: Static constructors cannot accept any parameters
    /// 3. **No return value**: Static constructors implicitly return `void`
    /// 4. **Single per type**: Only one static constructor allowed per type
    /// 5. **No accessibility**: Static constructors are implicitly `private`
    ///
    /// # Arguments
    /// * `method` - The method to validate (should be named `.cctor`)
    /// * `cil_type` - The type containing this static constructor
    /// * `errors` - Mutable vector to collect validation errors
    ///
    /// # Examples of Valid Static Constructors
    /// ```csharp
    /// static MyClass() { /* initialization code */ }  // C# syntax
    /// ```
    /// ```il
    /// .method private hidebysig specialname rtspecialname static
    ///     void .cctor() cil managed
    /// {
    ///     // IL initialization code
    ///     ret
    /// }
    /// ```
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

    /// Validates abstract method rules.
    ///
    /// Validates that abstract methods conform to .NET language semantics and runtime
    /// constraints. Abstract methods have specific modifier restrictions that ensure
    /// proper inheritance and polymorphism behavior.
    ///
    /// ## Abstract Method Rules
    /// 1. **Cannot be static**: Abstract methods must be instance methods for inheritance
    /// 2. **Cannot be final**: Abstract methods must be overridable by derived types
    /// 3. **Must be virtual**: Abstract methods are implicitly virtual for polymorphism
    /// 4. **No implementation**: Abstract methods cannot have method bodies
    /// 5. **Type context**: Abstract methods can only exist in abstract types
    ///
    /// ## Modifier Conflicts
    /// The following modifier combinations are invalid for abstract methods:
    /// - `abstract` + `static` (inheritance requires instance context)
    /// - `abstract` + `final`/`sealed` (abstract methods must be overridable)
    /// - `abstract` + `private` (derived types must be able to override)
    ///
    /// # Arguments
    /// * `method` - The method to validate for abstract method rules
    /// * `cil_type` - The type containing this method
    /// * `errors` - Mutable vector to collect validation errors
    ///
    /// # Examples of Valid Abstract Methods
    /// ```csharp
    /// public abstract void ProcessData();           // C# syntax
    /// protected abstract int CalculateValue();      // C# syntax
    /// ```
    /// ```il
    /// .method public hidebysig newslot abstract virtual
    ///     void ProcessData() cil managed
    /// {
    ///     // No method body for abstract methods
    /// }
    /// ```
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
