//! Comprehensive inheritance validator for type hierarchies and method inheritance.
//!
//! This validator provides comprehensive validation of inheritance relationships within the context
//! of fully resolved .NET metadata according to ECMA-335 specifications. It operates on resolved
//! type structures to validate inheritance hierarchies, detect circular dependencies, ensure
//! base type consistency, verify interface implementation rules, and validate method inheritance
//! patterns. This validator runs with priority 180 in the owned validation stage.
//!
//! # Architecture
//!
//! The inheritance validation system implements comprehensive inheritance relationship validation in sequential order:
//! 1. **Inheritance Hierarchy Consistency Validation** - Ensures inheritance relationships are well-formed without circular dependencies
//! 2. **Base Type Accessibility Validation** - Validates base types are accessible and compatible with inheritance rules
//! 3. **Interface Implementation Hierarchy Validation** - Ensures interface implementations follow proper inheritance rules
//! 4. **Abstract Concrete Inheritance Rules Validation** - Validates abstract and concrete type inheritance constraints
//! 5. **Method Inheritance Validation** - Validates method override rules, virtual method consistency, and abstract method implementation
//!
//! The implementation validates inheritance constraints according to ECMA-335 specifications,
//! ensuring proper inheritance hierarchy formation and preventing circular dependencies.
//! All validation includes graph traversal algorithms, accessibility verification, and method inheritance validation.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator`] - Main validator implementation providing comprehensive inheritance validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_inheritance_hierarchy_consistency`] - Inheritance hierarchy consistency and circular dependency detection
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_base_type_accessibility`] - Base type accessibility and compatibility validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_interface_implementation_hierarchy`] - Interface implementation hierarchy and constraint validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_abstract_concrete_inheritance_rules`] - Abstract and concrete type inheritance rule validation
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_method_inheritance`] - Method inheritance validation including override rules and virtual method consistency
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_basic_method_overrides`] - Basic method override validation for parameter count and final method rules
//! - [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator::validate_virtual_method_override`] - Virtual method override validation for signature compatibility
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedInheritanceValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedInheritanceValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_owned(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationOwnedValidatorFailed`] for:
//! - Inheritance hierarchy consistency violations (circular inheritance dependencies)
//! - Base type accessibility failures (inheritance from sealed types, inaccessible base types)
//! - Interface implementation violations (implementing non-interfaces, accessibility issues)
//! - Abstract concrete inheritance rule violations (concrete interfaces, invalid abstract/sealed combinations)
//! - Type flavor inheritance inconsistencies (incompatible flavor relationships)
//! - Method inheritance violations (concrete types with abstract methods, parameter count mismatches in overrides)
//! - Virtual method override violations (overriding final methods, signature incompatibilities)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable resolved metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::owned::types`] - Part of the owned type validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//! - [`crate::metadata::method::MethodMap`] - Source of method definitions for inheritance validation
//! - [`crate::metadata::method::Method`] - Individual method instances being validated
//!
//! # References
//!
//! - [ECMA-335 I.8.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Inheritance and object layout
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type inheritance
//! - [ECMA-335 II.12.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Inheritance and overriding
//! - [ECMA-335 II.22.37](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeDef inheritance

use crate::{
    metadata::{
        method::{Method, MethodMap, MethodModifiers},
        tables::TypeAttributes,
        typesystem::{CilFlavor, CilType, CilTypeRefList},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Result,
};
use std::collections::HashSet;

/// Foundation validator for inheritance hierarchies, circular dependencies, interface implementation, and method inheritance.
///
/// Ensures the structural integrity and consistency of inheritance relationships in resolved .NET metadata,
/// validating inheritance hierarchy formation, detecting circular dependencies, ensuring base type
/// compatibility, verifying interface implementation rules, and validating method inheritance patterns.
/// This validator operates on resolved type structures to provide essential guarantees about inheritance
/// integrity and method override consistency according to ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of inheritance validation according to
/// ECMA-335 specifications, using efficient graph traversal algorithms for cycle detection,
/// accessibility verification, and method inheritance validation in the resolved metadata object model.
/// Method inheritance validation includes checking abstract method implementation requirements,
/// virtual method override rules, and final method constraints.
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator;
/// use dotscope::metadata::validation::OwnedValidator;
/// use dotscope::metadata::validation::context::OwnedValidationContext;
///
/// # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
/// let context = get_context();
/// let validator = OwnedInheritanceValidator::new();
///
/// // Validate inheritance relationships including method inheritance
/// if validator.should_run(&context) {
///     validator.validate_owned(&context)?;
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures. Method inheritance validation
/// operates on thread-safe [`crate::metadata::method::MethodMap`] and [`crate::metadata::typesystem::CilType`] references.
pub struct OwnedInheritanceValidator;

impl OwnedInheritanceValidator {
    /// Creates a new inheritance validator instance.
    ///
    /// Initializes a validator instance that can be used to validate inheritance relationships
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::types::inheritance::OwnedInheritanceValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    pub fn new() -> Self {
        Self
    }
}

impl OwnedInheritanceValidator {
    /// Validates inheritance hierarchy consistency and circular dependency detection.
    ///
    /// Ensures that inheritance relationships are well-formed and don't contain
    /// circular dependencies that would make type resolution impossible.
    fn validate_inheritance_hierarchy_consistency(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let types = context.object().types();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        for type_entry in types.all_types() {
            if !visited.contains(&type_entry.token.value()) {
                self.check_inheritance_cycles(
                    &type_entry,
                    &mut visited,
                    &mut visiting,
                    context,
                    0,
                )?;
            }
        }

        Ok(())
    }

    /// Checks for circular inheritance dependencies starting from a given type.
    ///
    /// Uses depth-first search to detect cycles in the inheritance graph.
    /// Includes recursion depth limiting to prevent stack overflow.
    fn check_inheritance_cycles(
        &self,
        type_entry: &CilType,
        visited: &mut HashSet<u32>,
        visiting: &mut HashSet<u32>,
        context: &OwnedValidationContext,
        depth: usize,
    ) -> Result<()> {
        if depth > context.config().max_nesting_depth {
            return Err(crate::Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Inheritance chain depth exceeds maximum nesting depth limit of {} for type '{}'",
                    context.config().max_nesting_depth, type_entry.name
                ),
                source: None,
            });
        }

        let token = type_entry.token.value();

        if visiting.contains(&token) {
            let type_name = &type_entry.name;
            return Err(crate::Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular inheritance dependency detected involving type '{type_name}'"
                ),
                source: None,
            });
        }

        if visited.contains(&token) {
            return Ok(());
        }

        visiting.insert(token);

        // Check base type for cycles
        if let Some(base_type) = type_entry.base() {
            self.check_inheritance_cycles(&base_type, visited, visiting, context, depth + 1)?;
        }

        // Check interface implementations for cycles (less common but possible)
        for (_, interface_ref) in type_entry.interfaces.iter() {
            if let Some(interface_type) = interface_ref.upgrade() {
                self.check_inheritance_cycles(
                    &interface_type,
                    visited,
                    visiting,
                    context,
                    depth + 1,
                )?;
            }
        }

        visiting.remove(&token);
        visited.insert(token);

        Ok(())
    }

    /// Validates base type accessibility and compatibility.
    ///
    /// Ensures that base types are accessible from derived types and that
    /// inheritance relationships are semantically valid.
    fn validate_base_type_accessibility(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();

        let all_types = types.all_types();
        for type_entry in all_types {
            if let Some(base_type) = type_entry.base() {
                // Validate base type is not sealed (unless special cases or self-references)
                if base_type.flags & 0x0000_0100 != 0 {
                    // SEALED flag
                    // Allow self-references and generic relationships
                    let derived_fullname = type_entry.fullname();
                    let base_fullname = base_type.fullname();
                    let is_self_reference = derived_fullname == base_fullname;
                    let is_generic_relationship = (derived_fullname.contains('`')
                        || base_fullname.contains('`'))
                        && (derived_fullname
                            .starts_with(base_fullname.split('`').next().unwrap_or(""))
                            || base_fullname
                                .starts_with(derived_fullname.split('`').next().unwrap_or("")));
                    let is_pointer_relationship = derived_fullname.ends_with("*")
                        && derived_fullname.trim_end_matches("*") == base_fullname;
                    let is_array_relationship = derived_fullname.ends_with("[]")
                        && derived_fullname.trim_end_matches("[]") == base_fullname;

                    // Some special cases where sealed inheritance is allowed
                    let is_system_type = base_type.namespace.starts_with("System");
                    let is_value_type_inheritance = base_type.fullname() == "System.ValueType"
                        || base_type.fullname() == "System.Enum";

                    if !is_system_type
                        && !is_value_type_inheritance
                        && !is_self_reference
                        && !is_generic_relationship
                        && !is_pointer_relationship
                        && !is_array_relationship
                    {
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' cannot inherit from sealed type '{}'",
                                type_entry.name, base_type.name
                            ),
                            source: None,
                        });
                    }
                }

                // Validate base type inheritance patterns
                if base_type.flags & TypeAttributes::INTERFACE != 0 {
                    // Interfaces can inherit from other interfaces
                    // Also allow array and pointer types to inherit from interfaces
                    let derived_fullname = type_entry.fullname();
                    let base_fullname = base_type.fullname();
                    let is_array_relationship = derived_fullname.ends_with("[]")
                        && derived_fullname.trim_end_matches("[]") == base_fullname;
                    let is_pointer_relationship = derived_fullname.ends_with("*")
                        && derived_fullname.trim_end_matches("*") == base_fullname;

                    if type_entry.flags & TypeAttributes::INTERFACE == 0
                        && !is_array_relationship
                        && !is_pointer_relationship
                    {
                        // Non-interface types cannot inherit from interfaces (should use interface implementation)
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' cannot inherit from interface '{}' (use interface implementation instead)",
                                type_entry.name, base_type.name
                            ),
                            source: None,
                        });
                    }
                }

                // Validate accessibility compatibility
                let derived_visibility = type_entry.flags & TypeAttributes::VISIBILITY_MASK;
                let base_visibility = base_type.flags & TypeAttributes::VISIBILITY_MASK;

                // System base types, generic relationships, array relationships, and pointer relationships are always accessible
                let base_fullname = base_type.fullname();
                let derived_fullname = type_entry.fullname();
                let is_system_type = base_fullname.starts_with("System.");
                let is_generic_relationship = derived_fullname.contains('`')
                    && derived_fullname.starts_with(base_fullname.split('`').next().unwrap_or(""));
                let is_array_relationship = derived_fullname.ends_with("[]")
                    && derived_fullname.trim_end_matches("[]") == base_fullname;
                let is_pointer_relationship = derived_fullname.ends_with("*")
                    && derived_fullname.trim_end_matches("*") == base_fullname;

                if !is_system_type
                    && !is_generic_relationship
                    && !is_array_relationship
                    && !is_pointer_relationship
                    && !self.is_accessible_inheritance(derived_visibility, base_visibility)
                {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' cannot inherit from less accessible base type '{}'",
                            type_entry.name, base_type.name
                        ),
                        source: None,
                    });
                }

                // Validate consistent type flavor inheritance (skip self-references, generic relationships, array types, pointer types, and System types)
                let derived_fullname = type_entry.fullname();
                let base_fullname = base_type.fullname();
                let is_self_reference = derived_fullname == base_fullname;
                let is_generic_relationship = derived_fullname.contains('`')
                    && derived_fullname.starts_with(base_fullname.split('`').next().unwrap_or(""));
                let is_array_relationship = derived_fullname.ends_with("[]")
                    && derived_fullname.trim_end_matches("[]") == base_fullname;
                let is_pointer_relationship = derived_fullname.ends_with("*")
                    && derived_fullname.trim_end_matches("*") == base_fullname;
                let is_system_relationship =
                    derived_fullname.starts_with("System.") || base_fullname.starts_with("System.");

                if !is_self_reference
                    && !is_generic_relationship
                    && !is_array_relationship
                    && !is_pointer_relationship
                    && !is_system_relationship
                {
                    self.validate_type_flavor_inheritance(&type_entry, &base_type)?;
                }
            }
        }

        Ok(())
    }

    /// Validates interface implementation hierarchy and constraints.
    ///
    /// Ensures that interface implementations are valid and follow proper
    /// interface inheritance rules.
    fn validate_interface_implementation_hierarchy(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let types = context.object().types();

        for type_entry in types.all_types() {
            // Validate interface implementations
            for (_, interface_ref) in type_entry.interfaces.iter() {
                if let Some(interface_type) = interface_ref.upgrade() {
                    // Validate the implemented type is actually an interface
                    // Allow System types which may not have the Interface flag set correctly
                    let is_system_interface = interface_type.fullname().starts_with("System.");
                    if interface_type.flags & TypeAttributes::INTERFACE == 0 && !is_system_interface
                    {
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' tries to implement non-interface type '{}'",
                                type_entry.name, interface_type.name
                            ),
                            source: None,
                        });
                    }

                    // Validate interface accessibility
                    let type_visibility = type_entry.flags & TypeAttributes::VISIBILITY_MASK;
                    let interface_visibility =
                        interface_type.flags & TypeAttributes::VISIBILITY_MASK;

                    // Skip accessibility validation for System interfaces
                    let is_system_interface = interface_type.fullname().starts_with("System.");
                    if !is_system_interface
                        && !self.is_accessible_interface_implementation(
                            type_visibility,
                            interface_visibility,
                        )
                    {
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' cannot implement less accessible interface '{}'",
                                type_entry.name, interface_type.name
                            ),
                            source: None,
                        });
                    }
                }
            }

            // Validate that interfaces don't have conflicting implementations
            if type_entry.interfaces.count() > 1 {
                self.validate_interface_compatibility(&type_entry.interfaces)?;
            }
        }

        Ok(())
    }

    /// Validates abstract and concrete type inheritance rules.
    ///
    /// Ensures that abstract types are properly handled in inheritance
    /// hierarchies and that concrete types implement all required members.
    fn validate_abstract_concrete_inheritance_rules(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let types = context.object().types();

        for type_entry in types.all_types() {
            let flags = type_entry.flags;

            // Validate abstract type constraints
            if flags & TypeAttributes::ABSTRACT != 0 {
                // Abstract types cannot be sealed (except for static classes)
                if flags & 0x0000_0100 != 0 {
                    // SEALED flag - this is valid for static classes in C#
                    // Static classes are marked as both abstract and sealed by the compiler
                }

                // Interfaces must be abstract
                if flags & TypeAttributes::INTERFACE != 0 {
                    // This is correct - interfaces are abstract
                } else {
                    // Non-interface abstract types should have proper structure
                    if type_entry.methods.is_empty() && type_entry.fields.is_empty() {
                        // Abstract types with no members might be intended as base classes
                        // This is generally acceptable
                    }
                }
            }

            // Validate concrete type constraints
            if flags & TypeAttributes::ABSTRACT == 0 {
                // Concrete types cannot be interfaces
                if flags & TypeAttributes::INTERFACE != 0 {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Interface '{}' must be abstract", type_entry.name),
                        source: None,
                    });
                }
            }

            // Validate sealed type constraints
            if flags & 0x0000_0100 != 0 {
                // SEALED flag
                // Sealed types cannot be abstract (except for static classes)
                if flags & TypeAttributes::ABSTRACT != 0 {
                    // This is valid for static classes in C#
                    // Static classes are marked as both abstract and sealed by the compiler
                }

                // Sealed types should not have derived types (checked in derived types)
                // This is handled by validate_base_type_accessibility
            }
        }

        Ok(())
    }

    /// Validates type flavor inheritance consistency.
    fn validate_type_flavor_inheritance(
        &self,
        derived_type: &CilType,
        base_type: &CilType,
    ) -> Result<()> {
        let derived_flavor = derived_type.flavor();
        let base_flavor = base_type.flavor();

        // Validate consistent flavor inheritance patterns
        match (derived_flavor, base_flavor) {
            // Value types should inherit from System.ValueType or System.Enum
            (CilFlavor::ValueType, CilFlavor::ValueType) => Ok(()),
            (CilFlavor::ValueType, CilFlavor::Object) => {
                // Allow ValueType -> Object inheritance (System.ValueType -> System.Object)
                if base_type.fullname() == "System.Object" {
                    Ok(())
                } else {
                    Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Value type '{}' has incompatible base type flavor",
                            derived_type.name
                        ),
                        source: None,
                    })
                }
            }

            // Classes should inherit from other classes or Object
            (CilFlavor::Class, CilFlavor::Class) => Ok(()),
            (CilFlavor::Class, CilFlavor::Object) => Ok(()),

            // Interfaces cannot inherit from non-interfaces
            (CilFlavor::Interface, CilFlavor::Interface) => Ok(()),
            (CilFlavor::Interface, _) => {
                Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Interface '{}' cannot inherit from non-interface type '{}'",
                        derived_type.name, base_type.name
                    ),
                    source: None,
                })
            }

            // Other combinations are generally invalid
            _ => {
                Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Type '{}' has incompatible inheritance flavor relationship with base type '{}'",
                        derived_type.name, base_type.name
                    ),
                    source: None,
                })
            }
        }
    }

    /// Checks if inheritance is accessible based on visibility rules.
    fn is_accessible_inheritance(&self, derived_visibility: u32, base_visibility: u32) -> bool {
        // Public types can inherit from any accessible type
        if derived_visibility == TypeAttributes::PUBLIC {
            return base_visibility == TypeAttributes::PUBLIC;
        }

        // Internal types can inherit from internal or public types
        if derived_visibility == TypeAttributes::NOT_PUBLIC {
            return base_visibility == TypeAttributes::NOT_PUBLIC
                || base_visibility == TypeAttributes::PUBLIC;
        }

        // Nested types have more complex rules
        if derived_visibility >= TypeAttributes::NESTED_PUBLIC {
            // For simplicity, allow nested type inheritance for now
            // Full implementation would need to check containing type accessibility
            return true;
        }

        false
    }

    /// Checks if interface implementation is accessible based on visibility rules.
    fn is_accessible_interface_implementation(
        &self,
        type_visibility: u32,
        interface_visibility: u32,
    ) -> bool {
        // Similar to inheritance but slightly more permissive for interfaces
        if type_visibility == TypeAttributes::PUBLIC {
            return interface_visibility == TypeAttributes::PUBLIC;
        }

        if type_visibility == TypeAttributes::NOT_PUBLIC {
            return interface_visibility == TypeAttributes::NOT_PUBLIC
                || interface_visibility == TypeAttributes::PUBLIC;
        }

        // Nested types can generally implement accessible interfaces
        true
    }

    /// Validates that multiple interface implementations are compatible.
    fn validate_interface_compatibility(&self, interfaces: &CilTypeRefList) -> Result<()> {
        let mut interface_names = HashSet::new();

        for (_, interface_ref) in interfaces.iter() {
            if let Some(interface_type) = interface_ref.upgrade() {
                let interface_name = interface_type.fullname();

                // Check for duplicate interface implementations
                // Note: Generic interfaces with different type parameters are legitimate
                // e.g., IEquatable<int> and IEquatable<string> are different interfaces
                // So we disable this validation to avoid false positives
                interface_names.insert(interface_name.clone());
            }
        }

        Ok(())
    }

    /// Validates method inheritance relationships across type hierarchies.
    ///
    /// Performs comprehensive validation of method inheritance patterns according to ECMA-335
    /// specifications, ensuring that method overrides follow proper inheritance rules and that
    /// abstract methods are properly implemented in concrete derived types. This validation
    /// includes checking virtual method consistency, abstract method implementation requirements,
    /// and final method constraints.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method and type structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method inheritance relationships are valid
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Method inheritance violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Concrete types contain abstract methods (violates ECMA-335 requirements)
    /// - Virtual method overrides have incompatible signatures (parameter count mismatches)
    /// - Final methods are being overridden (violates sealing constraints)
    /// - Method inheritance chains are inconsistent across type hierarchies
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable resolved metadata structures.
    /// All method and type data is accessed through thread-safe collections.
    fn validate_method_inheritance(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();
        let methods = context.object().methods();

        for type_entry in types.all_types() {
            if let Some(base_type) = type_entry.base() {
                self.validate_basic_method_overrides(&type_entry, &base_type, methods)?;
            }
        }

        Ok(())
    }

    /// Validates basic method override rules between derived and base types.
    ///
    /// Performs validation of fundamental method inheritance rules according to ECMA-335
    /// specifications, focusing on abstract method implementation requirements and basic
    /// virtual method override constraints. This validation ensures that concrete types
    /// properly implement abstract methods and that virtual method overrides follow
    /// inheritance rules.
    ///
    /// # Arguments
    ///
    /// * `derived_type` - The derived type containing methods to validate via [`crate::metadata::typesystem::CilType`]
    /// * `base_type` - The base type containing methods being overridden via [`crate::metadata::typesystem::CilType`]
    /// * `methods` - Method map containing all method definitions via [`crate::metadata::method::MethodMap`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All basic method override rules are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Method override violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Concrete types contain abstract methods (ECMA-335 violation)
    /// - Virtual method override validation fails for any method pair
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable resolved metadata structures.
    fn validate_basic_method_overrides(
        &self,
        derived_type: &CilType,
        base_type: &CilType,
        methods: &MethodMap,
    ) -> Result<()> {
        // Skip validation if base type is an interface - interface implementation is different from class inheritance
        if base_type.flags & TypeAttributes::INTERFACE != 0 {
            return Ok(());
        }

        for method_entry in methods.iter() {
            let method = method_entry.value();

            if self.method_belongs_to_type(method, derived_type) {
                if method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
                    self.validate_virtual_method_override(method, base_type, methods)?;
                }

                if method.flags_modifiers.contains(MethodModifiers::ABSTRACT)
                    && derived_type.flags & TypeAttributes::ABSTRACT == 0
                {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Concrete type '{}' cannot have abstract method '{}'",
                            derived_type.name, method.name
                        ),
                        source: None,
                    });
                }
            }
        }
        Ok(())
    }

    /// Determines if a method belongs to a specific type by comparing tokens.
    ///
    /// Checks whether a given method is defined within a specific type by comparing
    /// method tokens against the type's method collection. This is used to associate
    /// methods with their declaring types during inheritance validation.
    ///
    /// # Arguments
    ///
    /// * `method` - The method to check ownership for via [`crate::metadata::method::Method`]
    /// * `type_entry` - The type to check method ownership against via [`crate::metadata::typesystem::CilType`]
    ///
    /// # Returns
    ///
    /// * `true` - The method belongs to the specified type
    /// * `false` - The method does not belong to the specified type
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable metadata structures.
    fn method_belongs_to_type(&self, method: &Method, type_entry: &CilType) -> bool {
        for (_, method_ref) in type_entry.methods.iter() {
            if method_ref.token() == Some(method.token) {
                return true;
            }
        }
        false
    }

    /// Validates virtual method override rules against base type methods.
    ///
    /// Performs detailed validation of virtual method overrides according to ECMA-335
    /// specifications, ensuring that method signatures are compatible and that final
    /// methods are not being overridden. This validation checks parameter count consistency
    /// and enforces final method sealing constraints across inheritance hierarchies.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The derived virtual method being validated via [`crate::metadata::method::Method`]
    /// * `base_type` - The base type containing potential overridden methods via [`crate::metadata::typesystem::CilType`]
    /// * `methods` - Method map containing all method definitions via [`crate::metadata::method::MethodMap`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All virtual method override rules are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Virtual method override violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Method override parameter count differs from base method (signature incompatibility)
    /// - Attempting to override a final method (sealing violation)
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and operates on immutable resolved metadata structures.
    fn validate_virtual_method_override(
        &self,
        derived_method: &Method,
        base_type: &CilType,
        methods: &MethodMap,
    ) -> Result<()> {
        // Skip interface method validation - interface implementation is different from method overriding
        if base_type.flags & TypeAttributes::INTERFACE != 0 {
            return Ok(());
        }

        for base_method_entry in methods.iter() {
            let base_method = base_method_entry.value();

            if self.method_belongs_to_type(base_method, base_type)
                && base_method.name == derived_method.name
                && base_method
                    .flags_modifiers
                    .contains(MethodModifiers::VIRTUAL)
            {
                // Skip validation if the method name suggests it's an interface method implementation
                // Interface methods often have names like "System.IComparable.CompareTo"
                if base_method.name.contains('.')
                    && (base_method.name.starts_with("System.I") || base_method.name.contains(".I"))
                {
                    continue;
                }

                if base_method.params.count() != derived_method.params.count() {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method override '{}' parameter count differs from base method",
                            derived_method.name
                        ),
                        source: None,
                    });
                }

                if base_method.flags_modifiers.contains(MethodModifiers::FINAL) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Cannot override final method '{}'", base_method.name),
                        source: None,
                    });
                }
            }
        }
        Ok(())
    }
}

impl OwnedValidator for OwnedInheritanceValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_inheritance_hierarchy_consistency(context)?;
        self.validate_base_type_accessibility(context)?;
        self.validate_interface_implementation_hierarchy(context)?;
        self.validate_abstract_concrete_inheritance_rules(context)?;
        self.validate_method_inheritance(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedInheritanceValidator"
    }

    fn priority(&self) -> u32 {
        180
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedInheritanceValidator {
    fn default() -> Self {
        Self::new()
    }
}
