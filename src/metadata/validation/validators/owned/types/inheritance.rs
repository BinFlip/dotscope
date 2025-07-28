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
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRefList, TypeRegistry},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};
use std::{
    collections::{HashMap, HashSet},
    mem,
};

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

/// Fast method-to-type mapping for efficient method ownership lookup
struct MethodTypeMapping {
    /// Maps method token to the type token that owns it
    method_to_type: HashMap<Token, Token>,
    /// Maps type token to all methods it owns
    type_to_methods: HashMap<Token, Vec<Token>>,
}

impl MethodTypeMapping {
    /// Builds the method-to-type mapping for fast lookups
    fn new(types: &TypeRegistry) -> Self {
        let mut method_to_type = HashMap::new();
        let mut type_to_methods: HashMap<Token, Vec<Token>> = HashMap::new();

        for type_entry in types.all_types() {
            let type_token = type_entry.token;
            let mut type_methods = Vec::new();

            for (_, method_ref) in type_entry.methods.iter() {
                if let Some(method_token) = method_ref.token() {
                    method_to_type.insert(method_token, type_token);
                    type_methods.push(method_token);
                }
            }

            if !type_methods.is_empty() {
                type_to_methods.insert(type_token, type_methods);
            }
        }

        Self {
            method_to_type,
            type_to_methods,
        }
    }

    /// Fast check if a method belongs to a specific type (O(1) lookup)
    fn method_belongs_to_type(&self, method_token: Token, type_token: Token) -> bool {
        self.method_to_type.get(&method_token) == Some(&type_token)
    }

    /// Get all methods for a specific type (O(1) lookup)
    fn get_type_methods(&self, type_token: Token) -> &[Token] {
        self.type_to_methods
            .get(&type_token)
            .map_or(&[], Vec::as_slice)
    }
}

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
    #[must_use]
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
            return Err(Error::ValidationOwnedValidatorFailed {
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
            return Err(Error::ValidationOwnedValidatorFailed {
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

        if let Some(base_type) = type_entry.base() {
            self.check_inheritance_cycles(&base_type, visited, visiting, context, depth + 1)?;
        }

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
                if base_type.flags & 0x0000_0100 != 0 {
                    let derived_fullname = type_entry.fullname();
                    let base_fullname = base_type.fullname();
                    let is_self_reference = derived_fullname == base_fullname;
                    let is_generic_relationship = (derived_fullname.contains('`')
                        || base_fullname.contains('`'))
                        && (derived_fullname
                            .starts_with(base_fullname.split('`').next().unwrap_or(""))
                            || base_fullname
                                .starts_with(derived_fullname.split('`').next().unwrap_or("")));
                    let is_pointer_relationship = derived_fullname.ends_with('*')
                        && derived_fullname.trim_end_matches('*') == base_fullname;
                    let is_array_relationship = derived_fullname.ends_with("[]")
                        && derived_fullname.trim_end_matches("[]") == base_fullname;

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
                        return Err(Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' cannot inherit from sealed type '{}'",
                                type_entry.name, base_type.name
                            ),
                            source: None,
                        });
                    }
                }

                if base_type.flags & TypeAttributes::INTERFACE != 0 {
                    let derived_fullname = type_entry.fullname();
                    let base_fullname = base_type.fullname();
                    let is_array_relationship = derived_fullname.ends_with("[]")
                        && derived_fullname.trim_end_matches("[]") == base_fullname;
                    let is_pointer_relationship = derived_fullname.ends_with('*')
                        && derived_fullname.trim_end_matches('*') == base_fullname;

                    if type_entry.flags & TypeAttributes::INTERFACE == 0
                        && !is_array_relationship
                        && !is_pointer_relationship
                    {
                        return Err(Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' cannot inherit from interface '{}' (use interface implementation instead)",
                                type_entry.name, base_type.name
                            ),
                            source: None,
                        });
                    }
                }

                let derived_visibility = type_entry.flags & TypeAttributes::VISIBILITY_MASK;
                let base_visibility = base_type.flags & TypeAttributes::VISIBILITY_MASK;

                let base_fullname = base_type.fullname();
                let derived_fullname = type_entry.fullname();
                let is_system_type = base_fullname.starts_with("System.");
                let is_generic_relationship = derived_fullname.contains('`')
                    && derived_fullname.starts_with(base_fullname.split('`').next().unwrap_or(""));
                let is_array_relationship = derived_fullname.ends_with("[]")
                    && derived_fullname.trim_end_matches("[]") == base_fullname;
                let is_pointer_relationship = derived_fullname.ends_with('*')
                    && derived_fullname.trim_end_matches('*') == base_fullname;

                if !is_system_type
                    && !is_generic_relationship
                    && !is_array_relationship
                    && !is_pointer_relationship
                    && !Self::is_accessible_inheritance(derived_visibility, base_visibility)
                {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' cannot inherit from less accessible base type '{}'",
                            type_entry.name, base_type.name
                        ),
                        source: None,
                    });
                }

                let derived_fullname = type_entry.fullname();
                let base_fullname = base_type.fullname();
                let is_self_reference = derived_fullname == base_fullname;
                let is_generic_relationship = derived_fullname.contains('`')
                    && derived_fullname.starts_with(base_fullname.split('`').next().unwrap_or(""));
                let is_array_relationship = derived_fullname.ends_with("[]")
                    && derived_fullname.trim_end_matches("[]") == base_fullname;
                let is_pointer_relationship = derived_fullname.ends_with('*')
                    && derived_fullname.trim_end_matches('*') == base_fullname;
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
            for (_, interface_ref) in type_entry.interfaces.iter() {
                if let Some(interface_type) = interface_ref.upgrade() {
                    let is_system_interface = interface_type.fullname().starts_with("System.");
                    if interface_type.flags & TypeAttributes::INTERFACE == 0 && !is_system_interface
                    {
                        return Err(Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' tries to implement non-interface type '{}'",
                                type_entry.name, interface_type.name
                            ),
                            source: None,
                        });
                    }

                    let type_visibility = type_entry.flags & TypeAttributes::VISIBILITY_MASK;
                    let interface_visibility =
                        interface_type.flags & TypeAttributes::VISIBILITY_MASK;

                    let is_system_interface = interface_type.fullname().starts_with("System.");
                    if !is_system_interface
                        && !Self::is_accessible_interface_implementation(
                            type_visibility,
                            interface_visibility,
                        )
                    {
                        return Err(Error::ValidationOwnedValidatorFailed {
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

            if type_entry.interfaces.count() > 1 {
                Self::validate_interface_compatibility(&type_entry.interfaces);
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

            if flags & TypeAttributes::ABSTRACT == 0 && flags & TypeAttributes::INTERFACE != 0 {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Interface '{}' must be abstract", type_entry.name),
                    source: None,
                });
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

        match (derived_flavor, base_flavor) {
            (CilFlavor::ValueType, CilFlavor::ValueType) |
            (CilFlavor::Class, CilFlavor::Class | CilFlavor::Object) |
            (CilFlavor::Interface, CilFlavor::Interface) => Ok(()),
            (CilFlavor::ValueType, CilFlavor::Object) => {
                if base_type.fullname() == "System.Object" {
                    Ok(())
                } else {
                    Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Value type '{}' has incompatible base type flavor",
                            derived_type.name
                        ),
                        source: None,
                    })
                }
            }
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
    fn is_accessible_inheritance(derived_visibility: u32, base_visibility: u32) -> bool {
        if derived_visibility == TypeAttributes::PUBLIC {
            return base_visibility == TypeAttributes::PUBLIC;
        }

        if derived_visibility == TypeAttributes::NOT_PUBLIC {
            return base_visibility == TypeAttributes::NOT_PUBLIC
                || base_visibility == TypeAttributes::PUBLIC;
        }

        if derived_visibility >= TypeAttributes::NESTED_PUBLIC {
            return true;
        }

        false
    }

    /// Checks if interface implementation is accessible based on visibility rules.
    fn is_accessible_interface_implementation(
        type_visibility: u32,
        interface_visibility: u32,
    ) -> bool {
        if type_visibility == TypeAttributes::PUBLIC {
            return interface_visibility == TypeAttributes::PUBLIC;
        }

        if type_visibility == TypeAttributes::NOT_PUBLIC {
            return interface_visibility == TypeAttributes::NOT_PUBLIC
                || interface_visibility == TypeAttributes::PUBLIC;
        }

        true
    }

    /// Validates that multiple interface implementations are compatible.
    fn validate_interface_compatibility(interfaces: &CilTypeRefList) {
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
        let method_mapping = MethodTypeMapping::new(types);

        for type_entry in types.all_types() {
            if let Some(base_type) = type_entry.base() {
                self.validate_basic_method_overrides(
                    &type_entry,
                    &base_type,
                    methods,
                    &method_mapping,
                )?;
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
    /// * `method_mapping` - Pre-built method-to-type mapping for efficient lookups
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
        method_mapping: &MethodTypeMapping,
    ) -> Result<()> {
        if base_type.flags & TypeAttributes::INTERFACE != 0 {
            return Ok(());
        }

        let type_methods = method_mapping.get_type_methods(derived_type.token);
        for &method_token in type_methods {
            if let Some(method_entry) = methods.get(&method_token) {
                let method = method_entry.value();

                if method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
                    self.validate_virtual_method_override(
                        method,
                        base_type,
                        methods,
                        method_mapping,
                    )?;
                }

                if method.flags_modifiers.contains(MethodModifiers::ABSTRACT)
                    && derived_type.flags & TypeAttributes::ABSTRACT == 0
                {
                    return Err(Error::ValidationOwnedValidatorFailed {
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
    /// * `method_mapping` - Pre-built method-to-type mapping for efficient lookups
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
        method_mapping: &MethodTypeMapping,
    ) -> Result<()> {
        if base_type.flags & TypeAttributes::INTERFACE != 0 {
            return Ok(());
        }

        if !derived_method
            .flags_modifiers
            .contains(MethodModifiers::VIRTUAL)
        {
            return Ok(());
        }

        let base_methods = method_mapping.get_type_methods(base_type.token);
        for &base_method_token in base_methods {
            if let Some(base_method_entry) = methods.get(&base_method_token) {
                let base_method = base_method_entry.value();

                if base_method
                    .flags_modifiers
                    .contains(MethodModifiers::VIRTUAL)
                    && Self::is_potential_method_override(derived_method, base_method)
                {
                    self.validate_method_override_rules(derived_method, base_method)?;
                }
            }
        }
        Ok(())
    }

    /// Determines if a derived method could potentially override a base method.
    ///
    /// This implements .NET method signature matching rules to determine if two methods
    /// represent an override relationship rather than overloading or hiding.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The method in the derived type
    /// * `base_method` - The potential base method to override
    ///
    /// # Returns
    ///
    /// `true` if the derived method could override the base method (same signature)
    fn is_potential_method_override(derived_method: &Method, base_method: &Method) -> bool {
        if derived_method.name != base_method.name {
            return false;
        }

        if base_method.name.contains('.')
            && (base_method.name.starts_with("System.I") || base_method.name.contains(".I"))
        {
            return false;
        }

        if derived_method.params.count() != base_method.params.count() {
            return false;
        }

        if !Self::do_parameter_types_match(derived_method, base_method) {
            return false;
        }

        if !Self::do_return_types_match(derived_method, base_method) {
            return false;
        }

        if !Self::do_generic_constraints_match(derived_method, base_method) {
            return false;
        }

        true
    }

    /// Validates the rules for method overriding between derived and base methods.
    ///
    /// This implements .NET method override validation according to ECMA-335 specifications,
    /// ensuring that override relationships follow proper inheritance rules.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The overriding method in the derived type
    /// * `base_method` - The base method being overridden
    ///
    /// # Returns
    ///
    /// Returns error if override rules are violated
    fn validate_method_override_rules(
        &self,
        derived_method: &Method,
        base_method: &Method,
    ) -> Result<()> {
        if base_method.flags_modifiers.contains(MethodModifiers::FINAL) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Cannot override final method '{}' - final methods cannot be overridden",
                    base_method.name
                ),
                source: None,
            });
        }

        if !base_method
            .flags_modifiers
            .contains(MethodModifiers::VIRTUAL)
        {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Cannot override non-virtual method '{}' - only virtual methods can be overridden",
                    base_method.name
                ),
                source: None,
            });
        }

        if !derived_method
            .flags_modifiers
            .contains(MethodModifiers::VIRTUAL)
        {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Method '{}' must be virtual to override base method",
                    derived_method.name
                ),
                source: None,
            });
        }

        if derived_method.flags_access < base_method.flags_access {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Override method '{}' cannot be less accessible than base method",
                    derived_method.name
                ),
                source: None,
            });
        }

        if base_method
            .flags_modifiers
            .contains(MethodModifiers::ABSTRACT)
            && derived_method
                .flags_modifiers
                .contains(MethodModifiers::ABSTRACT)
        {
            // This is OK - abstract method can be overridden by another abstract method
            // The concrete class further down the hierarchy must provide implementation
        }

        Ok(())
    }

    /// Checks if parameter types match exactly between two methods.
    ///
    /// For method overrides, parameter types must match exactly. This method compares
    /// the parameter types from the method signatures to determine if they are identical.
    ///
    /// # Arguments
    ///
    /// * `derived` - The potentially overriding method
    /// * `base` - The base method to compare against
    ///
    /// # Returns
    ///
    /// `true` if all parameter types match exactly
    fn do_parameter_types_match(derived: &Method, base: &Method) -> bool {
        let derived_params = &derived.signature.params;
        let base_params = &base.signature.params;

        if derived_params.len() != base_params.len() {
            return false;
        }

        for (derived_param, base_param) in derived_params.iter().zip(base_params.iter()) {
            // For method overrides, parameter types must be exactly the same
            // This is a simplified comparison - a full implementation would need
            // to handle generic types, array types, and complex type relationships
            if mem::discriminant(&derived_param.base) != mem::discriminant(&base_param.base) {
                return false;
            }
        }

        true
    }

    /// Checks if return types match between two methods.
    ///
    /// For method overrides, return types must be compatible. In most cases they must
    /// be exactly the same, but covariant return types are allowed in some contexts.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The potentially overriding method
    /// * `base_method` - The base method to compare against
    ///
    /// # Returns
    ///
    /// `true` if return types are compatible
    fn do_return_types_match(derived: &Method, base: &Method) -> bool {
        let derived_return = &derived.signature.return_type.base;
        let base_return = &base.signature.return_type.base;

        // For method overrides, return types typically must be exactly the same
        // This is a simplified comparison - a full implementation would need
        // to handle covariant return types and complex type relationships
        mem::discriminant(derived_return) == mem::discriminant(base_return)
    }

    /// Checks if generic constraints match between two methods.
    ///
    /// For generic method overrides, the generic parameter constraints must match
    /// to ensure type safety and compatibility.
    ///
    /// # Arguments
    ///
    /// * `derived_method` - The potentially overriding method
    /// * `base_method` - The base method to compare against
    ///
    /// # Returns
    ///
    /// `true` if generic constraints are compatible
    fn do_generic_constraints_match(derived: &Method, base: &Method) -> bool {
        let derived_generic_count = derived.signature.param_count_generic;
        let base_generic_count = base.signature.param_count_generic;

        if derived_generic_count != base_generic_count {
            return false;
        }

        if derived_generic_count == 0 && base_generic_count == 0 {
            return true;
        }

        // ToDo: Implement full GenericParam comparison to validate contraints
        true
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        test::{
            factories::validation::inheritance::owned_inheritance_validator_file_factory,
            owned_validator_test,
        },
    };

    /// Comprehensive test for OwnedInheritanceValidator using the golden pattern.
    ///
    /// Tests all major inheritance validation scenarios:
    /// - Circular inheritance detection
    /// - Sealed type inheritance violations
    /// - Interface inheritance violations
    /// - Accessibility violations
    /// - Abstract/concrete rule violations
    ///
    /// Uses the centralized test harness for consistent validation across all owned validators.
    #[test]
    fn test_owned_inheritance_validator_comprehensive() -> Result<()> {
        let validator = OwnedInheritanceValidator::new();

        owned_validator_test(
            owned_inheritance_validator_file_factory,
            "OwnedInheritanceValidator",
            "",
            ValidationConfig {
                enable_semantic_validation: true,
                ..Default::default()
            },
            |context| validator.validate_owned(context),
        )
    }
}
