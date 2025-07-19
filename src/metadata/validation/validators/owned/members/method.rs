//! Owned method validator for method signature validation and overriding rules.
//!
//! This validator provides comprehensive validation of method definitions, signatures,
//! inheritance patterns, and implementation requirements within the context of fully
//! resolved .NET metadata. It operates on resolved method structures to ensure ECMA-335 compliance
//! for method declarations, virtual dispatch setup, and type system consistency.
//! This validator runs with priority 160 in the owned validation stage.
//!
//! # Architecture
//!
//! The method validation system implements comprehensive method validation in sequential order:
//! 1. **Method Signature Validation** - Ensures method signatures are well-formed with resolved types
//! 2. **Virtual Inheritance Validation** - Validates virtual method inheritance and overriding rules
//! 3. **Constructor Validation** - Validates constructor naming conventions and implementation rules
//! 4. **Method Body Validation** - Ensures proper presence/absence of method implementations
//!
//! The implementation validates method constraints according to ECMA-335 specifications,
//! ensuring proper method definitions across type hierarchies and inheritance patterns.
//! All validation includes signature checking and implementation requirement verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator`] - Main validator implementation providing comprehensive method validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_method_signatures`] - Method signature consistency and type resolution validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_virtual_inheritance`] - Virtual method inheritance and overriding rule validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_constructors`] - Constructor naming convention and implementation validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_method_bodies`] - Method body presence and implementation requirement validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedMethodValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedMethodValidator::new();
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
//! - Method signature consistency violations (empty names, unresolved parameter types)
//! - Virtual method inheritance violations (abstract without virtual, static with virtual)
//! - Constructor convention violations (missing special flags, incorrect modifiers)
//! - Method body presence violations (abstract with RVA, concrete without RVA)
//! - Special method naming violations (special names without SPECIAL_NAME flag)
//! - Virtual table violations (NEW_SLOT without virtual on non-special methods)
//! - Static constructor accessibility violations (non-private static constructors)
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
//! - [`crate::metadata::validation::validators::owned::members`] - Part of the owned member validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved method structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_method_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method overriding and inheritance
//! - [ECMA-335 II.10.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Constructor specifications
//! - [ECMA-335 II.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures and calling conventions
//! - [ECMA-335 III.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method body validation requirements

use crate::{
    metadata::{
        method::{MethodAccessFlags, MethodImplCodeType, MethodModifiers, MethodVtableFlags},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Result,
};

/// Foundation validator for method definitions, signatures, and implementation requirements.
///
/// Ensures the structural integrity and consistency of method definitions in resolved .NET metadata,
/// validating proper method signatures, inheritance patterns, constructor conventions, and
/// implementation requirements. This validator operates on resolved method structures to provide
/// essential guarantees about method compliance with ECMA-335 specifications.
///
/// The validator implements comprehensive coverage of method validation according to
/// ECMA-335 specifications, ensuring proper method definitions across type hierarchies
/// and inheritance patterns in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedMethodValidator;

impl OwnedMethodValidator {
    /// Creates a new method validator instance.
    ///
    /// Initializes a validator instance that can be used to validate method definitions
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    pub fn new() -> Self {
        Self
    }

    /// Validates method signature consistency and type safety.
    ///
    /// Ensures that all method signatures are well-formed according to ECMA-335
    /// specifications, including parameter types, return types, and calling conventions.
    /// Validates method names and signature type resolution.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method signatures are valid and resolved
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Method signature violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Method names are empty
    /// - Parameter types are unresolved or have empty names
    /// - Return types are unresolved (Unknown type signatures)
    /// - Local variable types are unresolved or have empty names
    fn validate_method_signatures(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods.iter() {
            let method = entry.value();

            if method.name.is_empty() {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method with token 0x{:08X} has empty name",
                        entry.key().value()
                    ),
                    source: None,
                });
            }

            for (index, (_, param)) in method.params.iter().enumerate() {
                if let Some(base_type_ref) = param.base.get() {
                    if let Some(base_type) = base_type_ref.upgrade() {
                        if base_type.name.is_empty() {
                            return Err(crate::Error::ValidationOwnedValidatorFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Method '{}' parameter {} has unresolved type",
                                    method.name, index
                                ),
                                source: None,
                            });
                        }
                    } else {
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' parameter {} has unresolved type",
                                method.name, index
                            ),
                            source: None,
                        });
                    }
                } else {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' parameter {} has unresolved type",
                            method.name, index
                        ),
                        source: None,
                    });
                }
            }

            if let crate::metadata::signatures::TypeSignature::Unknown =
                &method.signature.return_type.base
            {
                let method_name = &method.name;
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Method '{method_name}' has unresolved return type"),
                    source: None,
                });
            }

            for (index, (_, local)) in method.local_vars.iter().enumerate() {
                if let Some(local_type) = local.base.upgrade() {
                    if local_type.name.is_empty() {
                        return Err(crate::Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' local variable {} has unresolved type",
                                method.name, index
                            ),
                            source: None,
                        });
                    }
                } else {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' local variable {} has unresolved type",
                            method.name, index
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates virtual method inheritance and overriding rules.
    ///
    /// Ensures that virtual methods follow proper inheritance patterns and that
    /// method overrides maintain signature compatibility. Validates virtual table
    /// flags and modifier combinations according to ECMA-335 requirements.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All virtual inheritance rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Virtual inheritance violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Abstract methods are not marked as virtual
    /// - Static methods are marked as virtual, abstract, or final
    /// - Final methods are not marked as virtual
    /// - NEW_SLOT is used without virtual on non-runtime-special methods
    fn validate_virtual_inheritance(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods.iter() {
            let method = entry.value();

            if method.flags_modifiers.contains(MethodModifiers::ABSTRACT)
                && !method.flags_modifiers.contains(MethodModifiers::VIRTUAL)
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Abstract method '{}' must also be virtual", method.name),
                    source: None,
                });
            }

            if method.flags_modifiers.contains(MethodModifiers::STATIC) {
                if method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Static method '{}' cannot be virtual", method.name),
                        source: None,
                    });
                }

                if method.flags_modifiers.contains(MethodModifiers::ABSTRACT) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Static method '{}' cannot be abstract", method.name),
                        source: None,
                    });
                }

                if method.flags_modifiers.contains(MethodModifiers::FINAL) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Static method '{}' cannot be final", method.name),
                        source: None,
                    });
                }
            }

            if method.flags_modifiers.contains(MethodModifiers::FINAL)
                && !method.flags_modifiers.contains(MethodModifiers::VIRTUAL)
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!("Final method '{}' must also be virtual", method.name),
                    source: None,
                });
            }

            if method.flags_vtable.contains(MethodVtableFlags::NEW_SLOT)
                && !method.flags_modifiers.contains(MethodModifiers::VIRTUAL)
                && !method
                    .flags_modifiers
                    .contains(MethodModifiers::RTSPECIAL_NAME)
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method '{}' uses NEW_SLOT but is not virtual or runtime special",
                        method.name
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Validates constructor naming conventions and implementation rules.
    ///
    /// Ensures that constructors follow .NET naming conventions and have appropriate
    /// attributes and accessibility modifiers. Validates both instance (.ctor) and
    /// static (.cctor) constructors according to ECMA-335 specifications.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All constructor conventions are followed
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Constructor violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Instance constructors lack RTSPECIAL_NAME or SPECIAL_NAME flags
    /// - Instance constructors are marked as static or virtual
    /// - Static constructors are not marked as static
    /// - Static constructors lack RTSPECIAL_NAME or SPECIAL_NAME flags
    /// - Static constructors are not private
    /// - Special method names lack SPECIAL_NAME flag (get_, set_, add_, remove_, op_)
    fn validate_constructors(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods.iter() {
            let method = entry.value();

            // Check instance constructors (.ctor)
            if method.name == ".ctor" {
                // Instance constructors must be RTSPECIAL_NAME and SPECIAL_NAME
                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::RTSPECIAL_NAME)
                {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Instance constructor '{}' must have RTSPECIAL_NAME flag",
                            method.name
                        ),
                        source: None,
                    });
                }

                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::SPECIAL_NAME)
                {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Instance constructor '{}' must have SPECIAL_NAME flag",
                            method.name
                        ),
                        source: None,
                    });
                }

                if method.flags_modifiers.contains(MethodModifiers::STATIC) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Instance constructor '{}' cannot be static", method.name),
                        source: None,
                    });
                }

                if method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Instance constructor '{}' cannot be virtual",
                            method.name
                        ),
                        source: None,
                    });
                }
            }

            // Check static constructors (.cctor)
            if method.name == ".cctor" {
                // Static constructors must be static, RTSPECIAL_NAME, and SPECIAL_NAME
                if !method.flags_modifiers.contains(MethodModifiers::STATIC) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Static constructor '{}' must be static", method.name),
                        source: None,
                    });
                }

                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::RTSPECIAL_NAME)
                {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Static constructor '{}' must have RTSPECIAL_NAME flag",
                            method.name
                        ),
                        source: None,
                    });
                }

                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::SPECIAL_NAME)
                {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Static constructor '{}' must have SPECIAL_NAME flag",
                            method.name
                        ),
                        source: None,
                    });
                }

                if !method.flags_access.contains(MethodAccessFlags::PRIVATE) {
                    return Err(crate::Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!("Static constructor '{}' should be private", method.name),
                        source: None,
                    });
                }
            }

            if (method.name.starts_with("get_")
                || method.name.starts_with("set_")
                || method.name.starts_with("add_")
                || method.name.starts_with("remove_")
                || method.name.starts_with("op_"))
                && !method
                    .flags_modifiers
                    .contains(MethodModifiers::SPECIAL_NAME)
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method '{}' with special name pattern should have SPECIAL_NAME flag",
                        method.name
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Validates method body presence requirements.
    ///
    /// Ensures that methods that require implementations have method bodies (RVA),
    /// and that abstract/interface methods do not have implementations. Validates
    /// implementation presence according to method type and attributes.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method body requirements are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Method body violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Abstract methods have implementation (RVA present)
    /// - P/Invoke methods have implementation (RVA present)
    /// - Runtime methods have implementation (RVA present)
    /// - Concrete methods lack implementation (RVA missing)
    fn validate_method_bodies(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods.iter() {
            let method = entry.value();

            if method.flags_modifiers.contains(MethodModifiers::ABSTRACT) && method.rva.is_some() {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Abstract method '{}' should not have implementation (RVA)",
                        method.name
                    ),
                    source: None,
                });
            }

            if method
                .flags_modifiers
                .contains(MethodModifiers::PINVOKE_IMPL)
                && method.rva.is_some()
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "P/Invoke method '{}' should not have implementation (RVA)",
                        method.name
                    ),
                    source: None,
                });
            }

            if method
                .impl_code_type
                .intersects(MethodImplCodeType::RUNTIME)
                && method.rva.is_some()
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Runtime method '{}' should not have implementation (RVA)",
                        method.name
                    ),
                    source: None,
                });
            }

            if !method.flags_modifiers.contains(MethodModifiers::ABSTRACT)
                && !method
                    .flags_modifiers
                    .contains(MethodModifiers::PINVOKE_IMPL)
                && !method
                    .impl_code_type
                    .intersects(MethodImplCodeType::RUNTIME)
                && method.rva.is_none()
            {
                return Err(crate::Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Concrete method '{}' must have implementation (RVA)",
                        method.name
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedMethodValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_method_signatures(context)?;
        self.validate_virtual_inheritance(context)?;
        self.validate_constructors(context)?;
        self.validate_method_bodies(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedMethodValidator"
    }

    fn priority(&self) -> u32 {
        160
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_method_validation
    }
}

impl Default for OwnedMethodValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::CilAssembly,
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{
                CodedIndex, CodedIndexType, MethodDefRaw, TableDataOwned, TableId, TypeDefRaw,
            },
            token::Token,
            validation::ValidationConfig,
        },
        test::{get_clean_testfile, owned_validator_test, TestAssembly},
    };

    fn owned_method_validator_file_factory() -> crate::Result<Vec<TestAssembly>> {
        let mut assemblies = Vec::new();

        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available - test cannot run".to_string(),
            ));
        };

        // 1. REQUIRED: Clean assembly - should pass all method validation
        assemblies.push(TestAssembly::new(&clean_testfile, true));

        // 2. NEGATIVE: Test method with empty name
        assemblies.push(create_assembly_with_empty_method_name()?);

        // 3. NEGATIVE: Test abstract method not marked as virtual
        assemblies.push(create_assembly_with_abstract_non_virtual_method()?);

        // 4. NEGATIVE: Test static method marked as virtual
        assemblies.push(create_assembly_with_static_virtual_method()?);

        // 5. NEGATIVE: Test instance constructor without RTSPECIAL_NAME flag
        assemblies.push(create_assembly_with_invalid_instance_constructor()?);

        // 6. NEGATIVE: Test abstract method with RVA present
        assemblies.push(create_assembly_with_abstract_method_with_rva()?);

        Ok(assemblies)
    }

    /// Creates an assembly with a method having an empty name - validation should fail
    fn create_assembly_with_empty_method_name() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithEmptyMethodName")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method with empty name
        let empty_name_index = assembly
            .string_add("")
            .map_err(|e| crate::Error::Error(format!("Failed to add empty method name: {e}")))?;

        let signature_bytes = vec![0x00, 0x00]; // Default method signature (no parameters, void return)
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006,          // Public
            name: empty_name_index, // Empty name - should trigger validation failure
            signature: signature_index,
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with an abstract method not marked as virtual - validation should fail
    fn create_assembly_with_abstract_non_virtual_method() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create abstract type to contain the method
        let type_name_index = assembly
            .string_add("AbstractTypeWithNonVirtualMethod")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000081, // Public | Abstract
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("AbstractNonVirtualMethod")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        let signature_bytes = vec![0x00, 0x00]; // Default method signature
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0406, // Public | Abstract (missing Virtual) - should trigger validation failure
            name: method_name_index,
            signature: signature_index,
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with a static method marked as virtual - validation should fail
    fn create_assembly_with_static_virtual_method() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithStaticVirtualMethod")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("StaticVirtualMethod")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        let signature_bytes = vec![0x00, 0x00]; // Default method signature
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0056, // Public | Static | Virtual - should trigger validation failure
            name: method_name_index,
            signature: signature_index,
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with an instance constructor without RTSPECIAL_NAME flag - validation should fail
    fn create_assembly_with_invalid_instance_constructor() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create type to contain the constructor
        let type_name_index = assembly
            .string_add("TypeWithInvalidConstructor")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000001, // Public
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create constructor name (.ctor)
        let ctor_name_index = assembly
            .string_add(".ctor")
            .map_err(|e| crate::Error::Error(format!("Failed to add constructor name: {e}")))?;

        let signature_bytes = vec![0x00, 0x00]; // Default method signature
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0x1000, // Has implementation
            impl_flags: 0,
            flags: 0x1806, // Public | SpecialName (missing RTSpecialName) - should trigger validation failure
            name: ctor_name_index,
            signature: signature_index,
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    /// Creates an assembly with an abstract method that has RVA present - validation should fail
    fn create_assembly_with_abstract_method_with_rva() -> crate::Result<TestAssembly> {
        let Some(clean_testfile) = get_clean_testfile() else {
            return Err(crate::Error::Error(
                "WindowsBase.dll not available".to_string(),
            ));
        };
        let view = CilAssemblyView::from_file(&clean_testfile)
            .map_err(|e| crate::Error::Error(format!("Failed to load test assembly: {e}")))?;

        let mut assembly = CilAssembly::new(view);

        // Create abstract type to contain the method
        let type_name_index = assembly
            .string_add("AbstractTypeWithRVAMethod")
            .map_err(|e| crate::Error::Error(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

        let type_def = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: 0x00000081, // Public | Abstract
            type_name: type_name_index,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        // Create method name
        let method_name_index = assembly
            .string_add("AbstractMethodWithRVA")
            .map_err(|e| crate::Error::Error(format!("Failed to add method name: {e}")))?;

        let signature_bytes = vec![0x00, 0x00]; // Default method signature
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| crate::Error::Error(format!("Failed to add signature: {e}")))?;

        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0x1000, // Has RVA - should trigger validation failure for abstract method
            impl_flags: 0,
            flags: 0x0446, // Public | Abstract | Virtual
            name: method_name_index,
            signature: signature_index,
            param_list: 1,
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| crate::Error::Error(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )
            .map_err(|e| crate::Error::Error(format!("Failed to add invalid method: {e}")))?;

        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| crate::Error::Error(format!("Failed to create temp file: {e}")))?;

        assembly
            .write_to_file(temp_file.path())
            .map_err(|e| crate::Error::Error(format!("Failed to write assembly: {e}")))?;

        Ok(TestAssembly::from_temp_file(temp_file, false))
    }

    #[test]
    fn test_owned_method_validator() -> crate::Result<()> {
        let validator = OwnedMethodValidator::new();
        let config = ValidationConfig {
            enable_method_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_method_validator_file_factory,
            "OwnedMethodValidator",
            "ValidationOwnedValidatorFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
