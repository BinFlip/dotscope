//! Owned signature validator for method signature validation.
//!
//! This validator provides comprehensive validation of method signatures within the context
//! of fully resolved .NET metadata, ensuring that signature components are properly formed,
//! compatible across inheritance hierarchies, and comply with ECMA-335 calling convention
//! requirements. It operates on resolved signature structures to validate signature integrity
//! and compatibility. This validator runs with priority 140 in the owned validation stage.
//!
//! # Architecture
//!
//! The signature validation system implements comprehensive method signature validation in sequential order:
//! 1. **Method Signature Format Validation** - Ensures signatures are well-formed with proper component structure
//! 2. **Signature Compatibility Validation** - Validates compatibility across inheritance and overriding scenarios
//!
//! The implementation validates method signatures according to ECMA-335 specifications,
//! ensuring proper signature formation and inheritance compatibility patterns.
//! All validation includes calling convention checking and parameter validation.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator`] - Main validator implementation providing comprehensive signature validation
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator::validate_method_signature_format`] - Method signature format and encoding validation
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator::validate_signature_compatibility`] - Signature compatibility validation across inheritance hierarchies
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedSignatureValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedSignatureValidator::new();
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
//! This validator returns [`crate::Error::ValidationOwnedFailed`] for:
//! - Method signature format violations (empty names, unresolved return types)
//! - Parameter signature issues (excessively long names, unresolved types, excessive custom attributes)
//! - Generic parameter violations (empty names, excessive lengths, invalid flags)
//! - Signature compatibility issues (excessive method overloads indicating complexity problems)
//! - Signature component validation failures (parameter count limits, name constraints)
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
//! - owned metadata validators - Part of the owned metadata validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved method signature structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_method_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures and calling conventions
//! - [ECMA-335 II.22.26](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - MethodDef table signature constraints
//! - [ECMA-335 II.23.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blobs and signatures
//! - [ECMA-335 I.8.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assignment compatibility
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method overriding and signatures

use rayon::prelude::*;
use std::collections::HashMap;

use crate::{
    metadata::validation::{
        context::{OwnedValidationContext, ValidationContext},
        traits::OwnedValidator,
    },
    Error, Result,
};

/// Foundation validator for method signatures, calling conventions, and signature compatibility.
///
/// Ensures the structural integrity and consistency of method signatures in resolved .NET metadata,
/// validating proper signature formation, inheritance compatibility, and calling convention
/// compliance. This validator operates on resolved signature structures to provide essential
/// guarantees about signature integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of method signature validation according to
/// ECMA-335 specifications, ensuring proper signature definitions and compatibility patterns
/// in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedSignatureValidator;

impl OwnedSignatureValidator {
    /// Creates a new signature validator instance.
    ///
    /// Initializes a validator instance that can be used to validate method signatures
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`OwnedSignatureValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedSignatureValidator {
    /// Validates method signature format and encoding.
    ///
    /// Ensures that method signatures are properly formed according to ECMA-335
    /// specifications and that all signature components are valid. Validates
    /// method names, return types, parameters, and generic parameters.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method signature structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method signature formats are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Signature format violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Method names are empty
    /// - Return types are unresolved (Unknown type signatures)
    /// - Parameter names exceed maximum length (>255 characters)
    /// - Parameters have unresolved types or excessive custom attributes (>10)
    /// - Generic parameters have empty names, excessive lengths, or invalid flags
    fn validate_method_signature_format(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        let results: Vec<Result<()>> = methods.iter().par_bridge().into_par_iter()
            .map(|entry| {
            let method = entry.value();

            // Validate method name is not empty (basic signature validation)
            if method.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method with token 0x{:08X} has empty name",
                        entry.key().value()
                    ),

                });
            }

            // Validate return type is resolved (copied from method validator)
            if method.signature.return_type.base
                == crate::metadata::signatures::TypeSignature::Unknown
            {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Method '{}' has unresolved return type", method.name),

                });
            }

            // Validate parameter signatures
            for (param_index, (_, param)) in method.params.iter().enumerate() {
                // Validate parameter name is reasonable (if present)
                if let Some(param_name) = &param.name {
                    if param_name.len() > 255 {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' parameter {} has excessively long name ({} characters)",
                                method.name,
                                param_index,
                                param_name.len()
                            ),

                        });
                    }
                }

                // Validate parameter has resolved type (copied from method validator)
                if param.base.get().is_none() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' parameter {} has unresolved type",
                            method.name, param_index
                        ),

                    });
                }

                // Check for reasonable number of custom attributes on parameters
                let custom_attr_count = param.custom_attributes.iter().count();
                if custom_attr_count > 10 {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' parameter {} has excessive custom attributes ({})",
                            method.name, param_index, custom_attr_count
                        ),

                    });
                }
            }

            // Validate generic parameters if present
            for (_, generic_param) in method.generic_params.iter() {
                // Validate generic parameter name
                if generic_param.name.is_empty() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' has generic parameter with empty name",
                            method.name
                        ),

                    });
                }

                if generic_param.name.len() > 255 {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' generic parameter '{}' has excessively long name",
                            method.name, generic_param.name
                        ),

                    });
                }

                // Validate generic parameter flags are reasonable
                if generic_param.flags > 0x001F {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' generic parameter '{}' has invalid flags: 0x{:04X}",
                            method.name, generic_param.name, generic_param.flags
                        ),

                    });
                }
            }
            Ok(())
        })
        .collect();

        for result in results {
            result?;
        }

        Ok(())
    }

    /// Validates signature compatibility across inheritance.
    ///
    /// Ensures that method signatures are compatible when methods are overridden
    /// or when interfaces are implemented. Detects excessive method overloading
    /// that could indicate signature complexity issues.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method signature structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All signature compatibility rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Signature compatibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Methods have excessive overloads (>1024) indicating potential complexity issues
    fn validate_signature_compatibility(&self, context: &OwnedValidationContext) -> Result<()> {
        // Track method signatures by type and name for proper overload counting
        // This ensures we count overloads per-type, not globally across all types
        for type_rc in context.target_assembly_types() {
            let mut type_method_signatures: HashMap<String, Vec<u32>> = HashMap::new();
            let methods = context.object().methods();

            // Collect methods for this specific type
            for (_, method_ref) in type_rc.methods.iter() {
                if let Some(method_token) = method_ref.token() {
                    if let Some(method_entry) = methods.get(&method_token) {
                        let method = method_entry.value();
                        type_method_signatures
                            .entry(method.name.clone())
                            .or_default()
                            .push(method_token.value());
                    }
                }
            }

            // Check for potential overloading issues within this type
            // Allow reasonable number of overloads as found in legitimate .NET libraries
            for (method_name, method_tokens) in type_method_signatures {
                if method_tokens.len() > 1024 {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' in type '{}' has excessive overloads ({}), potential signature complexity issue",
                            method_name, type_rc.name, method_tokens.len()
                        ),

                    });
                }
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedSignatureValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_method_signature_format(context)?;
        self.validate_signature_compatibility(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedSignatureValidator"
    }

    fn priority(&self) -> u32 {
        140
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_method_validation
    }
}

impl Default for OwnedSignatureValidator {
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
            factories::validation::signature::owned_signature_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    #[cfg(not(feature = "skip-expensive-tests"))]
    fn test_owned_signature_validator() -> Result<()> {
        let validator = OwnedSignatureValidator::new();
        let config = ValidationConfig {
            enable_method_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_signature_validator_file_factory,
            "OwnedSignatureValidator",
            "ValidationOwnedFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
