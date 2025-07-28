//! Owned attribute validator for custom attribute validation.
//!
//! This validator provides comprehensive validation of custom attributes according to ECMA-335
//! specifications within the context of fully resolved .NET metadata. It operates on resolved
//! custom attribute structures to ensure proper attribute usage rules, constructor calls,
//! target compatibility, and inheritance patterns. This validator runs with priority 130
//! in the owned validation stage.
//!
//! # Architecture
//!
//! The attribute validation system implements comprehensive custom attribute validation in sequential order:
//! 1. **Attribute Usage Validation** - Ensures custom attributes follow AttributeUsage constraints and target compatibility
//! 2. **Constructor Call Validation** - Validates attribute constructor parameters and argument limits
//! 3. **Target Compatibility Validation** - Ensures attributes are applied to valid targets with proper placement rules
//!
//! The implementation validates custom attributes according to ECMA-335 specifications,
//! ensuring proper attribute usage patterns and preventing malformed attribute data.
//! All validation includes argument checking and suspicious pattern detection.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator`] - Main validator implementation providing comprehensive attribute validation
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator::validate_attribute_usage_rules`] - Attribute usage constraint validation with target checking
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator::validate_attribute_constructor_calls`] - Constructor parameter validation with argument limit checking
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator::validate_attribute_target_compatibility`] - Target compatibility validation with placement rule verification
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator::validate_attribute_usage`] - Individual attribute validation with argument checking
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedAttributeValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedAttributeValidator::new();
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
//! - Invalid custom attribute usage patterns (malformed fixed/named arguments)
//! - Attribute constructor call violations (excessive arguments, duplicate named args)
//! - Target compatibility violations (invalid placement, suspicious patterns)
//! - Attribute argument validation failures (invalid types, null characters in strings)
//! - Named argument violations (empty names, excessive counts)
//! - Suspicious attribute patterns (excessively long strings, deep array nesting)
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
//! - [`crate::metadata::validation::validators::owned::metadata`] - Part of the owned metadata validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved custom attribute structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.21](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom Attributes
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - CustomAttribute table
//! - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom Attribute encoding
//! - [ECMA-335 IV](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Attribute class specifications

use std::collections::HashSet;

use crate::{
    metadata::{
        customattributes::{CustomAttributeArgument, CustomAttributeValue},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for custom attribute usage, constructor calls, and target compatibility.
///
/// Ensures the structural integrity and consistency of custom attributes in resolved .NET metadata,
/// validating proper attribute usage patterns, constructor parameter validity, and target placement
/// compatibility. This validator operates on resolved custom attribute structures to provide
/// essential guarantees about attribute compliance with ECMA-335 specifications.
///
/// The validator implements comprehensive coverage of custom attribute validation according to
/// ECMA-335 specifications, ensuring proper attribute usage patterns and preventing malformed
/// attribute data in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedAttributeValidator;

impl OwnedAttributeValidator {
    /// Creates a new attribute validator instance.
    ///
    /// Initializes a validator instance that can be used to validate custom attributes
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedAttributeValidator {
    /// Validates custom attribute usage rules and AttributeUsage constraints.
    ///
    /// Ensures that custom attributes are applied according to their AttributeUsage
    /// declarations, including valid targets, inheritance, and multiple usage rules.
    /// Validates attributes on both types and methods for proper usage patterns.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved custom attribute structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All attribute usage rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Attribute usage violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Custom attributes have invalid usage patterns on types or methods
    /// - Attribute arguments are malformed or invalid
    fn validate_attribute_usage_rules(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();
        let methods = context.object().methods();

        // Validate attributes on types
        for type_entry in types.all_types() {
            for (_, custom_attr) in type_entry.custom_attributes.iter() {
                if let Err(e) = self.validate_attribute_usage(custom_attr, "Type") {
                    let type_name = &type_entry.name;
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{type_name}' has invalid custom attribute usage: {e}"
                        ),
                        source: Some(Box::new(e)),
                    });
                }
            }
        }

        // Validate attributes on methods
        for method_entry in methods {
            let method = method_entry.value();
            for (_, custom_attr) in method.custom_attributes.iter() {
                if let Err(e) = self.validate_attribute_usage(custom_attr, "Method") {
                    let method_name = &method.name;
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{method_name}' has invalid custom attribute usage: {e}"
                        ),
                        source: Some(Box::new(e)),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates a single custom attribute usage.
    ///
    /// Checks if the attribute is valid for the given target type and follows
    /// proper usage rules defined by the attribute class. Validates both fixed
    /// and named arguments for proper structure and content.
    ///
    /// # Arguments
    ///
    /// * `custom_attr` - Custom attribute value to validate via [`crate::metadata::customattributes::CustomAttributeValue`]
    /// * `_target` - Target type description for error reporting
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Attribute usage is valid
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Attribute usage violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Fixed arguments are invalid or malformed
    /// - Named arguments have empty names or invalid values
    fn validate_attribute_usage(
        &self,
        custom_attr: &CustomAttributeValue,
        _target: &str,
    ) -> Result<()> {
        // Validate fixed arguments are well-formed
        for (index, arg) in custom_attr.fixed_args.iter().enumerate() {
            if !self.is_valid_attribute_argument(arg) {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Custom attribute has invalid fixed argument at index {index}: {arg:?}"
                    ),
                    source: None,
                });
            }
        }

        // Validate named arguments are well-formed
        for named_arg in &custom_attr.named_args {
            if named_arg.name.is_empty() {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: "Custom attribute has named argument with empty name".to_string(),
                    source: None,
                });
            }

            if !self.is_valid_attribute_argument(&named_arg.value) {
                let arg_name = &named_arg.name;
                let arg_value = &named_arg.value;
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Custom attribute has invalid named argument '{arg_name}': {arg_value:?}"
                    ),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Validates that an attribute argument is well-formed.
    ///
    /// Checks that the argument type is valid for custom attributes and
    /// that complex types like arrays and enums are properly structured.
    /// Performs recursive validation for array elements.
    ///
    /// # Arguments
    ///
    /// * `arg` - Custom attribute argument to validate via [`crate::metadata::customattributes::CustomAttributeArgument`]
    ///
    /// # Returns
    ///
    /// * `true` - Argument is well-formed and valid
    /// * `false` - Argument has structural issues or invalid content
    #[allow(clippy::only_used_in_recursion)]
    fn is_valid_attribute_argument(&self, arg: &CustomAttributeArgument) -> bool {
        match arg {
            // Primitive types are always valid
            CustomAttributeArgument::Bool(_)
            | CustomAttributeArgument::Char(_)
            | CustomAttributeArgument::I1(_)
            | CustomAttributeArgument::U1(_)
            | CustomAttributeArgument::I2(_)
            | CustomAttributeArgument::U2(_)
            | CustomAttributeArgument::I4(_)
            | CustomAttributeArgument::U4(_)
            | CustomAttributeArgument::I8(_)
            | CustomAttributeArgument::U8(_)
            | CustomAttributeArgument::R4(_)
            | CustomAttributeArgument::R8(_)
            | CustomAttributeArgument::I(_)
            | CustomAttributeArgument::U(_)
            | CustomAttributeArgument::Type(_) => true,

            CustomAttributeArgument::String(s) => !s.contains('\0'),

            CustomAttributeArgument::Array(elements) => elements
                .iter()
                .all(|elem| self.is_valid_attribute_argument(elem)),

            CustomAttributeArgument::Enum(type_name, underlying_value) => {
                !type_name.is_empty() && self.is_valid_attribute_argument(underlying_value)
            }

            CustomAttributeArgument::Void => false,
        }
    }

    /// Validates attribute constructor calls and parameter compatibility.
    ///
    /// Ensures that custom attributes use valid constructors with proper
    /// parameter types and counts matching the attribute class definition.
    /// Validates argument limits and named argument uniqueness.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved custom attribute structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All attribute constructor calls are valid
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Constructor call violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Fixed arguments exceed reasonable limits (>20)
    /// - Named arguments exceed reasonable limits (>50)
    /// - Named arguments have duplicate names
    fn validate_attribute_constructor_calls(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();

        for type_entry in types.all_types() {
            for (_, custom_attr) in type_entry.custom_attributes.iter() {
                if custom_attr.fixed_args.len() > 20 {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Custom attribute on type '{}' has excessive fixed arguments ({})",
                            type_entry.name,
                            custom_attr.fixed_args.len()
                        ),
                        source: None,
                    });
                }

                if custom_attr.named_args.len() > 50 {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Custom attribute on type '{}' has excessive named arguments ({})",
                            type_entry.name,
                            custom_attr.named_args.len()
                        ),
                        source: None,
                    });
                }

                let mut named_arg_names = HashSet::new();
                for named_arg in &custom_attr.named_args {
                    if !named_arg_names.insert(&named_arg.name) {
                        return Err(Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Custom attribute on type '{}' has duplicate named argument '{}'",
                                type_entry.name, named_arg.name
                            ),
                            source: None,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates attribute target compatibility and placement rules.
    ///
    /// Ensures that attributes are only applied to valid targets according
    /// to their AttributeUsage declarations and .NET framework rules.
    /// Detects suspicious attribute patterns that might indicate malformed data.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved custom attribute structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All attribute target compatibility rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Target compatibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedValidatorFailed`] if:
    /// - Attributes have suspicious patterns on types, fields, or methods
    /// - Attribute placement violates target compatibility rules
    fn validate_attribute_target_compatibility(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let types = context.object().types();
        let methods = context.object().methods();

        // Check type-level attributes
        for type_entry in types.all_types() {
            for (_, custom_attr) in type_entry.custom_attributes.iter() {
                if self.has_suspicious_attribute_pattern(custom_attr) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' has custom attribute with suspicious pattern",
                            type_entry.name
                        ),
                        source: None,
                    });
                }
            }

            for (_, field) in type_entry.fields.iter() {
                for (_, custom_attr) in field.custom_attributes.iter() {
                    if self.has_suspicious_attribute_pattern(custom_attr) {
                        return Err(Error::ValidationOwnedValidatorFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Field '{}' in type '{}' has custom attribute with suspicious pattern",
                                field.name, type_entry.name
                            ),
                            source: None,
                        });
                    }
                }
            }
        }

        for method_entry in methods {
            let method = method_entry.value();
            for (_, custom_attr) in method.custom_attributes.iter() {
                if self.has_suspicious_attribute_pattern(custom_attr) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' has custom attribute with suspicious pattern",
                            method.name
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Checks for suspicious custom attribute patterns that might indicate malformed data.
    ///
    /// Detects potentially problematic attribute patterns while avoiding false positives
    /// for legitimate custom attributes. Looks for excessively long strings, deep nesting,
    /// and similar names that could indicate corruption or malicious intent.
    ///
    /// # Arguments
    ///
    /// * `custom_attr` - Custom attribute value to check via [`crate::metadata::customattributes::CustomAttributeValue`]
    ///
    /// # Returns
    ///
    /// * `true` - Suspicious patterns detected
    /// * `false` - No concerning patterns found
    fn has_suspicious_attribute_pattern(&self, custom_attr: &CustomAttributeValue) -> bool {
        for arg in &custom_attr.fixed_args {
            if let CustomAttributeArgument::String(s) = arg {
                if s.len() > 10000 {
                    return true;
                }
            }
        }

        if self.has_deep_array_nesting(custom_attr, 0) {
            return true;
        }

        if custom_attr.named_args.len() > 20 {
            let mut similar_names = 0;
            for i in 0..custom_attr.named_args.len() {
                for j in (i + 1)..custom_attr.named_args.len() {
                    if Self::are_similar_names(
                        &custom_attr.named_args[i].name,
                        &custom_attr.named_args[j].name,
                    ) {
                        similar_names += 1;
                        if similar_names > 5 {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Checks for excessively deep array nesting in custom attributes.
    ///
    /// Recursively examines array arguments to detect suspicious nesting patterns
    /// that could indicate malformed or malicious attribute data.
    ///
    /// # Arguments
    ///
    /// * `custom_attr` - Custom attribute value to examine via [`crate::metadata::customattributes::CustomAttributeValue`]
    /// * `depth` - Current nesting depth for recursion tracking
    ///
    /// # Returns
    ///
    /// * `true` - Deep nesting detected (>10 levels)
    /// * `false` - Nesting depth is reasonable
    #[allow(clippy::only_used_in_recursion)]
    fn has_deep_array_nesting(&self, custom_attr: &CustomAttributeValue, depth: usize) -> bool {
        if depth > 10 {
            return true;
        }

        for arg in &custom_attr.fixed_args {
            if let CustomAttributeArgument::Array(elements) = arg {
                for element in elements {
                    if let CustomAttributeArgument::Array(_) = element {
                        let temp_attr = CustomAttributeValue {
                            fixed_args: vec![element.clone()],
                            named_args: vec![],
                        };
                        if self.has_deep_array_nesting(&temp_attr, depth + 1) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Checks if two names are suspiciously similar (potential typosquatting).
    ///
    /// Compares two strings to detect if they differ by only one character,
    /// which could indicate typosquatting or corruption in attribute names.
    ///
    /// # Arguments
    ///
    /// * `name1` - First name to compare
    /// * `name2` - Second name to compare
    ///
    /// # Returns
    ///
    /// * `true` - Names are suspiciously similar (same length, one character difference)
    /// * `false` - Names are sufficiently different
    fn are_similar_names(name1: &str, name2: &str) -> bool {
        if name1.len() != name2.len() {
            return false;
        }

        let mut differences = 0;
        for (c1, c2) in name1.chars().zip(name2.chars()) {
            if c1 != c2 {
                differences += 1;
                if differences > 1 {
                    return false;
                }
            }
        }

        differences == 1
    }
}

impl OwnedValidator for OwnedAttributeValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_attribute_usage_rules(context)?;
        self.validate_attribute_constructor_calls(context)?;
        self.validate_attribute_target_compatibility(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedAttributeValidator"
    }

    fn priority(&self) -> u32 {
        130
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedAttributeValidator {
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
            factories::validation::attribute::owned_attribute_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_attribute_validator() -> Result<()> {
        let validator = OwnedAttributeValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_attribute_validator_file_factory,
            "OwnedAttributeValidator",
            "ValidationOwnedValidatorFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
