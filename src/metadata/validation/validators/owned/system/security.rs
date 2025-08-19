//! Owned security validator for security constraint validation.
//!
//! This validator provides comprehensive validation of security constraints, permissions,
//! and security attributes within the context of fully resolved .NET metadata. It operates
//! on resolved security structures to validate permission declarations, code access security
//! attributes, and security transparency rules according to ECMA-335 and .NET security model
//! requirements. This validator runs with priority 120 in the owned validation stage.
//!
//! # Architecture
//!
//! The security validation system implements comprehensive security constraint validation in sequential order:
//! 1. **Security Permission Declaration Validation** - Ensures security declarations are properly formed according to ECMA-335
//! 2. **Code Access Security Attribute Validation** - Validates CAS attributes and security model constraints
//! 3. **Security Transparency Validation** - Ensures security-critical and transparent code boundaries are respected
//!
//! The implementation validates security constraints according to ECMA-335 specifications
//! and .NET Framework security model requirements, ensuring proper security declaration
//! formation and preventing security vulnerabilities. All validation includes permission
//! set parsing and security attribute verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator`] - Main validator implementation providing comprehensive security validation
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_security_permission_declarations`] - Security permission declaration and syntax validation
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_code_access_security_attributes`] - CAS attribute validation and security model constraint checking
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_security_transparency`] - Security transparency rule validation and boundary enforcement
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_permission_set_format`] - Permission set XML format and structure validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedSecurityValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedSecurityValidator::new();
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
//! This validator returns [`Error::ValidationOwnedValidatorFailed`] for:
//! - Security permission declaration violations (empty permission sets, invalid XML, suspicious patterns)
//! - Code access security attribute violations (excessive arguments, dangerous content)
//! - Security transparency violations (conflicting critical/transparent attributes, invalid inheritance)
//! - Permission set format violations (malformed XML, missing elements, excessive sizes)
//! - Security attribute usage violations (dangerous patterns, script injection attempts)
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
//! - [`crate::metadata::validation::validators::owned::system`] - Part of the owned system validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved security structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - DeclSecurity table
//! - [ECMA-335 II.21](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom Attributes (security attributes)
//! - [ECMA-335 IV.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Security attributes
//! - [.NET Framework Security Model](https://docs.microsoft.com/en-us/dotnet/framework/security/) - Security model compliance

use crate::{
    metadata::{
        customattributes::{CustomAttributeArgument, CustomAttributeValue},
        typesystem::CilType,
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};
use std::collections::HashSet;

/// Foundation validator for security constraints, permissions, and security attributes.
///
/// Ensures the structural integrity and consistency of security constraints in resolved .NET metadata,
/// validating security permission declarations, code access security attributes, and security transparency
/// rules. This validator operates on resolved security structures to provide essential guarantees
/// about security constraint integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of security validation according to
/// ECMA-335 specifications and .NET Framework security model requirements, ensuring proper
/// security declaration formation and preventing security vulnerabilities in the resolved
/// metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedSecurityValidator;

impl OwnedSecurityValidator {
    /// Creates a new security validator instance.
    ///
    /// Initializes a validator instance that can be used to validate security constraints
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedSecurityValidator {
    /// Validates security permission declarations and syntax.
    ///
    /// Ensures that security declarations are properly formed according to
    /// ECMA-335 specifications and .NET security model requirements.
    /// Currently a placeholder for future implementation when security_declarations API is available.
    ///
    /// # Arguments
    ///
    /// * `_context` - Owned validation context containing resolved security structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All security permission declarations are valid (placeholder implementation)
    /// * `Err(`[`Error::ValidationOwnedValidatorFailed`]`)` - Declaration violations found
    fn validate_security_permission_declarations(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let security_declarations = context.object().security_declarations();

        for entry in security_declarations {
            let (_token, decl_security) = (entry.key(), entry.value());

            // Validate security action is within valid range
            if !Self::is_valid_security_action(decl_security.action.into()) {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Security declaration has invalid action: {:?}",
                        decl_security.action
                    ),
                    source: None,
                });
            }

            // Validate permission set format - for XML format, check the XML content
            let permission_set = &decl_security.permission_set;
            if let crate::metadata::security::PermissionSetFormat::Xml = permission_set.format() {
                let xml_content = String::from_utf8_lossy(permission_set.raw_data());
                self.validate_permission_set_format(&xml_content)?;

                // Check for permission conflicts
                if let Some(conflict) = Self::detect_permission_conflicts(&xml_content) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Security declaration has permission conflict: {conflict}"
                        ),
                        source: None,
                    });
                }
            } else {
                // For binary format, perform basic validation on the raw data
                let raw_data = permission_set.raw_data();
                if raw_data.is_empty() {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: "Security declaration has empty permission set data".to_string(),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates permission set format according to XML schema.
    fn validate_permission_set_format(&self, permission_set: &str) -> Result<()> {
        if permission_set.is_empty() {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Empty permission set in security declaration".to_string(),
                source: None,
            });
        }

        // Check for basic XML structure
        if !permission_set.trim_start().starts_with('<')
            || !permission_set.trim_end().ends_with('>')
        {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Permission set is not valid XML".to_string(),
                source: None,
            });
        }

        // Check for required elements
        if !permission_set.contains("PermissionSet") {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Permission set missing PermissionSet element".to_string(),
                source: None,
            });
        }

        // Validate XML is not excessively large
        if permission_set.len() > 100_000 {
            let set_len = permission_set.len();
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!("Permission set is excessively large ({set_len} characters)"),
                source: None,
            });
        }

        // Check for suspicious patterns
        if Self::has_suspicious_permission_patterns(permission_set) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: "Permission set contains suspicious patterns".to_string(),
                source: None,
            });
        }

        Ok(())
    }

    /// Validates security action values.
    fn is_valid_security_action(action: u16) -> bool {
        matches!(action, 1..=14)
    }

    /// Detects conflicts in permission sets.
    fn detect_permission_conflicts(permission_set: &str) -> Option<String> {
        // Check for deny/assert conflicts
        if permission_set.contains("Deny") && permission_set.contains("Assert") {
            let deny_perms = Self::extract_permission_types(permission_set, "Deny");
            let assert_perms = Self::extract_permission_types(permission_set, "Assert");

            for deny_perm in &deny_perms {
                if assert_perms.contains(deny_perm) {
                    return Some(format!(
                        "Conflict: Deny and Assert on same permission: {deny_perm}"
                    ));
                }
            }
        }

        // Check for PermitOnly conflicts
        if permission_set.contains("PermitOnly") {
            let permit_perms = Self::extract_permission_types(permission_set, "PermitOnly");
            if permit_perms.len() > 1 {
                return Some("Multiple PermitOnly declarations conflict".to_string());
            }
        }

        None
    }

    /// Extracts permission types from permission set XML.
    fn extract_permission_types(permission_set: &str, action: &str) -> Vec<String> {
        let mut permissions = Vec::new();

        // Simplified extraction - real implementation would parse XML properly
        if let Some(start) = permission_set.find(&format!("<{action}")) {
            if let Some(end) = permission_set[start..].find('>') {
                let section = &permission_set[start..start + end];
                if let Some(class_start) = section.find("class=\"") {
                    if let Some(class_end) = section[class_start + 7..].find('"') {
                        let class_name = &section[class_start + 7..class_start + 7 + class_end];
                        permissions.push(class_name.to_string());
                    }
                }
            }
        }

        permissions
    }

    /// Checks for suspicious patterns in permission sets.
    fn has_suspicious_permission_patterns(permission_set: &str) -> bool {
        // Check for potentially dangerous permissions
        let dangerous_patterns = [
            "UnmanagedCode",
            "SkipVerification",
            "ControlEvidence",
            "ControlPolicy",
            "SerializationFormatter",
            "ControlPrincipal",
            "ControlThread",
            "Infrastructure",
            "FullTrust",
        ];

        for pattern in &dangerous_patterns {
            if permission_set.contains(pattern) {
                // Allow legitimate uses but flag excessive usage
                let count = permission_set.matches(pattern).count();
                if count > 3 {
                    return true;
                }
            }
        }

        // Check for script injection patterns
        if permission_set.contains("<script")
            || permission_set.contains("javascript:")
            || permission_set.contains("vbscript:")
        {
            return true;
        }

        // Check for excessively nested structures
        let nesting_level = permission_set.matches('<').count();
        if nesting_level > 100 {
            return true;
        }

        false
    }

    /// Validates code access security (CAS) attribute validation.
    ///
    /// Ensures that CAS attributes are properly applied and don't violate
    /// security model constraints or create security vulnerabilities.
    /// Validates security attributes on types and methods for proper usage.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved security structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All CAS attributes are properly applied
    /// * `Err(`[`Error::ValidationOwnedValidatorFailed`]`)` - CAS attribute violations found
    ///
    /// # Errors
    ///
    /// Returns [`Error::ValidationOwnedValidatorFailed`] if:
    /// - Security attributes have excessive arguments (>10)
    /// - Security attribute content contains dangerous patterns
    fn validate_code_access_security_attributes(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let types = context.object().types();
        let methods = context.object().methods();

        // Validate security attributes on types
        for type_entry in types.all_types() {
            for (_, custom_attr) in type_entry.custom_attributes.iter() {
                if Self::is_security_attribute(custom_attr) {
                    self.validate_security_attribute_usage(custom_attr, "Type", &type_entry.name)?;
                }
            }
        }

        // Validate security attributes on methods
        for method_entry in methods {
            let method = method_entry.value();
            for (_, custom_attr) in method.custom_attributes.iter() {
                if Self::is_security_attribute(custom_attr) {
                    self.validate_security_attribute_usage(custom_attr, "Method", &method.name)?;
                }
            }
        }

        Ok(())
    }

    /// Checks if a custom attribute is a security attribute.
    fn is_security_attribute(custom_attr: &CustomAttributeValue) -> bool {
        // This is simplified - real implementation would check the attribute type
        custom_attr.fixed_args.iter().any(|arg| {
            if let CustomAttributeArgument::String(s) = arg {
                s.contains("Security") || s.contains("Permission") || s.contains("Principal")
            } else {
                false
            }
        })
    }

    /// Validates security attribute usage.
    fn validate_security_attribute_usage(
        &self,
        custom_attr: &CustomAttributeValue,
        target_type: &str,
        target_name: &str,
    ) -> Result<()> {
        // Validate argument count is reasonable
        if custom_attr.fixed_args.len() > 10 {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Security attribute on {} '{}' has excessive arguments ({})",
                    target_type,
                    target_name,
                    custom_attr.fixed_args.len()
                ),
                source: None,
            });
        }

        // Validate string arguments don't contain dangerous content
        for arg in &custom_attr.fixed_args {
            if let CustomAttributeArgument::String(s) = arg {
                if Self::has_dangerous_security_content(s) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Security attribute on {target_type} '{target_name}' contains dangerous content"
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Checks for dangerous content in security attribute strings.
    fn has_dangerous_security_content(content: &str) -> bool {
        let dangerous_patterns = [
            "cmd.exe",
            "powershell",
            "regedit",
            "format c:",
            "rm -rf",
            "del /s",
            "<script",
            "javascript:",
            "vbscript:",
            "file://",
            "\\\\",
        ];

        dangerous_patterns
            .iter()
            .any(|pattern| content.to_lowercase().contains(pattern))
    }

    /// Validates security-critical and security-transparent code.
    ///
    /// Ensures that security transparency attributes are properly applied
    /// and that critical/transparent boundaries are respected. Validates
    /// transparency inheritance and conflicting attribute usage.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved security structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All security transparency rules are followed
    /// * `Err(`[`Error::ValidationOwnedValidatorFailed`]`)` - Transparency violations found
    ///
    /// # Errors
    ///
    /// Returns [`Error::ValidationOwnedValidatorFailed`] if:
    /// - Types are marked both SecurityCritical and SecurityTransparent
    /// - Transparent types inherit from critical base types
    fn validate_security_transparency(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();
        let mut critical_types = HashSet::new();
        let mut transparent_types = HashSet::new();

        // Identify critical and transparent types
        for type_entry in types.all_types() {
            let is_critical = Self::has_security_critical_attribute(&type_entry);
            let is_transparent = Self::has_security_transparent_attribute(&type_entry);

            if is_critical && is_transparent {
                return Err(Error::ValidationOwnedValidatorFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Type '{}' cannot be both SecurityCritical and SecurityTransparent",
                        type_entry.name
                    ),
                    source: None,
                });
            }

            if is_critical {
                critical_types.insert(type_entry.token.value());
            }
            if is_transparent {
                transparent_types.insert(type_entry.token.value());
            }
        }

        // Validate transparency inheritance
        for type_entry in types.all_types() {
            if let Some(base_type) = type_entry.base() {
                let type_token = type_entry.token.value();
                let base_token = base_type.token.value();

                // Transparent types cannot inherit from critical types
                if transparent_types.contains(&type_token) && critical_types.contains(&base_token) {
                    return Err(Error::ValidationOwnedValidatorFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Transparent type '{}' cannot inherit from critical base type",
                            type_entry.name
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Checks if a type has SecurityCritical attribute.
    fn has_security_critical_attribute(type_entry: &CilType) -> bool {
        type_entry.custom_attributes.iter().any(|(_, attr)| {
            attr.fixed_args.iter().any(|arg| {
                if let CustomAttributeArgument::String(s) = arg {
                    s.contains("SecurityCritical")
                } else {
                    false
                }
            })
        })
    }

    /// Checks if a type has SecurityTransparent attribute.
    fn has_security_transparent_attribute(type_entry: &CilType) -> bool {
        type_entry.custom_attributes.iter().any(|(_, attr)| {
            attr.fixed_args.iter().any(|arg| {
                if let CustomAttributeArgument::String(s) = arg {
                    s.contains("SecurityTransparent")
                } else {
                    false
                }
            })
        })
    }
}

impl OwnedValidator for OwnedSecurityValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_security_permission_declarations(context)?;
        self.validate_code_access_security_attributes(context)?;
        self.validate_security_transparency(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedSecurityValidator"
    }

    fn priority(&self) -> u32 {
        120
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedSecurityValidator {
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
            factories::validation::system_security::owned_security_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_security_validator() -> Result<()> {
        let validator = OwnedSecurityValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_security_validator_file_factory,
            "OwnedSecurityValidator",
            "ValidationOwnedValidatorFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
