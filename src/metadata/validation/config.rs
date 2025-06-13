//! Validation configuration for metadata loading
//!
//! This module provides configuration options for metadata validation,
//! focusing on semantic consistency checks that go beyond what the
//! loading process already validates structurally.

/// Configuration for metadata validation during assembly loading
///
/// The loading process already validates:
/// - Token format and resolution
/// - Table structure and heap references  
/// - Signature format and basic type references
/// - Basic structural integrity
///
/// This validation focuses on semantic consistency that requires cross-table analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ValidationConfig {
    /// Enable basic structural validation during table loading (recommended: always true)
    /// Note: Most structural validation is done during loading; this adds extra safety checks
    pub enable_structural_validation: bool,

    /// Enable expensive cross-table validation after loading (can be disabled for performance)
    /// Validates semantic consistency across metadata tables
    pub enable_cross_table_validation: bool,

    /// Enable field layout validation (overlap detection, offset validation)
    /// Only useful for types with explicit layout; detects problematic overlaps
    pub enable_field_layout_validation: bool,

    /// Enable type system validation (inheritance chains, generic constraints)
    /// Validates logical consistency of type hierarchies and generic constraints
    pub enable_type_system_validation: bool,

    /// Enable semantic validation (method consistency, access modifiers, abstract/concrete rules)
    /// Validates logical consistency of type and method semantics
    pub enable_semantic_validation: bool,

    /// Enable method validation (constructor rules, virtual method consistency)
    /// Validates method-specific semantic rules
    pub enable_method_validation: bool,

    /// Enable token validation (cross-reference consistency, token relationship validation)
    /// Validates token references and relationships beyond basic loading
    pub enable_token_validation: bool,

    /// Maximum nesting depth for nested classes (default: 64)
    pub max_nesting_depth: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            max_nesting_depth: 64,
        }
    }
}

impl ValidationConfig {
    /// Creates a disabled validation configuration for maximum performance
    ///
    /// Disables all validation checks including structural validation.
    /// **Warning**: Use only when you trust the assembly format and need absolute maximum performance.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enable_structural_validation: false,
            enable_cross_table_validation: false,
            enable_field_layout_validation: false,
            enable_type_system_validation: false,
            enable_semantic_validation: false,
            enable_method_validation: false,
            enable_token_validation: false,
            max_nesting_depth: 0,
        }
    }

    /// Creates a minimal validation configuration for maximum performance
    ///
    /// Only enables basic structural validation, disables expensive validations
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: false,
            enable_field_layout_validation: false,
            enable_type_system_validation: false,
            enable_semantic_validation: false,
            enable_method_validation: false,
            enable_token_validation: false,
            max_nesting_depth: 64,
        }
    }

    /// Creates a comprehensive validation configuration for maximum safety
    ///
    /// Enables all validation features (may be slow for large assemblies)
    #[must_use]
    pub fn comprehensive() -> Self {
        Self::default()
    }

    /// Creates a validation configuration suitable for production use
    ///
    /// This configuration mirrors the validation depth and features of the .NET runtime.
    /// Based on runtime source analysis, it focuses on validation that would cause
    /// actual runtime failures, (aiming to) providing parity with CLR/CoreRT validation behavior.
    #[must_use]
    pub fn production() -> Self {
        Self {
            enable_structural_validation: true, // Runtime always validates structure
            enable_cross_table_validation: true, // Runtime validates cross-references
            enable_field_layout_validation: false, // Runtime handles layout differently
            enable_type_system_validation: false, // Runtime validates on-demand during loading
            enable_semantic_validation: true,   // Runtime enforces ECMA-335 semantic rules
            enable_method_validation: true,     // Runtime enforces method constraints
            enable_token_validation: false,     // Runtime validates critical token references
            max_nesting_depth: 64,              // Reasonable runtime limit
        }
    }

    /// Creates a validation configuration with all checks enabled
    ///
    /// **Warning**: Field layout validation may produce false positives on legitimate
    /// overlapping fields (unions, explicit layout structs). Use with caution.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            max_nesting_depth: 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_config_presets() {
        let disabled = ValidationConfig::disabled();
        assert!(!disabled.enable_structural_validation);
        assert!(!disabled.enable_cross_table_validation);
        assert!(!disabled.enable_field_layout_validation);
        assert!(!disabled.enable_type_system_validation);
        assert!(!disabled.enable_semantic_validation);
        assert!(!disabled.enable_method_validation);
        assert!(!disabled.enable_token_validation);
        assert_eq!(disabled.max_nesting_depth, 0);

        let minimal = ValidationConfig::minimal();
        assert!(minimal.enable_structural_validation);
        assert!(!minimal.enable_cross_table_validation);
        assert!(!minimal.enable_semantic_validation);
        assert!(!minimal.enable_method_validation);
        assert!(!minimal.enable_token_validation);

        let comprehensive = ValidationConfig::comprehensive();
        assert!(comprehensive.enable_structural_validation);
        assert!(comprehensive.enable_cross_table_validation);
        assert!(comprehensive.enable_field_layout_validation);
        assert!(comprehensive.enable_type_system_validation);
        assert!(comprehensive.enable_semantic_validation);
        assert!(comprehensive.enable_method_validation);
        assert!(comprehensive.enable_token_validation);

        let production = ValidationConfig::production();
        assert!(production.enable_structural_validation);
        assert!(production.enable_cross_table_validation);
        assert!(!production.enable_field_layout_validation);
        assert!(!production.enable_type_system_validation);
        assert!(production.enable_semantic_validation);
        assert!(production.enable_method_validation);
        assert!(!production.enable_token_validation);
    }

    #[test]
    fn test_default_config() {
        let default = ValidationConfig::default();
        let comprehensive = ValidationConfig::comprehensive();
        assert_eq!(default, comprehensive);
    }
}
