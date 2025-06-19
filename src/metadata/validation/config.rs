//! # Validation Configuration for Metadata Loading
//!
//! This module provides comprehensive configuration options for metadata validation during
//! .NET assembly loading. The validation system operates in multiple layers, from basic
//! structural integrity to complex semantic consistency checks.
//!
//! ## Validation Categories
//!
//! The validation system is organized into several categories:
//!
//! - **Structural Validation**: Basic format integrity, token validity, heap references
//! - **Cross-Table Validation**: Consistency between related metadata tables
//! - **Field Layout Validation**: Memory layout validation and overlap detection
//! - **Type System Validation**: Inheritance chains, generic constraints, type compatibility
//! - **Semantic Validation**: ECMA-335 semantic rules, access modifiers, abstract/concrete rules
//! - **Method Validation**: Constructor rules, virtual method consistency, signature validation
//! - **Token Validation**: Cross-reference consistency and relationship validation
//!
//! ## Usage
//!
//! The validation configuration can be tailored for different scenarios:
//!
//!
//! The `ValidationConfig` provides predefined configurations for different scenarios:
//! production use with balanced validation, minimal validation for maximum performance,
//! strict validation for maximum safety, and support for custom configurations.
//!
//! ## Thread Safety
//!
//! `ValidationConfig` is `Copy` and immutable, making it safe to share between threads.
//! Configuration is typically set once and used across multiple assembly loading operations.
//!
//! ## Compliance
//!
//! The validation system implements checks based on:
//! - ECMA-335 CLI Standard specification
//! - .NET runtime validation behavior analysis
//! - Common metadata format issues and edge cases\

/// Configuration for metadata validation during assembly loading.
///
/// Controls the depth and scope of validation performed during .NET assembly loading.
/// The loading process already performs essential structural validation (token format,
/// table structure, heap references, signature format, basic type references). This
/// configuration controls additional semantic validation that requires cross-table analysis.
///
/// ## Design Philosophy
///
/// The validation system is designed with performance in mind:
/// - Basic structural validation is always recommended
/// - Expensive semantic validations can be selectively disabled
/// - Configuration presets provide common validation scenarios
/// - Fine-grained control allows optimization for specific use cases
///
/// ## Validation Layers
///
/// 1. **Structural**: Token integrity, heap references (fast)
/// 2. **Cross-table**: Reference consistency between tables (moderate)
/// 3. **Semantic**: ECMA-335 compliance, logical consistency (variable)
/// 4. **Type system**: Inheritance, generics, constraints (expensive)
///
/// ## Thread Safety
///
/// This struct is `Copy` and all fields are simple values, making it inherently
/// thread-safe for concurrent use across multiple assembly loading operations.
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
    /// Creates a disabled validation configuration for maximum performance.
    ///
    /// **⚠️ Warning**: This disables ALL validation checks, including basic structural
    /// validation. Use only when you absolutely trust the assembly format and need
    /// maximum performance. Malformed assemblies may cause panics or undefined behavior.
    ///
    /// ## Use Cases
    ///
    /// - Parsing known-good assemblies in performance-critical loops
    /// - Bulk processing of trusted assembly collections
    /// - Scenarios where external validation has already been performed
    ///
    /// ## Risks
    ///
    /// - No protection against malformed metadata
    /// - Potential for crashes on invalid data
    /// - Silent acceptance of ECMA-335 violations
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

    /// Creates a minimal validation configuration for maximum performance.
    ///
    /// Enables only essential structural validation while disabling expensive semantic
    /// checks. Provides a good balance between safety and performance for most use cases.
    ///
    /// ## What's Validated
    ///
    /// - Basic token format and resolution
    /// - Table structure integrity
    /// - Heap reference validity
    /// - Signature format correctness
    ///
    /// ## What's Skipped
    ///
    /// - Cross-table relationship validation
    /// - Type system consistency checks
    /// - Semantic rule enforcement
    /// - Method signature validation
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

    /// Creates a comprehensive validation configuration for maximum safety.
    ///
    /// Enables all validation features to catch every possible metadata issue.
    /// Recommended for development, testing, and scenarios where correctness
    /// is more important than performance.
    ///
    /// **Note**: May be slow for large assemblies with complex type hierarchies.
    #[must_use]
    pub fn comprehensive() -> Self {
        Self::default()
    }

    /// Creates a validation configuration suitable for production use.
    ///
    /// This configuration mirrors the validation performed by the .NET runtime,
    /// focusing on checks that would cause actual runtime failures. Based on
    /// analysis of `CoreCLR` and runtime source code.
    ///
    /// ## Validation Profile
    ///
    /// - **Structural**: ✅ Essential for basic safety
    /// - **Cross-table**: ✅ Runtime validates cross-references
    /// - **Field layout**: ❌ Runtime handles layout validation differently
    /// - **Type system**: ❌ Runtime validates lazily during type loading
    /// - **Semantic**: ✅ Runtime enforces ECMA-335 semantic rules
    /// - **Method**: ✅ Runtime enforces method constraints
    /// - **Token**: ❌ Runtime validates only critical token references
    ///
    /// This provides excellent runtime compatibility while maintaining good performance.
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

    /// Creates a validation configuration with all checks enabled.
    ///
    /// Similar to [`comprehensive()`](Self::comprehensive) but with explicit emphasis
    /// on strictness. All validation categories are enabled with maximum sensitivity.
    ///
    /// **⚠️ Warning**: Field layout validation may produce false positives on legitimate
    /// overlapping fields (unions, explicit layout structs). Review results carefully
    /// when working with low-level interop types.
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
