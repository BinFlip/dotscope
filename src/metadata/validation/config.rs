//! Validation configuration for metadata loading and assembly validation.
//!
//! This module provides comprehensive configuration options for metadata validation during
//! .NET assembly loading. The validation system operates in multiple layers, from basic
//! structural integrity to complex semantic consistency checks, allowing fine-grained
//! control over validation depth and scope.
//!
//! # Architecture
//!
//! The validation system is organized into several categories with increasing complexity:
//!
//! - **Structural Validation**: Basic format integrity, token validity, heap references
//! - **Cross-Table Validation**: Consistency between related metadata tables
//! - **Field Layout Validation**: Memory layout validation and overlap detection
//! - **Type System Validation**: Inheritance chains, generic constraints, type compatibility
//! - **Semantic Validation**: ECMA-335 semantic rules, access modifiers, abstract/concrete rules
//! - **Method Validation**: Constructor rules, virtual method consistency, signature validation
//! - **Token Validation**: Cross-reference consistency and relationship validation
//!
//! The system operates in two stages:
//! 1. **Raw Validation**: Validates raw assembly data during [`crate::metadata::cilassemblyview::CilAssemblyView`] loading
//! 2. **Owned Validation**: Validates resolved data structures during [`crate::metadata::cilobject::CilObject`] creation
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::config::ValidationConfig`] - Main configuration struct with predefined presets
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Executes validation using the configuration
//! - [`crate::metadata::validation::traits::RawValidator`] - Trait for raw validation implementations
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Trait for owned validation implementations
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::ValidationConfig;
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! // Use production configuration for balanced validation
//! let config = ValidationConfig::production();
//! let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_file_with_validation(&path, config)?;
//!
//! // Use minimal configuration for maximum performance
//! let config = ValidationConfig::minimal();
//! let view = CilAssemblyView::from_file_with_validation(&path, config)?;
//!
//! // Use comprehensive configuration for maximum safety
//! let config = ValidationConfig::comprehensive();
//! let view = CilAssemblyView::from_file_with_validation(&path, config)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. [`crate::metadata::validation::config::ValidationConfig`]
//! is [`Copy`] and immutable, making it safe to share between threads. Configuration is typically
//! set once and used across multiple assembly loading operations.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::cilassemblyview`] - Provides validation during assembly view creation
//! - [`crate::metadata::cilobject`] - Provides validation during object model creation
//! - [`crate::metadata::validation::engine`] - Core validation execution engine
//!
//! # References
//!
//! - [ECMA-335 CLI Standard specification](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [.NET Runtime validation behavior analysis](https://github.com/dotnet/runtime)

/// Configuration for metadata validation during assembly loading.
///
/// Controls the depth and scope of validation performed during .NET assembly loading.
/// The loading process already performs essential structural validation (token format,
/// table structure, heap references, signature format, basic type references). This
/// configuration controls additional semantic validation that requires cross-table analysis.
///
/// # Design Philosophy
///
/// The validation system provides configurable validation depth:
/// - Basic structural validation is always recommended
/// - Semantic validations can be selectively disabled
/// - Configuration presets provide common validation scenarios
/// - Fine-grained control allows optimization for specific use cases
///
/// # Validation Layers
///
/// 1. **Structural**: Token integrity, heap references
/// 2. **Cross-table**: Reference consistency between tables
/// 3. **Semantic**: ECMA-335 compliance, logical consistency
/// 4. **Type system**: Inheritance, generics, constraints
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ValidationConfig;
///
/// // Use production configuration for balanced validation
/// let config = ValidationConfig::production();
/// assert!(config.enable_structural_validation);
/// assert!(config.enable_semantic_validation);
///
/// // Create custom configuration
/// let config = ValidationConfig {
///     enable_structural_validation: true,
///     enable_semantic_validation: false,
///     ..ValidationConfig::minimal()
/// };
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This struct is [`Copy`] and all fields are simple values, making it inherently
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

    /// Enable constraint validation (generic constraints, layout constraints)
    /// Validates generic parameter constraints and field/class layout constraints
    pub enable_constraint_validation: bool,

    /// Maximum nesting depth for nested classes (default: 64)
    pub max_nesting_depth: usize,

    /// Enable raw assembly validation during CilAssemblyView loading (stage 1)
    /// This enables the validation pipeline to run on raw assembly data
    pub enable_raw_validation: bool,

    /// Enable owned data validation during CilObject loading (stage 2)
    /// This enables validation of resolved, owned data structures
    pub enable_owned_validation: bool,
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
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: true,
        }
    }
}

impl ValidationConfig {
    /// Creates a disabled validation configuration.
    ///
    /// **⚠️ Warning**: This disables ALL validation checks, including basic structural
    /// validation. Use only when you absolutely trust the assembly format. Malformed
    /// assemblies may cause panics or undefined behavior.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] with all validation disabled.
    ///
    /// # Use Cases
    ///
    /// - Parsing known-good assemblies in performance-critical loops
    /// - Bulk processing of trusted assembly collections
    /// - Scenarios where external validation has already been performed
    ///
    /// # Risks
    ///
    /// - No protection against malformed metadata
    /// - Potential for crashes on invalid data
    /// - Silent acceptance of ECMA-335 violations
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::disabled();
    /// assert!(!config.enable_structural_validation);
    /// assert!(!config.enable_semantic_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
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
            enable_constraint_validation: false,
            max_nesting_depth: 0,
            enable_raw_validation: false,
            enable_owned_validation: false,
        }
    }

    /// Creates a minimal validation configuration.
    ///
    /// Enables only essential structural validation while disabling semantic
    /// checks. Provides a good balance between safety and functionality for most use cases.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] with minimal validation enabled.
    ///
    /// # What's Validated
    ///
    /// - Basic token format and resolution
    /// - Table structure integrity
    /// - Heap reference validity
    /// - Signature format correctness
    ///
    /// # What's Skipped
    ///
    /// - Cross-table relationship validation
    /// - Type system consistency checks
    /// - Semantic rule enforcement
    /// - Method signature validation
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::minimal();
    /// assert!(config.enable_structural_validation);
    /// assert!(!config.enable_semantic_validation);
    /// assert!(config.enable_raw_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
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
            enable_constraint_validation: false,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: false,
        }
    }

    /// Creates a comprehensive validation configuration for maximum safety.
    ///
    /// Enables all validation features to catch every possible metadata issue.
    /// Recommended for development, testing, and scenarios where correctness
    /// is the primary concern.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] with all validation enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::comprehensive();
    /// assert!(config.enable_structural_validation);
    /// assert!(config.enable_semantic_validation);
    /// assert!(config.enable_type_system_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn comprehensive() -> Self {
        Self::default()
    }

    /// Creates a validation configuration suitable for production use.
    ///
    /// This configuration mirrors the validation performed by the .NET runtime,
    /// focusing on checks that would cause actual runtime failures. Based on
    /// analysis of [`CoreCLR`](https://github.com/dotnet/runtime) and runtime source code.
    /// Updated to reflect complete validation framework implementation.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] matching runtime validation.
    ///
    /// # Validation Profile (.NET Runtime Equivalence)
    ///
    /// - **Structural**: ✅ Essential for basic safety and metadata integrity
    /// - **Cross-table**: ✅ Runtime validates cross-references during loading
    /// - **Field layout**: ✅ Runtime validates explicit layout constraints
    /// - **Type system**: ✅ Runtime validates inheritance and generic constraints
    /// - **Semantic**: ✅ Runtime enforces ECMA-335 semantic rules
    /// - **Method**: ✅ Runtime enforces method signature and override constraints
    /// - **Token**: ✅ Runtime validates token references for security
    /// - **Constraint**: ✅ Runtime validates generic and layout constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::production();
    /// assert!(config.enable_structural_validation);
    /// assert!(config.enable_semantic_validation);
    /// assert!(config.enable_field_layout_validation);
    /// assert!(config.enable_constraint_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn production() -> Self {
        Self {
            enable_structural_validation: true, // Runtime validates metadata structure and format
            enable_cross_table_validation: true, // Runtime validates cross-references during loading
            enable_field_layout_validation: true, // Runtime validates explicit layout constraints
            enable_type_system_validation: true, // Runtime validates inheritance and generic constraints
            enable_semantic_validation: true,    // Runtime enforces ECMA-335 semantic rules
            enable_method_validation: true, // Runtime enforces method signature and override constraints
            enable_token_validation: true,  // Runtime validates token references for security
            enable_constraint_validation: true, // Runtime validates generic and layout constraints
            max_nesting_depth: 64,          // Standard runtime nesting limit
            enable_raw_validation: true,    // Enable raw validation for safety and format integrity
            enable_owned_validation: true,  // Enable owned validation for semantic completeness
        }
    }

    /// Creates a validation configuration with all checks enabled.
    ///
    /// Similar to [`comprehensive()`](Self::comprehensive) but with explicit emphasis
    /// on strictness. All validation categories are enabled with maximum sensitivity.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] with strict validation enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::strict();
    /// assert!(config.enable_field_layout_validation);
    /// assert!(config.enable_constraint_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
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
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: true,
        }
    }

    /// Returns true if raw validation should be performed during [`crate::metadata::cilassemblyview::CilAssemblyView`] loading.
    ///
    /// # Returns
    ///
    /// Returns `true` if raw validation stage should be executed, `false` otherwise.
    #[must_use]
    pub fn should_validate_raw(&self) -> bool {
        self.enable_raw_validation
    }

    /// Returns true if owned validation should be performed during [`crate::metadata::cilobject::CilObject`] loading.
    ///
    /// # Returns
    ///
    /// Returns `true` if owned validation stage should be executed, `false` otherwise.
    #[must_use]
    pub fn should_validate_owned(&self) -> bool {
        self.enable_owned_validation
    }

    /// Creates a configuration for raw validation only (stage 1).
    ///
    /// This configuration is suitable for scenarios where you only need basic
    /// structural validation of the raw assembly data without full semantic validation.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] configured for raw validation only.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::raw_only();
    /// assert!(config.should_validate_raw());
    /// assert!(!config.should_validate_owned());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn raw_only() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: false,
            enable_field_layout_validation: false,
            enable_type_system_validation: false,
            enable_semantic_validation: false,
            enable_method_validation: false,
            enable_token_validation: false,
            enable_constraint_validation: false,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: false,
        }
    }

    /// Creates a configuration for owned validation only (stage 2).
    ///
    /// This configuration assumes that raw validation has already been performed
    /// and focuses on validating the resolved, owned data structures.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] configured for owned validation only.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::owned_only();
    /// assert!(!config.should_validate_raw());
    /// assert!(config.should_validate_owned());
    /// assert!(config.enable_semantic_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn owned_only() -> Self {
        Self {
            enable_structural_validation: false,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: false,
            enable_owned_validation: true,
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
        assert!(!disabled.enable_raw_validation);
        assert!(!disabled.enable_owned_validation);

        let minimal = ValidationConfig::minimal();
        assert!(minimal.enable_structural_validation);
        assert!(!minimal.enable_cross_table_validation);
        assert!(!minimal.enable_semantic_validation);
        assert!(!minimal.enable_method_validation);
        assert!(!minimal.enable_token_validation);
        assert!(minimal.enable_raw_validation);
        assert!(!minimal.enable_owned_validation);

        let comprehensive = ValidationConfig::comprehensive();
        assert!(comprehensive.enable_structural_validation);
        assert!(comprehensive.enable_cross_table_validation);
        assert!(comprehensive.enable_field_layout_validation);
        assert!(comprehensive.enable_type_system_validation);
        assert!(comprehensive.enable_semantic_validation);
        assert!(comprehensive.enable_method_validation);
        assert!(comprehensive.enable_token_validation);
        assert!(comprehensive.enable_raw_validation);
        assert!(comprehensive.enable_owned_validation);

        let production = ValidationConfig::production();
        assert!(production.enable_structural_validation);
        assert!(production.enable_cross_table_validation);
        assert!(production.enable_field_layout_validation);
        assert!(production.enable_type_system_validation);
        assert!(production.enable_semantic_validation);
        assert!(production.enable_method_validation);
        assert!(production.enable_token_validation);
        assert!(production.enable_constraint_validation);
        assert!(production.enable_raw_validation);
        assert!(production.enable_owned_validation);
    }

    #[test]
    fn test_default_config() {
        let default = ValidationConfig::default();
        let comprehensive = ValidationConfig::comprehensive();
        assert_eq!(default, comprehensive);
    }

    #[test]
    fn test_validation_stage_methods() {
        let production = ValidationConfig::production();
        assert!(production.should_validate_raw());
        assert!(production.should_validate_owned());

        let disabled = ValidationConfig::disabled();
        assert!(!disabled.should_validate_raw());
        assert!(!disabled.should_validate_owned());

        let raw_only = ValidationConfig::raw_only();
        assert!(raw_only.should_validate_raw());
        assert!(!raw_only.should_validate_owned());
        assert!(raw_only.enable_structural_validation);
        assert!(!raw_only.enable_cross_table_validation);

        let owned_only = ValidationConfig::owned_only();
        assert!(!owned_only.should_validate_raw());
        assert!(owned_only.should_validate_owned());
        assert!(!owned_only.enable_structural_validation);
        assert!(owned_only.enable_cross_table_validation);
    }
}
