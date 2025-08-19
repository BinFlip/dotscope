//! Validation context types and implementations for the unified validation framework.
//!
//! This module provides context abstractions that allow validators to operate on different
//! types of metadata (raw vs owned) while maintaining a unified interface. The context
//! system supports both raw metadata validation (Stage 1) and owned metadata validation (Stage 2).
//!
//! # Architecture
//!
//! The validation system operates through two main context types:
//! - [`crate::metadata::validation::context::RawValidationContext`] - For raw metadata validation during assembly loading
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - For owned metadata validation with resolved data structures
//!
//! Both contexts implement the [`crate::metadata::validation::context::ValidationContext`] trait,
//! providing common functionality while allowing stage-specific operations.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::context::ValidationContext`] - Base trait for all validation contexts
//! - [`crate::metadata::validation::context::RawValidationContext`] - Context for Stage 1 raw validation
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Context for Stage 2 owned validation
//! - [`crate::metadata::validation::context::ValidationStage`] - Enumeration of validation stages
//! - [`crate::metadata::validation::context::factory`] - Factory functions for creating contexts
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawValidationContext, ValidationContext, ValidationConfig, ReferenceScanner};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_file(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//! let config = ValidationConfig::production();
//!
//! // Create raw validation context for loading
//! let context = RawValidationContext::new_for_loading(&view, &scanner, &config);
//! assert!(context.is_loading_validation());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`] when their contained references are.
//! Contexts are typically short-lived and used within a single validation run.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Uses contexts to execute validation
//! - [`crate::metadata::validation::traits`] - Validators receive contexts as parameters
//! - [`crate::metadata::validation::scanner`] - Provides shared reference scanning capabilities

use crate::{
    cilassembly::AssemblyChanges,
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        validation::{config::ValidationConfig, scanner::ReferenceScanner},
    },
};

/// Validation stage indicator for context discrimination.
///
/// Represents the two validation stages in the dotscope validation system:
/// raw metadata validation and owned metadata validation.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ValidationStage;
///
/// let stage = ValidationStage::Raw;
/// assert_eq!(stage, ValidationStage::Raw);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    /// Stage 1: Raw metadata validation using [`crate::metadata::cilassemblyview::CilAssemblyView`]
    Raw,
    /// Stage 2: Owned metadata validation using [`crate::metadata::cilobject::CilObject`]
    Owned,
}

/// Base trait for all validation contexts.
///
/// This trait provides common functionality that all validation contexts must implement,
/// regardless of the validation stage or data type being validated. It ensures consistent
/// access to validation configuration and shared resources.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{ValidationContext, ValidationStage, ValidationConfig};
///
/// fn check_context<T: ValidationContext>(context: &T) {
///     match context.validation_stage() {
///         ValidationStage::Raw => println!("Raw validation context"),
///         ValidationStage::Owned => println!("Owned validation context"),
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// Implementations are thread-safe when their contained references are thread-safe.
pub trait ValidationContext {
    /// Returns the validation stage this context represents.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::context::ValidationStage`] indicating whether
    /// this is a raw or owned validation context.
    fn validation_stage(&self) -> ValidationStage;

    /// Returns a reference to the shared reference scanner.
    ///
    /// The reference scanner is used for efficient cross-table reference validation
    /// and is shared across all validators in a validation run.
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`crate::metadata::validation::scanner::ReferenceScanner`]
    /// for this validation context.
    fn reference_scanner(&self) -> &ReferenceScanner;

    /// Returns a reference to the validation configuration.
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`crate::metadata::validation::config::ValidationConfig`]
    /// that controls validation behavior.
    fn config(&self) -> &ValidationConfig;
}

/// Context for Stage 1 (raw) validation.
///
/// This context is used when validating raw metadata through [`crate::metadata::cilassemblyview::CilAssemblyView`],
/// either during initial loading or when validating assembly modifications.
/// It supports both scenarios through the optional changes parameter.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{RawValidationContext, ValidationConfig, ReferenceScanner};
/// use dotscope::metadata::cilassemblyview::CilAssemblyView;
/// use std::path::Path;
///
/// # let path = Path::new("assembly.dll");
/// let view = CilAssemblyView::from_file(&path)?;
/// let scanner = ReferenceScanner::from_view(&view)?;
/// let config = ValidationConfig::minimal();
///
/// // Create context for loading validation
/// let context = RawValidationContext::new_for_loading(&view, &scanner, &config);
/// assert!(context.is_loading_validation());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This struct is [`Send`] and [`Sync`] when all contained references are thread-safe.
pub struct RawValidationContext<'a> {
    /// The assembly view containing raw metadata
    view: &'a CilAssemblyView,
    /// Optional assembly changes for modification validation
    changes: Option<&'a AssemblyChanges>,
    /// Shared reference scanner for efficient validation
    scanner: &'a ReferenceScanner,
    /// Validation configuration
    config: &'a ValidationConfig,
}

impl<'a> RawValidationContext<'a> {
    /// Creates a new raw validation context for loading validation.
    ///
    /// This constructor is used when validating a [`crate::metadata::cilassemblyview::CilAssemblyView`] during loading,
    /// without any modifications.
    ///
    /// # Arguments
    ///
    /// * `view` - The [`crate::metadata::cilassemblyview::CilAssemblyView`] to validate
    /// * `scanner` - Shared [`crate::metadata::validation::scanner::ReferenceScanner`] for cross-table validation
    /// * `config` - [`crate::metadata::validation::config::ValidationConfig`] controlling validation behavior
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::validation::context::RawValidationContext`] configured for loading validation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::{RawValidationContext, ValidationConfig, ReferenceScanner};
    /// use dotscope::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let path = Path::new("assembly.dll");
    /// let view = CilAssemblyView::from_file(&path)?;
    /// let scanner = ReferenceScanner::from_view(&view)?;
    /// let config = ValidationConfig::production();
    ///
    /// let context = RawValidationContext::new_for_loading(&view, &scanner, &config);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new_for_loading(
        view: &'a CilAssemblyView,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> Self {
        Self {
            view,
            changes: None,
            scanner,
            config,
        }
    }

    /// Creates a new raw validation context for modification validation.
    ///
    /// This constructor is used when validating assembly changes against
    /// an original [`crate::metadata::cilassemblyview::CilAssemblyView`].
    ///
    /// # Arguments
    ///
    /// * `view` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`]
    /// * `changes` - The assembly changes to validate
    /// * `scanner` - Shared [`crate::metadata::validation::scanner::ReferenceScanner`]
    /// * `config` - [`crate::metadata::validation::config::ValidationConfig`] controlling validation
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::validation::context::RawValidationContext`] configured for modification validation.
    pub fn new_for_modification(
        view: &'a CilAssemblyView,
        changes: &'a AssemblyChanges,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> Self {
        Self {
            view,
            changes: Some(changes),
            scanner,
            config,
        }
    }

    /// Returns the assembly changes if this is a modification validation context.
    ///
    /// # Returns
    ///
    /// Returns `Some(&AssemblyChanges)` for modification validation,
    /// `None` for loading validation contexts.
    #[must_use]
    pub fn changes(&self) -> Option<&AssemblyChanges> {
        self.changes
    }

    /// Returns true if this context is for modification validation.
    ///
    /// # Returns
    ///
    /// Returns `true` if this context contains assembly changes, `false` otherwise.
    #[must_use]
    pub fn is_modification_validation(&self) -> bool {
        self.changes.is_some()
    }

    /// Returns true if this context is for loading validation.
    ///
    /// # Returns
    ///
    /// Returns `true` if this context is for loading validation, `false` otherwise.
    #[must_use]
    pub fn is_loading_validation(&self) -> bool {
        self.changes.is_none()
    }

    /// Returns a reference to the underlying [`crate::metadata::cilassemblyview::CilAssemblyView`].
    ///
    /// This provides access to raw metadata for raw validation.
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`crate::metadata::cilassemblyview::CilAssemblyView`] being validated.
    #[must_use]
    pub fn assembly_view(&self) -> &CilAssemblyView {
        self.view
    }
}

impl ValidationContext for RawValidationContext<'_> {
    fn validation_stage(&self) -> ValidationStage {
        ValidationStage::Raw
    }

    fn reference_scanner(&self) -> &ReferenceScanner {
        self.scanner
    }

    fn config(&self) -> &ValidationConfig {
        self.config
    }
}

/// Context for Stage 2 (owned) validation.
///
/// This context is used when validating owned metadata through `CilObject`,
/// which contains fully resolved type information and cross-references.
/// CilObject provides access to both raw and resolved metadata through its public API.
pub struct OwnedValidationContext<'a> {
    /// The CilObject containing both raw and resolved metadata
    object: &'a CilObject,
    /// Shared reference scanner for efficient validation
    scanner: &'a ReferenceScanner,
    /// Validation configuration
    config: &'a ValidationConfig,
}

impl<'a> OwnedValidationContext<'a> {
    /// Creates a new owned validation context.
    ///
    /// # Arguments
    ///
    /// * `object` - The CilObject containing both raw and resolved metadata
    /// * `scanner` - Shared reference scanner
    /// * `config` - Validation configuration
    pub fn new(
        object: &'a CilObject,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> Self {
        Self {
            object,
            scanner,
            config,
        }
    }

    /// Returns a reference to the CilObject.
    ///
    /// This provides access to both raw and fully resolved metadata including type registries,
    /// method maps, and other resolved structures through CilObject's public API.
    #[must_use]
    pub fn object(&self) -> &CilObject {
        self.object
    }
}

impl ValidationContext for OwnedValidationContext<'_> {
    fn validation_stage(&self) -> ValidationStage {
        ValidationStage::Owned
    }

    fn reference_scanner(&self) -> &ReferenceScanner {
        self.scanner
    }

    fn config(&self) -> &ValidationConfig {
        self.config
    }
}

/// Factory functions for creating validation contexts.
pub mod factory {
    use super::{
        AssemblyChanges, CilAssemblyView, CilObject, OwnedValidationContext, RawValidationContext,
        ReferenceScanner, ValidationConfig,
    };

    /// Creates a raw validation context for loading validation.
    pub fn raw_loading_context<'a>(
        view: &'a CilAssemblyView,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> RawValidationContext<'a> {
        RawValidationContext::new_for_loading(view, scanner, config)
    }

    /// Creates a raw validation context for modification validation.
    pub fn raw_modification_context<'a>(
        view: &'a CilAssemblyView,
        changes: &'a AssemblyChanges,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> RawValidationContext<'a> {
        RawValidationContext::new_for_modification(view, changes, scanner, config)
    }

    /// Creates an owned validation context.
    pub fn owned_context<'a>(
        object: &'a CilObject,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> OwnedValidationContext<'a> {
        OwnedValidationContext::new(object, scanner, config)
    }
}

#[cfg(test)]
mod tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use crate::metadata::validation::config::ValidationConfig;
    use std::path::PathBuf;

    #[test]
    fn test_raw_loading_context() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::from_view(&view).unwrap();
            let config = ValidationConfig::minimal();

            let context = RawValidationContext::new_for_loading(&view, &scanner, &config);

            assert_eq!(context.validation_stage(), ValidationStage::Raw);
            assert!(context.is_loading_validation());
            assert!(!context.is_modification_validation());
            assert!(context.changes().is_none());
        }
    }

    #[test]
    fn test_raw_modification_context() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::from_view(&view).unwrap();
            let config = ValidationConfig::minimal();
            let changes = AssemblyChanges::new(&view);

            let context =
                RawValidationContext::new_for_modification(&view, &changes, &scanner, &config);

            assert_eq!(context.validation_stage(), ValidationStage::Raw);
            assert!(!context.is_loading_validation());
            assert!(context.is_modification_validation());
            assert!(context.changes().is_some());
        }
    }

    #[test]
    fn test_factory_functions() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::from_view(&view).unwrap();
            let config = ValidationConfig::minimal();
            let changes = AssemblyChanges::new(&view);

            let loading_context = factory::raw_loading_context(&view, &scanner, &config);
            assert_eq!(loading_context.validation_stage(), ValidationStage::Raw);

            let modification_context =
                factory::raw_modification_context(&view, &changes, &scanner, &config);
            assert_eq!(
                modification_context.validation_stage(),
                ValidationStage::Raw
            );
        }
    }
}
