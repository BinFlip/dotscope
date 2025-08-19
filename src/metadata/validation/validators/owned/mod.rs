//! Owned validation stage (Stage 2) validators for the fine-grained validation framework.
//!
//! This module contains fine-grained validators that operate on owned metadata through [`crate::metadata::cilobject::CilObject`].
//! Owned validators perform specific semantic validation tasks that require resolved metadata structures,
//! ensuring ECMA-335 compliance and runtime safety for fully loaded .NET assemblies. These validators
//! operate after successful raw validation and provide comprehensive semantic analysis.
//!
//! # Architecture
//!
//! The owned validation system operates on resolved metadata structures in six functional categories:
//! 1. **Type Validators** ([`crate::metadata::validation::validators::owned::types`]) - Type system semantics and inheritance
//! 2. **Constraint Validators** ([`crate::metadata::validation::validators::owned::constraints`]) - Generic constraint satisfaction and type compatibility
//! 3. **Member Validators** ([`crate::metadata::validation::validators::owned::members`]) - Method and field validation
//! 4. **Metadata Validators** ([`crate::metadata::validation::validators::owned::metadata`]) - Attribute and signature validation
//! 5. **Relationship Validators** ([`crate::metadata::validation::validators::owned::relationships`]) - Cross-reference validation
//! 6. **System Validators** ([`crate::metadata::validation::validators::owned::system`]) - Assembly-level validation
//!
//! Each validator implements [`crate::metadata::validation::traits::OwnedValidator`] and operates through
//! [`crate::metadata::validation::context::OwnedValidationContext`] for coordinated validation.
//!
//! # Key Components
//!
//! ## Type Validators
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeDefinitionValidator`] - Type definition validation and consistency
//! - [`crate::metadata::validation::validators::owned::types::OwnedInheritanceValidator`] - Inheritance chain validation and rules
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeCircularityValidator`] - Circular type dependency detection
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeDependencyValidator`] - Type dependency chain validation
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeOwnershipValidator`] - Type ownership validation
//!
//! ## Constraint Validators
//! - [`crate::metadata::validation::validators::owned::constraints::OwnedTypeConstraintValidator`] - Generic constraint satisfaction and type compatibility
//!
//! ## Member Validators
//! - [`crate::metadata::validation::validators::owned::members::OwnedMethodValidator`] - Method validation, overriding, and signatures
//! - [`crate::metadata::validation::validators::owned::members::OwnedFieldValidator`] - Field validation, layout, and accessibility
//! - [`crate::metadata::validation::validators::owned::members::OwnedAccessibilityValidator`] - Accessibility and visibility rule enforcement
//!
//! ## Metadata Validators
//! - [`crate::metadata::validation::validators::owned::metadata::OwnedAttributeValidator`] - Custom attribute usage and validation
//! - [`crate::metadata::validation::validators::owned::metadata::OwnedSignatureValidator`] - Method signature validation and compatibility
//!
//! ## Relationship Validators
//! - [`crate::metadata::validation::validators::owned::relationships::OwnedCircularityValidator`] - Circular reference detection in type hierarchies
//! - [`crate::metadata::validation::validators::owned::relationships::OwnedDependencyValidator`] - Dependency chain validation across resolved assemblies
//! - [`crate::metadata::validation::validators::owned::relationships::OwnedOwnershipValidator`] - Parent-child ownership validation in resolved structures
//!
//! ## System Validators
//! - [`crate::metadata::validation::validators::owned::system::OwnedSecurityValidator`] - Security attributes and permissions
//! - [`crate::metadata::validation::validators::owned::system::OwnedAssemblyValidator`] - Cross-assembly references and dependencies
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     OwnedTypeDefinitionValidator, OwnedMethodValidator, OwnedValidationContext, OwnedValidator
//! };
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate type definitions
//! let type_validator = OwnedTypeDefinitionValidator::new();
//! type_validator.validate_owned(&context)?;
//!
//! // Validate methods
//! let method_validator = OwnedMethodValidator::new();
//! method_validator.validate_owned(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All owned validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. The validation context provides thread-safe access to metadata.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Coordinates owned validator execution
//! - [`crate::metadata::validation::context`] - Provides owned validation contexts
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::OwnedValidator`] trait
//! - [`crate::metadata::cilobject`] - Validates resolved metadata structures

mod constraints;
mod members;
mod metadata;
mod relationships;
mod system;
mod types;

// Re-export all validators for direct access by ValidationEngine
pub use constraints::OwnedTypeConstraintValidator;
pub use members::{OwnedAccessibilityValidator, OwnedFieldValidator, OwnedMethodValidator};
pub use metadata::{OwnedAttributeValidator, OwnedSignatureValidator};
pub use relationships::{
    OwnedCircularityValidator, OwnedDependencyValidator, OwnedOwnershipValidator,
};
pub use system::{OwnedAssemblyValidator, OwnedSecurityValidator};
pub use types::{
    OwnedInheritanceValidator, OwnedTypeCircularityValidator, OwnedTypeDefinitionValidator,
    OwnedTypeDependencyValidator, OwnedTypeOwnershipValidator,
};
