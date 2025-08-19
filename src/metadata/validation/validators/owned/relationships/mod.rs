//! Owned relationship validators for Stage 2 validation.
//!
//! This module contains specialized validators that ensure relationship integrity and ECMA-335
//! compliance for resolved metadata relationships. These validators operate on [`crate::metadata::cilobject::CilObject`]
//! structures and perform comprehensive semantic analysis of cross-reference relationships,
//! circular dependencies, and ownership hierarchies within resolved type systems.
//!
//! # Architecture
//!
//! The relationship validation system provides three key areas of relationship validation:
//! 1. **Circularity Detection** ([`crate::metadata::validation::validators::owned::relationships::circularity`]) - Circular reference detection in type hierarchies and dependencies
//! 2. **Dependency Validation** ([`crate::metadata::validation::validators::owned::relationships::dependency`]) - Cross-assembly and cross-type dependency chain validation
//! 3. **Ownership Validation** ([`crate::metadata::validation::validators::owned::relationships::ownership`]) - Parent-child ownership relationships and containment rules
//!
//! These validators ensure that metadata relationships conform to .NET runtime requirements and
//! maintain consistency across resolved assemblies and type hierarchies without creating
//! impossible or circular dependencies.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::relationships::OwnedCircularityValidator`] - Detects circular references in type hierarchies, inheritance chains, and dependency graphs
//! - [`crate::metadata::validation::validators::owned::relationships::OwnedDependencyValidator`] - Validates dependency chains across assemblies and validates resolution order constraints
//! - [`crate::metadata::validation::validators::owned::relationships::OwnedOwnershipValidator`] - Validates parent-child ownership relationships and nested type containment rules
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     OwnedCircularityValidator, OwnedDependencyValidator, OwnedValidationContext, OwnedValidator
//! };
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Detect circular references
//! let circularity_validator = OwnedCircularityValidator::new();
//! circularity_validator.validate_owned(&context)?;
//!
//! // Validate dependency chains
//! let dependency_validator = OwnedDependencyValidator::new();
//! dependency_validator.validate_owned(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All relationship validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Relationship validation can be performed concurrently across different assemblies.
//!
//! # Integration
//!
//! This module integrates with:
//! - Owned validation stage - Part of the owned validation stage
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::OwnedValidator`] trait
//! - shared reference validation utilities - Uses shared reference validation utilities

mod circularity;
mod dependency;
mod ownership;

pub use circularity::OwnedCircularityValidator;
pub use dependency::OwnedDependencyValidator;
pub use ownership::OwnedOwnershipValidator;
