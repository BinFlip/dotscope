//! Owned type validators for Stage 2 validation.
//!
//! This module contains specialized validators that ensure type system integrity and ECMA-335
//! compliance for resolved type definitions. These validators operate on [`crate::metadata::cilobject::CilObject`]
//! structures and perform comprehensive semantic analysis of type hierarchies, inheritance chains,
//! circular dependencies, and ownership relationships.
//!
//! # Architecture
//!
//! The type validation system provides five key areas of type system validation:
//! 1. **Definition Validation** ([`crate::metadata::validation::validators::owned::types::definition`]) - Type definition structure and consistency
//! 2. **Inheritance Validation** ([`crate::metadata::validation::validators::owned::types::inheritance`]) - Inheritance chain rules and constraints
//! 3. **Circularity Detection** ([`crate::metadata::validation::validators::owned::types::circularity`]) - Circular type dependency detection
//! 4. **Dependency Validation** ([`crate::metadata::validation::validators::owned::types::dependency`]) - Type dependency chain analysis
//! 5. **Ownership Validation** ([`crate::metadata::validation::validators::owned::types::ownership`]) - Type ownership and containment rules
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeDefinitionValidator`] - Validates type definition structure and ECMA-335 compliance
//! - [`crate::metadata::validation::validators::owned::types::OwnedInheritanceValidator`] - Validates inheritance chains and interface implementation rules
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeCircularityValidator`] - Detects circular dependencies in type hierarchies
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeDependencyValidator`] - Validates type dependency relationships and constraints
//! - [`crate::metadata::validation::validators::owned::types::OwnedTypeOwnershipValidator`] - Validates nested type ownership and containment rules
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     OwnedTypeDefinitionValidator, OwnedInheritanceValidator, OwnedValidationContext, OwnedValidator
//! };
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate type definitions
//! let type_validator = OwnedTypeDefinitionValidator::new();
//! type_validator.validate_owned(&context)?;
//!
//! // Validate inheritance chains
//! let inheritance_validator = OwnedInheritanceValidator::new();
//! inheritance_validator.validate_owned(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All type validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Type validation can be performed concurrently across different types.
//!
//! # Integration
//!
//! This module integrates with:
//! - Owned validation stage - Part of the owned validation stage
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::OwnedValidator`] trait
//! - [`crate::metadata::cilobject`] - Validates resolved type structures

mod circularity;
mod definition;
mod dependency;
mod inheritance;
mod ownership;

pub use circularity::OwnedTypeCircularityValidator;
pub use definition::OwnedTypeDefinitionValidator;
pub use dependency::OwnedTypeDependencyValidator;
pub use inheritance::OwnedInheritanceValidator;
pub use ownership::OwnedTypeOwnershipValidator;
