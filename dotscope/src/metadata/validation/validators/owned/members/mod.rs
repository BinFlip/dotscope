//! Owned member validators for Stage 2 validation.
//!
//! This module contains specialized validators that ensure type member integrity and ECMA-335
//! compliance for resolved method and field definitions. These validators operate on [`crate::metadata::cilobject::CilObject`]
//! structures and perform comprehensive semantic analysis of method signatures, field layouts,
//! accessibility rules, and member relationships within type hierarchies.
//!
//! # Architecture
//!
//! The member validation system provides three key areas of member validation:
//! 1. **Method Validation** ([`crate::metadata::validation::validators::owned::members::method`]) - Method signature, override, and constraint validation
//! 2. **Field Validation** ([`crate::metadata::validation::validators::owned::members::field`]) - Field layout, type, and constraint validation
//! 3. **Accessibility Validation** ([`crate::metadata::validation::validators::owned::members::accessibility`]) - Member accessibility and visibility rule enforcement
//!
//! These validators ensure that type members conform to .NET runtime requirements and maintain
//! consistency across inheritance hierarchies and interface implementations.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::members::OwnedMethodValidator`] - Validates method definitions, signatures, overriding rules, and parameter constraints
//! - [`crate::metadata::validation::validators::owned::members::OwnedFieldValidator`] - Validates field definitions, layouts, types, and memory constraints
//! - [`crate::metadata::validation::validators::owned::members::OwnedAccessibilityValidator`] - Validates member accessibility rules and visibility constraints
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     OwnedMethodValidator, OwnedFieldValidator, OwnedValidationContext, OwnedValidator
//! };
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate method definitions
//! let method_validator = OwnedMethodValidator::new();
//! method_validator.validate_owned(&context)?;
//!
//! // Validate field definitions
//! let field_validator = OwnedFieldValidator::new();
//! field_validator.validate_owned(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All member validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Member validation can be performed concurrently across different types.
//!
//! # Integration
//!
//! This module integrates with:
//! - Owned validation stage - Part of the owned validation stage
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::OwnedValidator`] trait
//! - [`crate::metadata::cilobject`] - Validates resolved member structures

mod accessibility;
mod field;
mod method;

pub use accessibility::OwnedAccessibilityValidator;
pub use field::OwnedFieldValidator;
pub use method::OwnedMethodValidator;
