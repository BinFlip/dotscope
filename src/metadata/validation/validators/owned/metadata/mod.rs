//! Owned metadata validators for Stage 2 validation.
//!
//! This module contains specialized validators that ensure metadata integrity and ECMA-335
//! compliance for resolved metadata structures. These validators operate on [`crate::metadata::cilobject::CilObject`]
//! and perform comprehensive semantic analysis of custom attributes, method signatures,
//! and other metadata constructs that require resolved type information.
//!
//! # Architecture
//!
//! The metadata validation system provides two key areas of metadata validation:
//! 1. **Attribute Validation** ([`crate::metadata::validation::validators::owned::metadata::attribute`]) - Custom attribute usage, targets, and constraint validation
//! 2. **Signature Validation** ([`crate::metadata::validation::validators::owned::metadata::signature`]) - Method signature compatibility and constraint validation
//!
//! These validators ensure that metadata constructs conform to .NET runtime requirements and
//! maintain consistency across resolved type hierarchies and assemblies.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::metadata::OwnedAttributeValidator`] - Validates custom attribute definitions, usage, and target constraints
//! - [`crate::metadata::validation::validators::owned::metadata::OwnedSignatureValidator`] - Validates method signature compatibility and type constraints
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     OwnedAttributeValidator, OwnedSignatureValidator, OwnedValidationContext, OwnedValidator
//! };
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate custom attributes
//! let attribute_validator = OwnedAttributeValidator::new();
//! attribute_validator.validate_owned(&context)?;
//!
//! // Validate method signatures
//! let signature_validator = OwnedSignatureValidator::new();
//! signature_validator.validate_owned(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All metadata validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Metadata validation can be performed concurrently across different assemblies.
//!
//! # Integration
//!
//! This module integrates with:
//! - Owned validation stage - Part of the owned validation stage
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::OwnedValidator`] trait
//! - [`crate::metadata::cilobject`] - Validates resolved metadata structures

mod attribute;
mod signature;

pub use attribute::OwnedAttributeValidator;
pub use signature::OwnedSignatureValidator;
