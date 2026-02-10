//! Raw constraint validators for Stage 1 validation.
//!
//! This module contains specialized validators that ensure constraint compliance and ECMA-335
//! conformance for raw metadata structures. These validators operate on [`crate::metadata::cilassemblyview::CilAssemblyView`]
//! and validate constraint satisfaction in layout specifications, generic parameter bounds,
//! and other structural constraints that must be verified before semantic analysis.
//!
//! # Architecture
//!
//! The constraint validation system provides two key areas of constraint validation:
//! 1. **Generic Constraint Validation** ([`generic`]) - Generic parameter constraints, bounds, and variance rules
//! 2. **Layout Constraint Validation** ([`layout`]) - Field layout, class layout, and memory alignment constraints
//!
//! These validators ensure that constraint specifications in raw metadata conform to ECMA-335
//! requirements and can be safely processed by the .NET runtime without violating type system
//! or memory layout rules.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::RawGenericConstraintValidator`] - Validates generic parameter constraints, type bounds, variance specifications, and constraint compatibility
//! - [`crate::metadata::validation::validators::RawLayoutConstraintValidator`] - Validates field layout constraints, class layout specifications, packing alignment, and memory layout rules
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     RawGenericConstraintValidator, RawLayoutConstraintValidator, RawValidationContext, RawValidator
//! };
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate generic constraints
//! let generic_validator = RawGenericConstraintValidator::new();
//! generic_validator.validate_raw(&context)?;
//!
//! // Validate layout constraints
//! let layout_validator = RawLayoutConstraintValidator::new();
//! layout_validator.validate_raw(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All constraint validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Constraint validation can be performed concurrently across different assemblies.
//!
//! # Integration
//!
//! This module integrates with:
//! - Raw validation stage - Part of the raw validation stage after structure validation
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine with fail-fast behavior
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::RawValidator`] trait
//! - shared schema validation utilities - Uses shared schema validation utilities
mod generic;
mod layout;

pub use generic::RawGenericConstraintValidator;
pub use layout::RawLayoutConstraintValidator;
