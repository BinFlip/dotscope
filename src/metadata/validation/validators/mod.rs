//! Fine-grained validators for the metadata validation framework.
//!
//! This module contains the complete fine-grained validator implementation that replaced
//! the previous monolithic validator approach. The validators provide comprehensive validation
//! coverage across both raw metadata structures and owned object data, ensuring ECMA-335
//! compliance and runtime safety through focused, single-responsibility validators.
//!
//! # Architecture
//!
//! The validator system is organized into two main validation stages:
//! 1. **Raw Validators** (raw validation stage) - Validate raw assembly data during Stage 1
//! 2. **Owned Validators** (owned validation stage) - Validate resolved object data during Stage 2
//!
//! Each validator category is further subdivided by functional area:
//! - **Structure Validators**: Token format, table integrity, heap validation
//! - **Constraint Validators**: Layout constraints, generic parameter validation
//! - **Semantic Validators**: Type system, inheritance, method validation
//! - **Relationship Validators**: Cross-table references, ownership validation
//! - **Security Validators**: Access control, permission validation
//!
//! # Key Components
//!
//! ## Raw Validators (Stage 1)
//!
//! - raw structure validators - Basic structural validation
//! - raw constraint validators - Layout and generic constraints
//! - raw modification validators - Assembly change validation
//!
//! ## Owned Validators (Stage 2)
//!
//! - owned type validators - Type system validation
//! - owned member validators - Method and field validation
//! - owned metadata validators - Signature and attribute validation
//! - owned relationship validators - Cross-reference validation
//! - owned system validators - Assembly-level validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     RawTokenValidator, OwnedTypeDefinitionValidator, RawValidationContext,
//!     OwnedValidationContext, RawValidator, OwnedValidator
//! };
//!
//! # fn setup_contexts() -> (RawValidationContext<'static>, OwnedValidationContext<'static>) {
//! #     // Mock context setup
//! #     unimplemented!()
//! # }
//! let (raw_context, owned_context) = setup_contexts();
//!
//! // Use raw validator for Stage 1 validation
//! let token_validator = RawTokenValidator::new();
//! token_validator.validate_raw(&raw_context)?;
//!
//! // Use owned validator for Stage 2 validation
//! let type_validator = OwnedTypeDefinitionValidator::new();
//! type_validator.validate_owned(&owned_context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All validators are designed for concurrent execution and implement [`Send`] + [`Sync`].
//! The validation engine uses parallel processing internally to maximize validation speed
//! across multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Coordinates validator execution
//! - [`crate::metadata::validation::traits`] - Defines validator interfaces
//! - [`crate::metadata::validation::context`] - Provides validation contexts
//! - [`crate::metadata::validation::config`] - Controls validator behavior

mod owned;
mod raw;

pub use owned::*;
pub use raw::*;
