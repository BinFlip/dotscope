//! Owned system validators for Stage 2 validation.
//!
//! This module contains specialized validators that ensure system-level integrity and ECMA-335
//! compliance for resolved assembly structures. These validators operate on [`crate::metadata::cilobject::CilObject`]
//! and perform comprehensive semantic analysis of assembly-level constraints, security attributes,
//! cross-assembly dependencies, and system-wide validation requirements.
//!
//! # Architecture
//!
//! The system validation system provides two key areas of system-level validation:
//! 1. **Assembly Validation** ([`crate::metadata::validation::validators::owned::system::assembly`]) - Cross-assembly references, dependencies, and assembly-level constraint validation
//! 2. **Security Validation** ([`crate::metadata::validation::validators::owned::system::security`]) - Security attributes, permissions, and access control validation
//!
//! These validators ensure that system-level constraints conform to .NET runtime requirements and
//! maintain consistency across resolved assemblies, security boundaries, and runtime environments.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::system::OwnedAssemblyValidator`] - Validates cross-assembly references, dependency resolution, and assembly-level metadata constraints
//! - [`crate::metadata::validation::validators::owned::system::OwnedSecurityValidator`] - Validates security attributes, permission sets, and access control constraints
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     OwnedAssemblyValidator, OwnedSecurityValidator, OwnedValidationContext, OwnedValidator
//! };
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate assembly-level constraints
//! let assembly_validator = OwnedAssemblyValidator::new();
//! assembly_validator.validate_owned(&context)?;
//!
//! // Validate security constraints
//! let security_validator = OwnedSecurityValidator::new();
//! security_validator.validate_owned(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All system validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. System validation can be performed concurrently across different assemblies.
//!
//! # Integration
//!
//! This module integrates with:
//! - Owned validation stage - Part of the owned validation stage
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::OwnedValidator`] trait
//! - [`crate::metadata::cilobject`] - Validates resolved assembly structures

mod assembly;
mod security;

pub use assembly::OwnedAssemblyValidator;
pub use security::OwnedSecurityValidator;
