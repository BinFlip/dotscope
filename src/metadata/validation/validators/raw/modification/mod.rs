//! Raw modification validators for Stage 1 validation.
//!
//! This module contains specialized validators that ensure modification integrity and ECMA-335
//! compliance for assembly change operations. These validators operate on [`crate::metadata::cilassemblyview::CilAssemblyView`]
//! with [`crate::cilassembly::AssemblyChanges`] and validate that proposed modifications to assembly metadata
//! are structurally sound, maintain referential integrity, and preserve ECMA-335 constraints.
//!
//! # Architecture
//!
//! The modification validation system provides two key areas of modification validation:
//! 1. **Operation Validation** ([`operation`]) - Individual change operation validation (insert, update, delete)
//! 2. **Integrity Validation** ([`integrity`]) - Post-change integrity and consistency validation
//!
//! These validators ensure that assembly modifications preserve structural integrity and
//! ECMA-335 compliance while allowing safe runtime updates and transformations.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::RawOperationValidator`] - Validates individual change operations for structural correctness, constraint preservation, and operation safety
//! - [`crate::metadata::validation::validators::RawChangeIntegrityValidator`] - Validates post-change integrity, cross-table consistency, and overall metadata coherence
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     RawOperationValidator, RawChangeIntegrityValidator, RawValidationContext, RawValidator
//! };
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate individual operations
//! let operation_validator = RawOperationValidator::new();
//! operation_validator.validate_raw(&context)?;
//!
//! // Validate post-change integrity
//! let integrity_validator = RawChangeIntegrityValidator::new();
//! integrity_validator.validate_raw(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All modification validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Modification validation can be performed concurrently for independent changes.
//!
//! # Integration
//!
//! This module integrates with:
//! - Raw validation stage - Part of the raw validation stage for modification scenarios
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine with fail-fast behavior
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::RawValidator`] trait
//! - [`crate::cilassembly`] - Validates [`crate::cilassembly::AssemblyChanges`] structures

mod integrity;
mod operation;

pub use integrity::RawChangeIntegrityValidator;
pub use operation::RawOperationValidator;
