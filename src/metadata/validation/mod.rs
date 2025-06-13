//! Validation utilities for metadata tables
//!
//! This module provides comprehensive validation logic for ensuring
//! metadata integrity and type safety across the .NET type system.

mod config;
mod constraint;
mod field;
mod layout;
mod method;
mod nested;
mod orchestrator;
mod semantic;
mod token;

pub use config::ValidationConfig;
pub(crate) use constraint::ConstraintValidator;
pub(crate) use field::FieldValidator;
pub(crate) use layout::LayoutValidator;
pub(crate) use method::MethodValidator;
pub(crate) use nested::NestedClassValidator;
pub(crate) use orchestrator::Orchestrator;
pub(crate) use semantic::SemanticValidator;
pub(crate) use token::TokenValidator;
