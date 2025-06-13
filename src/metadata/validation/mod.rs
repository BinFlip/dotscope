//! Validation utilities for metadata tables
//!
//! This module provides comprehensive validation logic for ensuring
//! metadata integrity and type safety across the .NET type system.
//!
//! ## Completed Validation Features
//!
//! - ✅ **Cross-table validation**: Token consistency, semantic validation, method validation
//! - ✅ **Field layout validation**: Overlap detection, boundary checking for explicit layouts
//! - ✅ **Type system validation**: Inheritance rules, sealed/abstract constraints
//! - ✅ **Semantic validation**: Interface rules, inheritance validation, type system consistency
//! - ✅ **Method validation**: Constructor rules, abstract method validation, parameter validation
//! - ✅ **Nested class validation**: Circular reference detection and depth limits
//!
//! ## TODO: Remaining Validation Gaps
//!
//! ### Infrastructure & Core Validation
//! - [ ] **Coded Index Runtime Validation** - Less comprehensive than .NET Runtime (in `codedindex.rs`)
//! - [ ] **Coded Index Error Recovery** - Runtime has better malformed assembly handling
//! - [ ] **UTF-8 String Validation** - Runtime has comprehensive UTF-8 validation for #Strings heap
//! - [ ] **Malformed String Handling** - Less robust than runtime for UserStrings heap
//!
//! ### PE & File Structure Validation
//! - [ ] **Comprehensive PE Header Validation** - Runtime has more thorough PE validation
//! - [ ] **Malformed PE Recovery** - Runtime handles corrupted PE files better
//! - [ ] **PE Security Checks** - Runtime has additional security validation
//!
//! ### IL & Method Validation
//! - [ ] **IL Instruction Sequence Validation** - Runtime validates IL instruction sequences
//! - [ ] **Stack Depth Validation** - Runtime tracks and validates stack depth
//! - [ ] **CIL Verification Rules** - Runtime applies comprehensive CIL verification
//!
//! ### Table-Specific Validation
//! - [ ] **Parameter Type Compatibility Validation** (Param table) - No type compatibility checking when parameters are shared between methods
//! - [ ] **Signature Type Validation** (MemberRef table) - No validation that signature type is compatible with parent type
//! - [ ] **Parameter Validation Against Signature** (MethodDef table) - Method signature parameter validation
//! - [ ] **Event Range Validation** (EventMap table) - No validation that computed event range is within bounds
//! - [ ] **Property Range Validation** (PropertyMap table) - No validation that computed property range is within bounds
//! - [ ] **Semantic Attribute Validation** (MethodSemantics table) - No validation that method signatures are compatible with semantic roles
//!
//! ### Assembly-Level Validation
//! - [ ] **Enhanced GUID Validation** (Module table) - Minor validation improvement needed
//! - [ ] **Cross-Assembly Resolution Validation** (TypeRef table) - Validation for cross-assembly type references
//!
//! **Total: ~18 remaining validation gaps** across different categories, ranging from critical
//! infrastructure validation to table-specific edge case validation.

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
