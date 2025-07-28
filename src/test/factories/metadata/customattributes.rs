//! Factory methods for custom attributes test data.
//!
//! Contains helper methods migrated from custom attributes source files
//! for creating test data related to custom attribute parsing and encoding.

use crate::{
    metadata::{
        method::{Method, MethodRc},
        typesystem::CilFlavor,
    },
    test::MethodBuilder,
};
use std::sync::Arc;

/// Helper to create a method with empty parameters for parsing tests
///
/// Originally from: `src/metadata/customattributes/mod.rs`
pub fn create_empty_method() -> Arc<Method> {
    MethodBuilder::new().with_name("TestConstructor").build()
}

/// Helper to create a method with specific parameter types
///
/// Originally from: `src/metadata/customattributes/mod.rs`
pub fn create_method_with_params(param_types: Vec<CilFlavor>) -> Arc<Method> {
    MethodBuilder::with_param_types("TestConstructor", param_types).build()
}

/// Helper function to create a simple method for basic parsing tests
///
/// Originally from: `src/metadata/customattributes/parser.rs`
pub fn create_empty_constructor() -> MethodRc {
    MethodBuilder::new().with_name("EmptyConstructor").build()
}

/// Helper function to create a method with specific parameter types using builders
///
/// Originally from: `src/metadata/customattributes/parser.rs`
pub fn create_constructor_with_params(param_types: Vec<CilFlavor>) -> MethodRc {
    MethodBuilder::with_param_types("AttributeConstructor", param_types).build()
}
