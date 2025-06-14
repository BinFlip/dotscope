//! Legacy helper functions and utilities
//!
//! This module contains the original helper functions preserved for backward
//! compatibility. These functions are thin wrappers around the new builder
//! pattern APIs.

use crate::metadata::{
    method::MethodRc,
    tables::{AssemblyRefRc, FileRc, ModuleRefRc},
    token::Token,
    typesystem::{CilTypeRc, CilTypeReference},
};

use super::builders::{
    AssemblyRefBuilder, CilTypeBuilder, FileBuilder, MethodBuilder, ModuleRefBuilder,
};
// pub use super::builders::types::create_exportedtype; // TODO: Integrate when used

// Helper function to create a ModuleRef
pub fn create_module_ref(rid: u32, name: &str) -> ModuleRefRc {
    ModuleRefBuilder::new()
        .with_rid(rid)
        .with_name(name)
        .build()
}

// Helper function to create an AssemblyRef
pub fn create_assembly_ref(rid: u32, name: &str) -> AssemblyRefRc {
    AssemblyRefBuilder::new()
        .with_rid(rid)
        .with_name(name)
        .build()
}

// Helper function to create a File
pub fn create_file(rid: u32, name: &str) -> FileRc {
    FileBuilder::new().with_rid(rid).with_name(name).build()
}

// Helper function to create a Method
pub fn create_method(name: &str) -> MethodRc {
    MethodBuilder::simple_void_method(name).build()
}

// Helper function to create a CilType
pub fn create_cil_type(
    token: Token,
    namespace: &str,
    name: &str,
    external: Option<CilTypeReference>,
) -> CilTypeRc {
    CilTypeBuilder::new()
        .with_token(token)
        .with_namespace(namespace)
        .with_name(name)
        .with_external(external.unwrap_or_else(|| CilTypeReference::File(create_file(1, "test"))))
        .build()
}
