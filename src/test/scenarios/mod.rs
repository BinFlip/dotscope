//! Pre-built complex scenarios and test data combinations
//!
//! This module provides functions for creating complex, realistic test scenarios
//! that combine multiple metadata objects in meaningful ways. These scenarios
//! help test complex interactions and edge cases.

use crate::metadata::{
    method::MethodRc,
    tables::{AssemblyRefRc, ModuleRefRc},
    typesystem::CilTypeRc,
};

use super::builders::{AssemblyRefBuilder, CilTypeBuilder, MethodBuilder, ModuleRefBuilder};

/// Create a basic class hierarchy: BaseClass -> DerivedClass
pub fn create_inheritance_scenario() -> (CilTypeRc, CilTypeRc) {
    let base_class = CilTypeBuilder::simple_class("Test", "BaseClass").build();
    let derived_class = CilTypeBuilder::simple_class("Test", "DerivedClass").build();
    (base_class, derived_class)
}

/// Create a class with common methods (constructor, property, method)
pub fn create_class_with_members(class_name: &str) -> (CilTypeRc, Vec<MethodRc>) {
    let class_type = CilTypeBuilder::simple_class("Test", class_name).build();
    let methods = vec![
        MethodBuilder::constructor().build(),
        MethodBuilder::property_getter("Name").build(),
        MethodBuilder::property_setter("Name").build(),
        MethodBuilder::simple_void_method("DoSomething").build(),
    ];
    (class_type, methods)
}

/// Create assembly references for common .NET libraries
pub fn create_standard_assembly_refs() -> Vec<AssemblyRefRc> {
    vec![
        AssemblyRefBuilder::dotnet_framework("mscorlib").build(),
        AssemblyRefBuilder::dotnet_framework("System").build(),
        AssemblyRefBuilder::dotnet_framework("System.Core").build(),
        AssemblyRefBuilder::dotnet_core("System.Runtime").build(),
        AssemblyRefBuilder::dotnet_core("System.Collections").build(),
    ]
}

/// Create module references for common native libraries
pub fn create_standard_module_refs() -> Vec<ModuleRefRc> {
    vec![
        ModuleRefBuilder::new().with_name("kernel32.dll").build(),
        ModuleRefBuilder::new().with_name("user32.dll").build(),
        ModuleRefBuilder::new().with_name("advapi32.dll").build(),
    ]
}
