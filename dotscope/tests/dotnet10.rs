//! Integration tests for .NET 10 runtime assembly compatibility.
//!
//! This test suite loads all available .NET 10 runtime assemblies from the test
//! samples directory and compares the loading success rates between ProjectLoader
//! (with dependency resolution) and CilAssemblyView. This exercises modern .NET
//! metadata features such as nullable reference types, default interface methods,
//! and InterfaceImpl custom attributes.

mod common;

use std::path::Path;

#[test]
#[ignore] // Large-scale compatibility test - run manually with: cargo test -- --ignored
fn test_dotnet10_assembly_compatibility() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let dotnet10_path = Path::new(&manifest_dir).join("tests/samples/dotnet_10.0");

    common::compatibility::run_assembly_compatibility_test(&dotnet10_path, ".NET 10");
}
