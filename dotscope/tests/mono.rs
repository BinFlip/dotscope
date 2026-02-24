//! Integration tests for Mono .NET Framework assembly compatibility.
//!
//! This test suite loads all available Mono assemblies from the test samples
//! directory and compares the loading success rates between ProjectLoader (with
//! dependency resolution) and CilAssemblyView. This helps identify compatibility
//! issues and the benefits of loading assemblies with their dependencies.

mod common;

use std::path::Path;

#[test]
#[ignore] // Large-scale compatibility test - run manually with: cargo test -- --ignored
fn test_mono_assembly_compatibility() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mono_path = Path::new(&manifest_dir).join("tests/samples/mono_4.8");

    common::compatibility::run_assembly_compatibility_test(&mono_path, "MONO");
}
