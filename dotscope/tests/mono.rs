//! Integration tests for Mono .NET Framework assembly compatibility.
//!
//! This test suite loads all available Mono assemblies from the test samples
//! directory and compares the loading success rates between ProjectLoader (with
//! dependency resolution) and CilAssemblyView. This helps identify compatibility
//! issues and the benefits of loading assemblies with their dependencies.

use dotscope::testkit::fixture;

#[test]
#[ignore] // Large-scale compatibility test - run manually with: cargo test -- --ignored
fn test_mono_assembly_compatibility() {
    let mono_path = fixture("mono_4.8");

    dotscope::testkit::compatibility::run_assembly_compatibility_test(&mono_path, "MONO");
}
