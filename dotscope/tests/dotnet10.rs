#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

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

/// The core library's structs are value types on every load.
///
/// A type defined in the image gets its base linked by the inheritance pass,
/// which runs beside loaders that may already ask for the type's flavor; a
/// flavor computed before the link was a class for good, so `System.DateTime`
/// read as a reference type on some loads and a struct on others.
#[test]
fn core_library_structs_are_value_types_on_every_load() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let corelib =
        Path::new(&manifest_dir).join("tests/samples/dotnet_10.0/System.Private.CoreLib.dll");
    let data = std::fs::read(corelib).expect("System.Private.CoreLib.dll");
    for _ in 0..3 {
        let assembly = dotscope::CilObject::from_mem_with_validation(
            data.clone(),
            dotscope::metadata::validation::ValidationConfig::analysis(),
        )
        .expect("loads");
        for name in ["DateTime", "TimeSpan", "Guid", "Decimal", "DayOfWeek"] {
            let flavors: Vec<bool> = assembly
                .types()
                .iter()
                .filter(|entry| {
                    let ty = entry.value();
                    ty.namespace == "System" && ty.name == name && ty.token.table() == 0x02
                })
                .map(|entry| entry.value().flavor().is_value_type())
                .collect();
            assert_eq!(flavors, [true], "System.{name}");
        }
    }
}
