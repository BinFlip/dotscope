//! Project Loader Example
//!
//! This example demonstrates how to use the `ProjectLoader` API to load and analyze
//! .NET assemblies with automatic dependency resolution.
//!
//! The `ProjectLoader` provides a builder-style API for:
//! - Loading a primary assembly with its dependencies
//! - Automatic dependency discovery from search paths
//! - Graceful handling of missing dependencies
//! - Cross-assembly type resolution
//!
//! # Usage
//!
//! ```bash
//! cargo run --example project_loader -- <path-to-assembly>
//! ```
//!
//! With a custom search path for dependencies:
//! ```bash
//! cargo run --example project_loader -- <path-to-assembly> --search-path /path/to/dependencies
//! ```
//!
//! Example with Mono framework assemblies:
//! ```bash
//! cargo run --example project_loader -- tests/samples/crafted_2.exe --search-path tests/samples/mono_4.5
//! ```

use dotscope::project::ProjectLoader;
use std::env;

fn main() -> dotscope::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "Usage: {} <assembly-path> [--search-path <path>] [--search-path <path2>] ...",
            args[0]
        );
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --search-path <path>  Add a directory to search for dependencies");
        eprintln!("                        (can be specified multiple times)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} MyApp.exe", args[0]);
        eprintln!("  {} MyApp.exe --search-path /usr/lib/mono/4.5", args[0]);
        eprintln!(
            "  {} tests/samples/crafted_2.exe --search-path tests/samples/mono_4.5",
            args[0]
        );
        std::process::exit(1);
    }

    let assembly_path = &args[1];

    // Parse --search-path arguments
    let mut search_paths: Vec<String> = Vec::new();
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--search-path" && i + 1 < args.len() {
            search_paths.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    println!("=== dotscope Project Loader Example ===\n");
    println!("Loading assembly: {}", assembly_path);

    // Build the project loader with configuration
    let mut loader = ProjectLoader::new().primary_file(assembly_path)?;

    // Add search paths and enable auto-discovery if any were specified
    if !search_paths.is_empty() {
        println!("Search paths:");
        for path in &search_paths {
            println!("  - {}", path);
            loader = loader.with_search_path(path)?;
        }
        loader = loader.auto_discover(true);
    } else {
        // Also search in the same directory as the primary assembly
        if let Some(parent) = std::path::Path::new(assembly_path).parent() {
            if parent.exists() && parent.is_dir() {
                loader = loader.with_search_path(parent)?.auto_discover(true);
                println!("Search path: {} (auto)", parent.display());
            }
        }
    }

    println!();

    // Build and load the project
    let result = loader.build()?;

    // Display loading statistics
    println!("=== Loading Results ===\n");
    println!(
        "Assemblies loaded: {} successful, {} failed",
        result.success_count(),
        result.failure_count()
    );

    // Show loaded assemblies
    if !result.loaded_assemblies.is_empty() {
        println!("\nLoaded assemblies:");
        for identity in &result.loaded_assemblies {
            println!("  - {} v{}", identity.name, identity.version);
        }
    }

    // Show missing dependencies
    if !result.missing_dependencies.is_empty() {
        println!("\nMissing dependencies:");
        for dep in &result.missing_dependencies {
            println!("  - {}", dep);
        }
    }

    // Show version mismatches
    if !result.version_mismatches.is_empty() {
        println!("\nVersion mismatches:");
        for mismatch in &result.version_mismatches {
            println!(
                "  - {} (required: {}, found: {})",
                mismatch.required.name, mismatch.required.version, mismatch.actual.version
            );
        }
    }

    // Show failed loads
    if !result.failed_loads.is_empty() {
        println!("\nFailed loads:");
        for (name, error) in &result.failed_loads {
            println!("  - {}: {}", name, error);
        }
    }

    // Access the loaded project
    let project = &result.project;

    println!("\n=== Project Analysis ===\n");
    println!("Total assemblies in project: {}", project.assembly_count());

    // Get the primary assembly
    if let Some(primary) = project.get_primary() {
        println!("\nPrimary Assembly Details:");

        // Get the assembly name from the Assembly table
        if let Some(assembly_info) = primary.assembly() {
            println!("  Name: {}", assembly_info.name);
            println!(
                "  Version: {}.{}.{}.{}",
                assembly_info.major_version,
                assembly_info.minor_version,
                assembly_info.build_number,
                assembly_info.revision_number
            );
        }

        println!("  Types: {}", primary.types().len());
        println!("  Methods: {}", primary.methods().len());

        // Show some types from the primary assembly
        let types = primary.types();
        if !types.is_empty() {
            println!("\n  Sample types (up to 10):");
            for entry in types.iter().take(10) {
                let ciltype = entry.value();
                println!("    - {} ({:?})", ciltype.fullname(), ciltype.flavor());
            }
            if types.len() > 10 {
                println!("    ... and {} more", types.len() - 10);
            }
        }
    }

    // Iterate over all assemblies in the project
    println!("\n=== All Assemblies Summary ===\n");
    for (identity, assembly) in project.iter() {
        println!(
            "{}: {} types, {} methods",
            identity.name,
            assembly.types().len(),
            assembly.methods().len()
        );
    }

    // Demonstrate cross-assembly type lookup
    println!("\n=== Cross-Assembly Type Lookup ===\n");

    // Try to find some common types
    let types_to_find = ["System.Object", "System.String", "System.Int32"];

    for type_name in &types_to_find {
        match project.get_type_by_name(type_name) {
            Some(ciltype) => {
                println!("Found {}: {} methods", type_name, ciltype.methods.count());
            }
            None => {
                println!("{}: not found in loaded assemblies", type_name);
            }
        }
    }

    // Find all definitions of a type across assemblies
    println!("\n=== Type Definition Search ===\n");
    let definitions = project.find_type_definitions("Object");
    if definitions.is_empty() {
        println!("No types matching 'Object' found");
    } else {
        println!("Types matching 'Object':");
        for (identity, ciltype) in definitions.iter().take(5) {
            println!("  - {} in {}", ciltype.fullname(), identity.name);
        }
        if definitions.len() > 5 {
            println!("  ... and {} more", definitions.len() - 5);
        }
    }

    println!("\n=== Complete ===");

    Ok(())
}
