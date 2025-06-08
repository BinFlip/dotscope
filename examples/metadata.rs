//! # Metadata Tables and Streams Exploration
//!
//! **What this example teaches:**
//! - Direct access to metadata tables and streams
//! - String, GUID, and blob heap analysis
//! - Cross-reference analysis between metadata tables
//! - Assembly dependency analysis
//! - Working with raw metadata structures
//!
//! **When to use this pattern:**
//! - Building metadata analysis tools
//! - Investigating assembly internals
//! - Dependency tracking and analysis
//! - Understanding ECMA-335 metadata structures
//!
//! **Prerequisites:**
//! - Solid understanding of .NET metadata concepts
//! - Familiarity with ECMA-335 specification
//! - Experience with basic dotscope operations

use dotscope::prelude::*;
use std::{collections::HashMap, env, path::Path};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-dotnet-assembly>", args[0]);
        eprintln!();
        eprintln!("This example explores metadata tables and streams in detail:");
        eprintln!("  • Raw metadata table access and analysis");
        eprintln!("  • Heap content examination (strings, GUIDs, blobs)");
        eprintln!("  • Cross-table relationship analysis");
        eprintln!("  • Assembly dependency tracking");
        return Ok(());
    }

    let path = Path::new(&args[1]);
    println!("🔬 Metadata exploration of: {}", path.display());

    let assembly = CilObject::from_file(path)?;

    // === Metadata Tables Analysis ===
    print_metadata_tables(&assembly);

    // === String and Blob Heap Analysis ===
    print_heap_analysis(&assembly);

    // === Type System Deep Dive ===
    print_type_system_analysis(&assembly);

    // === Assembly Dependencies ===
    print_dependency_analysis(&assembly);

    println!("\n✅ Metadata exploration completed!");

    Ok(())
}

fn print_metadata_tables(assembly: &CilObject) {
    println!("\n📊 Metadata Tables Analysis:");

    if let Some(tables) = assembly.tables() {
        println!("  Total tables present: {}", tables.table_count());

        // Show which tables are present using the new API
        println!("  Available metadata tables:");
        for table_id in tables.present_tables() {
            let row_count = tables.table_row_count(table_id);
            println!("    ✓ {:?} ({} rows)", table_id, row_count);
        }
    }

    // Method statistics
    let methods = assembly.methods();
    println!("  Methods analyzed: {}", methods.len());

    // Type statistics
    let types = assembly.types();
    println!("  Types analyzed: {}", types.len());
}

fn print_heap_analysis(assembly: &CilObject) {
    println!("\n🗃️  Heap Analysis:");

    if let Some(tables) = assembly.tables() {
        let heap_info = &tables.info;
        println!("  String heap size: {} bytes", heap_info.str_bytes());
        println!("  GUID heap size: {} bytes", heap_info.guid_bytes());
        println!("  Blob heap size: {} bytes", heap_info.blob_bytes());
    }

    // String heap analysis
    if let Some(_strings) = assembly.strings() {
        println!("  String heap contains metadata strings");
        // Note: The Strings heap doesn't expose iteration in the public API
        // This is intentional as it requires careful offset management
    }

    // GUID heap analysis
    if let Some(_guids) = assembly.guids() {
        println!("  GUID heap contains module and type identifiers");
        // Note: The Guid heap doesn't expose length in the public API
        // Individual GUIDs can be accessed by index via guids.get(index)
    }

    // Blob heap analysis
    if let Some(_blob) = assembly.blob() {
        println!("  Blob heap contains signatures, constants, and marshalling information");
        // Note: Blob heap doesn't expose size() method in public API
        // Individual blobs can be accessed by index via blob.get(index)
    }
}

fn print_type_system_analysis(assembly: &CilObject) {
    println!("\n🏗️  Type System Analysis:");

    let types = assembly.types();
    let mut namespace_stats: HashMap<String, usize> = HashMap::new();
    let mut type_kind_stats: HashMap<&str, usize> = HashMap::new();

    // Analyze types by namespace and kind
    for type_def in &types.all_types() {
        let namespace = if type_def.namespace.is_empty() {
            "<global>".to_string()
        } else {
            type_def.namespace.clone()
        };

        *namespace_stats.entry(namespace).or_insert(0) += 1;

        // Categorize by common patterns
        if type_def.name.ends_with("Attribute") {
            *type_kind_stats.entry("Attributes").or_insert(0) += 1;
        } else if type_def.name.ends_with("Exception") {
            *type_kind_stats.entry("Exceptions").or_insert(0) += 1;
        } else if type_def.name.ends_with("EventArgs") {
            *type_kind_stats.entry("EventArgs").or_insert(0) += 1;
        } else if type_def.name.starts_with('I')
            && type_def.name.len() > 1
            && type_def.name.chars().nth(1).unwrap().is_uppercase()
        {
            *type_kind_stats.entry("Interfaces").or_insert(0) += 1;
        } else {
            *type_kind_stats.entry("Classes").or_insert(0) += 1;
        }
    }

    // Display namespace statistics
    println!("  Top namespaces by type count:");
    let mut sorted_ns: Vec<_> = namespace_stats.iter().collect();
    sorted_ns.sort_by(|a, b| b.1.cmp(a.1));
    for (namespace, count) in sorted_ns.iter().take(8) {
        println!("    {}: {} types", namespace, count);
    }

    // Display type kind statistics
    println!("  Type categories:");
    for (kind, count) in &type_kind_stats {
        println!("    {}: {} types", kind, count);
    }
}

fn print_dependency_analysis(assembly: &CilObject) {
    println!("\n🔗 Dependency Analysis:");

    // Assembly references analysis using the correct public API
    let assembly_refs = assembly.refs_assembly();
    println!("  Assembly references: {}", assembly_refs.len());

    if !assembly_refs.is_empty() {
        println!("  Referenced assemblies:");
        for (i, entry) in assembly_refs.iter().take(10).enumerate() {
            let assembly_ref = entry.value();
            let culture = assembly_ref
                .culture
                .as_ref()
                .map_or("neutral", |c| c.as_str());
            let version = format!(
                "{}.{}.{}.{}",
                assembly_ref.major_version,
                assembly_ref.minor_version,
                assembly_ref.build_number,
                assembly_ref.revision_number
            );

            // Decode assembly flags for better readability
            let mut flag_descriptions = Vec::new();
            if assembly_ref.flags & 0x0001 > 0 {
                flag_descriptions.push("PublicKey");
            }
            if assembly_ref.flags & 0x0100 > 0 {
                flag_descriptions.push("Retargetable");
            }
            if assembly_ref.flags & 0x4000 > 0 {
                flag_descriptions.push("DisableJITOptimizer");
            }
            if assembly_ref.flags & 0x8000 > 0 {
                flag_descriptions.push("EnableJITTracking");
            }
            let flags_str = if flag_descriptions.is_empty() {
                "None".to_string()
            } else {
                flag_descriptions.join(", ")
            };

            println!("    {}. {} v{}", i + 1, assembly_ref.name, version);
            println!("       Culture: {}, Flags: {}", culture, flags_str);

            // Show identifier information if available
            if let Some(ref identifier) = assembly_ref.identifier {
                match identifier {
                    dotscope::metadata::identity::Identity::PubKey(key) => {
                        println!("       PublicKey: {} bytes", key.len());
                    }
                    dotscope::metadata::identity::Identity::Token(token) => {
                        println!("       Token: 0x{:016X}", token);
                    }
                }
            }

            // Show hash information if available
            if assembly_ref.hash.is_some() {
                println!("       Hash: present");
            }
        }
        if assembly_refs.len() > 10 {
            println!("    ... and {} more", assembly_refs.len() - 10);
        }
    }

    // Module references analysis using the correct public API
    let module_refs = assembly.refs_module();
    println!("  Module references: {}", module_refs.len());

    if !module_refs.is_empty() {
        println!("  Referenced modules:");
        for (i, entry) in module_refs.iter().take(10).enumerate() {
            let module_ref = entry.value();
            println!("    {}. {}", i + 1, module_ref.name);
        }
        if module_refs.len() > 10 {
            println!("    ... and {} more", module_refs.len() - 10);
        }
    }

    // Import analysis
    let imports = assembly.imports();
    println!("  Total imports: {}", imports.len());

    // Export analysis
    let exports = assembly.exports();
    println!("  Total exports: {}", exports.len());
}
