//! SSA and Disassembly Viewer for .NET Assemblies
//!
//! This example demonstrates how to load a .NET assembly,
//! find a specific method, and display its SSA form alongside the disassembly.
//!
//! # Usage
//!
//! ```bash
//! # View method by name (supports partial matching)
//! cargo run --example ssa_viewer -- --file path/to/assembly.dll --method "MyClass::MyMethod"
//!
//! # View method by RVA
//! cargo run --example ssa_viewer -- --file path/to/assembly.dll --rva 0x2050
//!
//! # With additional search paths for dependencies
//! cargo run --example ssa_viewer -- --file path/to/assembly.dll --search /path/to/deps --method "Main"
//!
//! # List all methods in the assembly
//! cargo run --example ssa_viewer -- --file path/to/assembly.dll --list
//! ```

use dotscope::analysis::{ControlFlowGraph, NodeId, SsaBuilder, SsaFunction};
use dotscope::assembly::decode_blocks;
use dotscope::metadata::method::MethodRc;
use dotscope::project::ProjectLoader;
use dotscope::CilObject;
use std::path::PathBuf;
use std::sync::Arc;

/// Command line arguments
struct Args {
    file: PathBuf,
    search_paths: Vec<PathBuf>,
    method_name: Option<String>,
    rva: Option<u64>,
    list_methods: bool,
    show_disasm: bool,
    show_ssa: bool,
    show_cfg: bool,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().collect();

    let mut file: Option<PathBuf> = None;
    let mut search_paths = Vec::new();
    let mut method_name = None;
    let mut rva = None;
    let mut list_methods = false;
    let mut show_disasm = true;
    let mut show_ssa = true;
    let mut show_cfg = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "-f" => {
                i += 1;
                if i >= args.len() {
                    return Err("--file requires a path argument".to_string());
                }
                file = Some(PathBuf::from(&args[i]));
            }
            "--search" | "-s" => {
                i += 1;
                if i >= args.len() {
                    return Err("--search requires a path argument".to_string());
                }
                search_paths.push(PathBuf::from(&args[i]));
            }
            "--method" | "-m" => {
                i += 1;
                if i >= args.len() {
                    return Err("--method requires a name argument".to_string());
                }
                method_name = Some(args[i].clone());
            }
            "--rva" | "-r" => {
                i += 1;
                if i >= args.len() {
                    return Err("--rva requires a hex address argument".to_string());
                }
                let rva_str = args[i].trim_start_matches("0x").trim_start_matches("0X");
                rva = Some(
                    u64::from_str_radix(rva_str, 16)
                        .map_err(|_| format!("Invalid RVA: {}", args[i]))?,
                );
            }
            "--list" | "-l" => {
                list_methods = true;
            }
            "--no-disasm" => {
                show_disasm = false;
            }
            "--no-ssa" => {
                show_ssa = false;
            }
            "--cfg" => {
                show_cfg = true;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                // If no flag, treat as file path if file not set
                if file.is_none() && !other.starts_with('-') {
                    file = Some(PathBuf::from(other));
                } else {
                    return Err(format!("Unknown argument: {}", other));
                }
            }
        }
        i += 1;
    }

    let file = file.ok_or("Missing required --file argument")?;

    Ok(Args {
        file,
        search_paths,
        method_name,
        rva,
        list_methods,
        show_disasm,
        show_ssa,
        show_cfg,
    })
}

fn print_help() {
    println!(
        r#"SSA and Disassembly Viewer for .NET Assemblies

USAGE:
    cargo run --example ssa_viewer -- [OPTIONS] --file <FILE>

OPTIONS:
    -f, --file <FILE>       Path to the .NET assembly to analyze (required)
    -s, --search <PATH>     Additional search path for dependencies (can be repeated)
    -m, --method <NAME>     Method name to find (supports partial matching)
    -r, --rva <ADDRESS>     Method RVA in hex (e.g., 0x2050)
    -l, --list              List all methods in the assembly
        --no-disasm         Don't show disassembly
        --no-ssa            Don't show SSA form
        --cfg               Show CFG information
    -h, --help              Show this help message

EXAMPLES:
    # View a specific method by name
    cargo run --example ssa_viewer -- --file MyApp.dll --method "Program::Main"

    # View method by RVA
    cargo run --example ssa_viewer -- --file MyApp.dll --rva 0x2050

    # List all methods
    cargo run --example ssa_viewer -- --file MyApp.dll --list

    # With dependency search path
    cargo run --example ssa_viewer -- --file MyApp.dll --search /usr/share/dotnet/shared --method Main
"#
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args().map_err(|e| {
        eprintln!("Error: {}", e);
        eprintln!("Use --help for usage information");
        e
    })?;

    println!("Loading assembly: {}", args.file.display());

    // Build the project using ProjectLoader
    let mut loader = ProjectLoader::new().primary_file(&args.file)?;

    for path in &args.search_paths {
        println!("Adding search path: {}", path.display());
        loader = loader.with_search_path(path)?;
    }

    // Enable auto-discovery of dependencies
    loader = loader.auto_discover(true);

    let result = loader.build()?;

    // Report any issues
    if result.has_failures() {
        eprintln!(
            "\nWarning: {} assemblies failed to load",
            result.failure_count()
        );
        for (name, reason) in &result.failed_loads {
            eprintln!("  - {}: {}", name, reason);
        }
    }

    // Get the project
    let project = &result.project;

    // Get the primary assembly
    let primary = project
        .get_primary()
        .ok_or("Failed to get primary assembly")?;

    if args.list_methods {
        list_methods(&primary)?;
        return Ok(());
    }

    // Find the method
    let method = if let Some(ref name) = args.method_name {
        find_method_by_name(&primary, name)?
    } else if let Some(rva) = args.rva {
        find_method_by_rva(&primary, rva)?
    } else {
        return Err("Must specify either --method or --rva".into());
    };

    // Display method info
    display_method(&primary, &method, &args)?;

    Ok(())
}

fn list_methods(assembly: &CilObject) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Methods in Assembly ===\n");

    let methods = assembly.methods();
    let mut count = 0;

    for entry in methods.iter() {
        let method = entry.value();
        if let Some(rva) = method.rva {
            if rva > 0 {
                let type_name = assembly
                    .types()
                    .iter()
                    .find(|t| {
                        t.value().methods.iter().any(|(_, m)| {
                            m.upgrade()
                                .map(|m| m.token == method.token)
                                .unwrap_or(false)
                        })
                    })
                    .map(|t| {
                        let ty = t.value();
                        if ty.namespace.is_empty() {
                            ty.name.clone()
                        } else {
                            format!("{}.{}", ty.namespace, ty.name)
                        }
                    })
                    .unwrap_or_else(|| "<unknown>".to_string());

                println!("  0x{:08X}  {}::{}", rva, type_name, method.name);
                count += 1;
            }
        }
    }

    println!("\nTotal: {} methods with bodies", count);
    Ok(())
}

fn find_method_by_name(
    assembly: &CilObject,
    name: &str,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    let methods = assembly.methods();

    // Try exact match first, then partial match
    let mut matches = Vec::new();

    for entry in methods.iter() {
        let method = entry.value();

        if method.rva.is_none() || method.rva == Some(0) {
            continue;
        }

        // Find type name
        let type_name = assembly
            .types()
            .iter()
            .find(|t| {
                t.value().methods.iter().any(|(_, m)| {
                    m.upgrade()
                        .map(|m| m.token == method.token)
                        .unwrap_or(false)
                })
            })
            .map(|t| {
                let ty = t.value();
                if ty.namespace.is_empty() {
                    ty.name.clone()
                } else {
                    format!("{}.{}", ty.namespace, ty.name)
                }
            })
            .unwrap_or_else(|| "<unknown>".to_string());

        let full_name = format!("{}::{}", type_name, method.name);

        // Check for match
        let is_exact = full_name == name || method.name == name;
        let is_partial = full_name.contains(name) || method.name.contains(name);

        if is_exact {
            return Ok(method.clone());
        }
        if is_partial {
            matches.push((full_name, method.clone()));
        }
    }

    match matches.len() {
        0 => Err(format!("No method found matching '{}'", name).into()),
        1 => Ok(matches.into_iter().next().unwrap().1),
        _ => {
            println!("Multiple methods match '{}':", name);
            for (i, (full_name, method)) in matches.iter().enumerate() {
                println!(
                    "  {}. {} (RVA: 0x{:08X})",
                    i + 1,
                    full_name,
                    method.rva.unwrap_or(0)
                );
            }
            Err("Please be more specific".into())
        }
    }
}

fn find_method_by_rva(
    assembly: &CilObject,
    rva: u64,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    let methods = assembly.methods();

    for entry in methods.iter() {
        let method = entry.value();
        if method.rva == Some(rva as u32) {
            return Ok(method.clone());
        }
    }

    Err(format!("No method found at RVA 0x{:08X}", rva).into())
}

fn display_method(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find type name
    let type_name = assembly
        .types()
        .iter()
        .find(|t| {
            t.value().methods.iter().any(|(_, m)| {
                m.upgrade()
                    .map(|m| m.token == method.token)
                    .unwrap_or(false)
            })
        })
        .map(|t| {
            let ty = t.value();
            if ty.namespace.is_empty() {
                ty.name.clone()
            } else {
                format!("{}.{}", ty.namespace, ty.name)
            }
        })
        .unwrap_or_else(|| "<unknown>".to_string());

    let rva = method.rva.unwrap_or(0);
    // Include 'this' parameter for instance methods
    let num_args =
        method.signature.param_count as usize + if method.signature.has_this { 1 } else { 0 };
    let num_locals = method.local_vars.count();

    println!("\n{}", "=".repeat(80));
    println!("Method: {}::{}", type_name, method.name);
    println!("RVA: 0x{:08X} | Token: {:?}", rva, method.token);
    println!("Arguments: {} | Locals: {}", num_args, num_locals);
    println!("{}", "=".repeat(80));

    // Get method body from blocks
    let blocks = method.blocks.get();
    if blocks.is_none() || blocks.map(|b| b.is_empty()).unwrap_or(true) {
        println!("\nMethod has no decoded blocks");
        return Ok(());
    }

    let blocks = blocks.unwrap();

    // Collect all instructions
    let all_instrs: Vec<_> = blocks
        .iter()
        .flat_map(|b| b.instructions.iter().cloned())
        .collect();

    if all_instrs.is_empty() {
        println!("\nNo instructions in method");
        return Ok(());
    }

    // Get the raw bytes from the first instruction to the last
    let first_rva = all_instrs.first().map(|i| i.rva).unwrap_or(0);
    let last_instr = all_instrs.last().unwrap();
    let total_size = (last_instr.rva - first_rva + last_instr.size as u64) as usize;

    // Get the actual bytes from the assembly
    let file = assembly.file();
    let body_data = if let Ok(file_offset) = file.rva_to_offset(first_rva as usize) {
        let data = file.data();
        let end = (file_offset + total_size).min(data.len());
        data[file_offset..end].to_vec()
    } else {
        Vec::new()
    };

    if body_data.is_empty() {
        println!("\nCouldn't read method body data");
        return Ok(());
    }

    // Decode to our own basic blocks for CFG
    let cfg_blocks = decode_blocks(&body_data, 0, first_rva as usize, Some(body_data.len()))?;

    if cfg_blocks.is_empty() {
        println!("\nNo basic blocks decoded");
        return Ok(());
    }

    // Build CFG
    let cfg = ControlFlowGraph::from_basic_blocks(cfg_blocks)?;

    if args.show_cfg {
        println!("\n--- Control Flow Graph ---");
        println!("Blocks: {}", cfg.block_count());
        println!("Has loops: {}", cfg.has_loops());
        if cfg.has_loops() {
            let loops = cfg.loops();
            println!("Loop count: {}", loops.len());
            for (i, l) in loops.iter().enumerate() {
                println!(
                    "  Loop {}: header=B{}, depth={}, body size={}",
                    i,
                    l.header.index(),
                    l.depth,
                    l.body.len()
                );
            }
        }
        println!();
    }

    if args.show_disasm {
        println!("\n--- Disassembly ---");
        for block_idx in 0..cfg.block_count() {
            if let Some(block) = cfg.block(NodeId::new(block_idx)) {
                println!("\nB{}: (RVA 0x{:08X})", block_idx, block.rva);
                for instr in &block.instructions {
                    print!("  {:08X}: {:12}", instr.rva, instr.mnemonic);
                    match &instr.operand {
                        dotscope::assembly::Operand::None => {}
                        op => print!(" {:?}", op),
                    }
                    if !instr.branch_targets.is_empty() {
                        print!(" -> {:?}", instr.branch_targets);
                    }
                    println!();
                }
            }
        }
    }

    if args.show_ssa {
        // Build SSA
        match SsaBuilder::build(&cfg, num_args, num_locals) {
            Ok(ssa) => {
                println!("\n--- SSA Form ---");
                display_ssa(&ssa);
            }
            Err(e) => {
                println!("\n--- SSA Form ---");
                println!("Failed to build SSA: {}", e);
            }
        }
    }

    Ok(())
}

fn display_ssa(ssa: &SsaFunction) {
    println!(
        "Variables: {} | Blocks: {} | Phi nodes: {}",
        ssa.variable_count(),
        ssa.block_count(),
        ssa.total_phi_count()
    );

    println!("\nVariables:");
    for var in ssa.variables() {
        println!(
            "  {} : {:?} v{} @ {:?}",
            var.id(),
            var.origin(),
            var.version(),
            var.def_site()
        );
    }

    println!();

    for block in ssa.blocks() {
        println!("B{}:", block.id());

        // Phi nodes
        for phi in block.phi_nodes() {
            println!("  {}", phi);
        }

        // Instructions
        for instr in block.instructions() {
            println!("    {}", instr);
        }

        println!();
    }
}
