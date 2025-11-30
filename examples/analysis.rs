//! Analysis Viewer for .NET Assemblies
//!
//! This example demonstrates how to load a .NET assembly and display various
//! analysis results including disassembly, SSA form, control flow graphs, and call graphs.
//!
//! # Usage
//!
//! ```bash
//! # View disassembly of a method
//! cargo run --example analysis -- --file path/to/assembly.dll --method "Main" disasm
//!
//! # View SSA form of a method
//! cargo run --example analysis -- --file path/to/assembly.dll --method "Main" ssa
//!
//! # Export CFG in DOT format
//! cargo run --example analysis -- --file path/to/assembly.dll --method "Main" cfg
//!
//! # Export call graph in DOT format
//! cargo run --example analysis -- --file path/to/assembly.dll callgraph
//!
//! # List all methods in the assembly
//! cargo run --example analysis -- --file path/to/assembly.dll list
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use dotscope::analysis::{CallGraph, NodeId, SsaBuilder, SsaFunction};
use dotscope::metadata::method::MethodRc;
use dotscope::metadata::token::Token;
use dotscope::project::ProjectLoader;
use dotscope::CilObject;

#[derive(Parser)]
#[command(name = "analysis")]
#[command(about = "Analysis viewer for .NET assemblies", long_about = None)]
struct Cli {
    /// Path to the .NET assembly to analyze
    #[arg(short, long)]
    file: PathBuf,

    /// Additional search paths for dependencies (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Append)]
    search: Vec<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List all methods in the assembly
    List,

    /// Show disassembly of a method
    Disasm {
        /// Method name (supports partial matching)
        #[arg(short, long, group = "target")]
        method: Option<String>,

        /// Method RVA in hex (e.g., 0x2050)
        #[arg(short, long, group = "target", value_parser = parse_hex)]
        rva: Option<u64>,
    },

    /// Show SSA form of a method
    Ssa {
        /// Method name (supports partial matching)
        #[arg(short, long, group = "target")]
        method: Option<String>,

        /// Method RVA in hex (e.g., 0x2050)
        #[arg(short, long, group = "target", value_parser = parse_hex)]
        rva: Option<u64>,
    },

    /// Export control flow graph in DOT format
    Cfg {
        /// Method name (supports partial matching)
        #[arg(short, long, group = "target")]
        method: Option<String>,

        /// Method RVA in hex (e.g., 0x2050)
        #[arg(short, long, group = "target", value_parser = parse_hex)]
        rva: Option<u64>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Export call graph in DOT format
    Callgraph {
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("Invalid hex number: {}", e))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    eprintln!("Loading assembly: {}", cli.file.display());

    // Build the project using ProjectLoader
    let mut loader = ProjectLoader::new().primary_file(&cli.file)?;

    for path in &cli.search {
        eprintln!("Adding search path: {}", path.display());
        loader = loader.with_search_path(path)?;
    }

    loader = loader.auto_discover(true);
    let result = loader.build()?;

    if result.has_failures() {
        eprintln!(
            "\nWarning: {} assemblies failed to load",
            result.failure_count()
        );
        for (name, reason) in &result.failed_loads {
            eprintln!("  - {}: {}", name, reason);
        }
    }

    let primary = result
        .project
        .get_primary()
        .ok_or("Failed to get primary assembly")?;

    match cli.command {
        Command::List => list_methods(&primary),
        Command::Disasm { method, rva } => {
            let m = find_method(&primary, method.as_deref(), rva)?;
            display_disasm(&primary, &m)
        }
        Command::Ssa { method, rva } => {
            let m = find_method(&primary, method.as_deref(), rva)?;
            display_ssa_method(&primary, &m)
        }
        Command::Cfg {
            method,
            rva,
            output,
        } => {
            let m = find_method(&primary, method.as_deref(), rva)?;
            display_cfg(&primary, &m, output.as_deref())
        }
        Command::Callgraph { output } => display_callgraph(&primary, output.as_deref()),
    }
}

fn find_method(
    assembly: &Arc<CilObject>,
    name: Option<&str>,
    rva: Option<u64>,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    match (name, rva) {
        (Some(n), _) => find_method_by_name(assembly, n),
        (_, Some(r)) => find_method_by_rva(assembly, r),
        (None, None) => Err("Must specify --method or --rva".into()),
    }
}

fn list_methods(assembly: &CilObject) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Methods in Assembly ===\n");

    let methods = assembly.methods();
    let mut count = 0;

    for entry in methods {
        let method = entry.value();
        if let Some(rva) = method.rva {
            if rva > 0 {
                let type_name = get_method_type_name(assembly, method.token);
                println!("  0x{:08X}  {}::{}", rva, type_name, method.name);
                count += 1;
            }
        }
    }

    println!("\nTotal: {} methods with bodies", count);
    Ok(())
}

fn get_method_type_name(assembly: &CilObject, method_token: Token) -> String {
    assembly
        .types()
        .iter()
        .find(|t| {
            t.value().methods.iter().any(|(_, m)| {
                m.upgrade()
                    .map(|m| m.token == method_token)
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
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn find_method_by_name(
    assembly: &CilObject,
    name: &str,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    let methods = assembly.methods();
    let mut matches = Vec::new();

    for entry in methods {
        let method = entry.value();

        if method.rva.is_none() || method.rva == Some(0) {
            continue;
        }

        let type_name = get_method_type_name(assembly, method.token);
        let full_name = format!("{}::{}", type_name, method.name);

        if full_name == name || method.name == name {
            return Ok(method.clone());
        }
        if full_name.contains(name) || method.name.contains(name) {
            matches.push((full_name, method.clone()));
        }
    }

    match matches.len() {
        0 => Err(format!("No method found matching '{}'", name).into()),
        1 => Ok(matches.into_iter().next().unwrap().1),
        _ => {
            eprintln!("Multiple methods match '{}':", name);
            for (i, (full_name, method)) in matches.iter().enumerate() {
                eprintln!(
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
    for entry in assembly.methods() {
        let method = entry.value();
        if method.rva == Some(rva as u32) {
            return Ok(method.clone());
        }
    }
    Err(format!("No method found at RVA 0x{:08X}", rva).into())
}

fn display_disasm(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_name = get_method_type_name(assembly, method.token);
    let rva = method.rva.unwrap_or(0);
    let num_args = method.signature.param_count as usize + usize::from(method.signature.has_this);
    let num_locals = method.local_vars.count();

    println!("\n{}", "=".repeat(80));
    println!("Method: {}::{}", type_name, method.name);
    println!("RVA: 0x{:08X} | Token: {:?}", rva, method.token);
    println!("Arguments: {} | Locals: {}", num_args, num_locals);
    println!("{}", "=".repeat(80));

    let cfg = method
        .cfg()
        .ok_or("Method has no decoded blocks or CFG construction failed")?;

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

    Ok(())
}

fn display_ssa_method(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_name = get_method_type_name(assembly, method.token);
    let rva = method.rva.unwrap_or(0);
    let num_args = method.signature.param_count as usize + usize::from(method.signature.has_this);
    let num_locals = method.local_vars.count();

    println!("\n{}", "=".repeat(80));
    println!("Method: {}::{}", type_name, method.name);
    println!("RVA: 0x{:08X} | Token: {:?}", rva, method.token);
    println!("Arguments: {} | Locals: {}", num_args, num_locals);
    println!("{}", "=".repeat(80));

    let cfg = method
        .cfg()
        .ok_or("Method has no decoded blocks or CFG construction failed")?;

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
        for phi in block.phi_nodes() {
            println!("  {}", phi);
        }
        for instr in block.instructions() {
            println!("    {}", instr);
        }
        println!();
    }
}

fn display_cfg(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
    output_file: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_name = get_method_type_name(assembly, method.token);
    let cfg = method
        .cfg()
        .ok_or("Method has no decoded blocks or CFG construction failed")?;

    let dot = cfg.to_dot(Some(&format!("{}::{}", type_name, method.name)));

    if let Some(path) = output_file {
        std::fs::write(path, &dot)?;
        eprintln!("CFG written to: {}", path.display());
    } else {
        println!("{}", dot);
    }

    Ok(())
}

fn display_callgraph(
    assembly: &Arc<CilObject>,
    output_file: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Building call graph...");

    // Try to build from entry point first (cleaner graph for executables)
    // Fall back to full graph for libraries
    let callgraph = if let Some(cg) = CallGraph::build_from_entrypoint(assembly)? {
        eprintln!("Built from entry point (reachable methods only)");
        cg
    } else {
        eprintln!("No entry point found, building full call graph");
        CallGraph::build(assembly)?
    };

    let stats = callgraph.stats();
    eprintln!(
        "Call graph: {} methods, {} edges, {} call sites",
        stats.method_count, stats.edge_count, stats.total_call_sites
    );

    let dot = callgraph.to_dot(None);

    if let Some(path) = output_file {
        std::fs::write(path, &dot)?;
        eprintln!("Call graph written to: {}", path.display());
    } else {
        println!("{}", dot);
    }

    Ok(())
}
