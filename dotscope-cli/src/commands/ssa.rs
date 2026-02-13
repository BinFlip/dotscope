use std::{fmt::Write as _, path::Path};

use anyhow::Context;
use dotscope::analysis::{SsaBlock, SsaFunction, SsaVarId};

use crate::commands::{common::load_assembly, resolution::resolve_single_method};

pub fn run(
    path: &Path,
    method_filter: &str,
    show_phis: bool,
    show_types: bool,
) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let method = resolve_single_method(&assembly, method_filter)?;

    let method_label = format!("{} (0x{:08X})", method.name, method.token.value());

    let ssa = method
        .ssa(&assembly)
        .with_context(|| format!("method {method_label} has no body or cannot build SSA"))?;

    if show_types {
        print_ssa_with_types(&ssa, &method_label, show_phis);
    } else if !show_phis {
        print_ssa_no_phis(&ssa, &method_label);
    } else {
        // Default: use the Display impl which already includes phis
        println!("SSA for {method_label}");
        println!();
        print!("{ssa}");
    }

    Ok(())
}

/// Print SSA output with phi nodes filtered out.
fn print_ssa_no_phis(ssa: &SsaFunction, label: &str) {
    println!("SSA for {label}");
    println!("  Variables: {}", ssa.variable_count());
    println!("  Blocks: {}", ssa.block_count());
    println!();

    for block in ssa.blocks() {
        println!("B{}:", block.id());
        for instr in block.instructions() {
            println!("  {instr}");
        }
    }
}

/// Print SSA output with type annotations on variables.
fn print_ssa_with_types(ssa: &SsaFunction, label: &str, show_phis: bool) {
    println!("SSA for {label}");
    println!("  Variables: {}", ssa.variable_count());
    println!("  Blocks: {}", ssa.block_count());
    println!();

    // Variable summary with types
    let typed_count = ssa
        .variables()
        .iter()
        .filter(|v| v.has_known_type())
        .count();
    if typed_count > 0 {
        println!("Variables with known types:");
        for var in ssa.variables() {
            if var.has_known_type() {
                println!("  {}: {}", var, var.var_type());
            }
        }
        println!();
    }

    for block in ssa.blocks() {
        print_block_with_types(block, ssa, show_phis);
    }
}

fn print_block_with_types(block: &SsaBlock, ssa: &SsaFunction, show_phis: bool) {
    println!("B{}:", block.id());

    if show_phis {
        for phi in block.phi_nodes() {
            let result_id = phi.result();
            let type_annotation = type_annotation_for(ssa, result_id);
            println!("  {phi}{type_annotation}");
        }
    }

    for instr in block.instructions() {
        // Try to annotate the defined variable's type
        let def_annotation = instr
            .def()
            .and_then(|var_id| {
                let idx = var_id.index();
                ssa.variables().get(idx)
            })
            .filter(|v| v.has_known_type())
            .map(|v| format!("  // -> {}", v.var_type()))
            .unwrap_or_default();

        println!("  {instr}{def_annotation}");
    }
}

fn type_annotation_for(ssa: &SsaFunction, var_id: SsaVarId) -> String {
    let idx = var_id.index();
    match ssa.variables().get(idx) {
        Some(v) if v.has_known_type() => {
            let mut s = String::new();
            let _ = write!(s, "  // -> {}", v.var_type());
            s
        }
        _ => String::new(),
    }
}
