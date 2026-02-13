use std::path::Path;

use anyhow::{bail, Context};
use dotscope::analysis::CfgEdgeKind;
use serde::Serialize;

use crate::{
    commands::{common::load_assembly, resolution::resolve_single_method},
    output::{Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct CfgSuccessorOutput {
    block: usize,
    edge_type: String,
}

#[derive(Debug, Serialize)]
struct CfgBlockOutput {
    id: usize,
    instruction_count: usize,
    successors: Vec<CfgSuccessorOutput>,
}

#[derive(Debug, Serialize)]
struct LoopOutput {
    header: usize,
    loop_type: String,
    depth: usize,
    body: Vec<usize>,
    exits: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct CfgOutput {
    method: String,
    block_count: usize,
    entry: usize,
    exits: Vec<usize>,
    blocks: Vec<CfgBlockOutput>,
    loops: Option<Vec<LoopOutput>>,
}

pub fn run(path: &Path, method_filter: &str, format: &str, show_loops: bool) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let method = resolve_single_method(&assembly, method_filter)?;

    let method_label = format!("{} (0x{:08X})", method.name, method.token.value());

    let cfg = method
        .cfg()
        .with_context(|| format!("method {method_label} has no body or cannot build CFG"))?;

    match format {
        "json" => {
            let entry = cfg.entry();
            let exits: Vec<usize> = cfg.exits().iter().map(|e| e.index()).collect();

            let mut blocks = Vec::new();
            for node_id in cfg.reverse_postorder() {
                let Some(block) = cfg.block(node_id) else {
                    continue;
                };

                let successors: Vec<CfgSuccessorOutput> = cfg
                    .outgoing_edges(node_id)
                    .map(|(_, target, edge)| CfgSuccessorOutput {
                        block: target.index(),
                        edge_type: edge_kind_label(edge.kind()).to_string(),
                    })
                    .collect();

                blocks.push(CfgBlockOutput {
                    id: node_id.index(),
                    instruction_count: block.instructions.len(),
                    successors,
                });
            }

            let loops = if show_loops {
                let loop_infos = cfg.loops();
                Some(
                    loop_infos
                        .iter()
                        .map(|li| {
                            let mut body: Vec<usize> = li.body.iter().map(|n| n.index()).collect();
                            body.sort_unstable();
                            let loop_exits: Vec<usize> =
                                li.exits.iter().map(|e| e.exit_block.index()).collect();
                            LoopOutput {
                                header: li.header.index(),
                                loop_type: format!("{:?}", li.loop_type),
                                depth: li.depth,
                                body,
                                exits: loop_exits,
                            }
                        })
                        .collect(),
                )
            } else {
                None
            };

            let output = CfgOutput {
                method: method_label,
                block_count: cfg.block_count(),
                entry: entry.index(),
                exits,
                blocks,
                loops,
            };

            let json = serde_json::to_string_pretty(&output)?;
            println!("{json}");
        }
        "dot" => {
            println!("{}", cfg.to_dot(Some(&method_label)));
        }
        "text" => {
            // Summary line
            let entry = cfg.entry();
            let exits = cfg.exits();
            let exit_labels: Vec<String> =
                exits.iter().map(|e| format!("B{}", e.index())).collect();

            println!("Control flow graph for {method_label}");
            println!(
                "Blocks: {}, Entry: B{}, Exits: {}",
                cfg.block_count(),
                entry.index(),
                if exit_labels.is_empty() {
                    "(none)".to_string()
                } else {
                    exit_labels.join(", ")
                }
            );
            println!();

            // Per-block table
            let mut tw = TabWriter::new(&[
                ("Block", Align::Left),
                ("Instructions", Align::Right),
                ("Successors", Align::Left),
                ("Edge types", Align::Left),
            ]);

            for node_id in cfg.reverse_postorder() {
                let Some(block) = cfg.block(node_id) else {
                    continue;
                };

                let block_label = format!("B{}", node_id.index());
                let instr_count = block.instructions.len().to_string();

                let edges: Vec<_> = cfg.outgoing_edges(node_id).collect();

                let successors: Vec<String> = edges
                    .iter()
                    .map(|(_, target, _)| format!("B{}", target.index()))
                    .collect();

                let edge_types: Vec<String> = edges
                    .iter()
                    .map(|(_, target, edge)| {
                        let kind_str = edge_kind_label(edge.kind());
                        format!("{kind_str} -> B{}", target.index())
                    })
                    .collect();

                let succ_str = if successors.is_empty() {
                    "(exit)".to_string()
                } else {
                    successors.join(", ")
                };

                let edge_str = if edge_types.is_empty() {
                    "(exit)".to_string()
                } else {
                    edge_types.join(", ")
                };

                tw.row(vec![block_label, instr_count, succ_str, edge_str]);
            }

            tw.print();

            // Loop analysis
            if show_loops {
                let loops = cfg.loops();
                println!();
                if loops.is_empty() {
                    println!("Loops: 0");
                } else {
                    println!("Loops: {}", loops.len());
                    for (i, loop_info) in loops.iter().enumerate() {
                        let mut body: Vec<usize> =
                            loop_info.body.iter().map(|n| n.index()).collect();
                        body.sort_unstable();
                        let body_str: Vec<String> = body.iter().map(|b| format!("B{b}")).collect();

                        let exits_str: Vec<String> = loop_info
                            .exits
                            .iter()
                            .map(|e| format!("B{}", e.exit_block.index()))
                            .collect();

                        println!(
                            "  Loop {i}: header=B{}, type={:?}, depth={}, body={{{}}}, exits={{{}}}",
                            loop_info.header.index(),
                            loop_info.loop_type,
                            loop_info.depth,
                            body_str.join(", "),
                            exits_str.join(", "),
                        );
                    }
                }
            }
        }
        other => bail!("unsupported format '{other}'; expected 'text', 'dot', or 'json'"),
    }

    Ok(())
}

fn edge_kind_label(kind: &CfgEdgeKind) -> &'static str {
    match kind {
        CfgEdgeKind::Unconditional => "unconditional",
        CfgEdgeKind::ConditionalTrue => "conditional_true",
        CfgEdgeKind::ConditionalFalse => "conditional_false",
        CfgEdgeKind::Switch { .. } => "switch",
        CfgEdgeKind::ExceptionHandler { .. } => "exception_handler",
        CfgEdgeKind::Leave => "leave",
        CfgEdgeKind::EndFinally => "end_finally",
    }
}
