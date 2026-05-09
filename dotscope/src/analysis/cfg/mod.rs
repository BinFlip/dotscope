//! Control Flow Graph (CFG) construction and analysis.
//!
//! This module provides a proper graph abstraction over CIL basic blocks with
//! efficient traversal, dominator computation, and loop detection capabilities.
//!
//! # Architecture
//!
//! The CFG builds upon generic graph infrastructure, providing CIL-specific node
//! and edge types while leveraging shared algorithms for dominators, traversals,
//! and strongly connected components.
//!
//! # Key Components
//!
//! - [`ControlFlowGraph`] - The main CFG structure wrapping basic blocks
//! - [`CfgEdge`] / [`CfgEdgeKind`] - Edges and their control-flow classification
//! - [`LoopAnalyzer`] / [`LoopForest`] / [`LoopInfo`] - Loop detection (re-exported
//!   from `analyssa::analysis::loops` / `analyssa::analysis::loop_analyzer`)
//! - [`SemanticAnalyzer`] / [`BlockSemantics`] / [`LoopSemantics`] - Higher-level
//!   block- and loop-role classification used by deobfuscation passes
//!
//! # Edge Types
//!
//! The CFG distinguishes several types of control flow edges:
//!
//! - **Unconditional**: Direct jumps or fall-through to a single successor
//! - **Conditional True/False**: Branches based on a condition
//! - **Switch**: Multi-way branches with case values
//! - **Exception**: Edges to exception handlers
//!
//! # Lazy Computation
//!
//! Expensive analyses like dominator trees and loop information are computed
//! lazily on first access and cached for subsequent queries. This is implemented
//! using [`std::sync::OnceLock`] for thread-safe initialization.
//!
//! # Examples
//!
//! ## Building a CFG from Basic Blocks
//!
//! ```rust,ignore
//! use dotscope::analysis::ControlFlowGraph;
//! use dotscope::assembly::decode_blocks;
//!
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let graph = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! println!("CFG has {} blocks", graph.block_count());
//! println!("Entry block: {:?}", graph.entry());
//! ```
//!
//! ## Traversing the CFG
//!
//! ```rust,ignore
//! use dotscope::analysis::ControlFlowGraph;
//!
//! let graph = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Iterate in reverse postorder (useful for data flow)
//! for block_id in graph.reverse_postorder() {
//!     let block = graph.block(block_id).unwrap();
//!     println!("Block {} at RVA 0x{:x}", block_id, block.basic_block.rva);
//! }
//! ```
//!
//! ## Computing Dominators
//!
//! ```rust,ignore
//! use dotscope::analysis::ControlFlowGraph;
//!
//! let graph = ControlFlowGraph::from_basic_blocks(blocks)?;
//! let dominators = graph.dominators();
//!
//! // Check domination relationships
//! if dominators.dominates(graph.entry(), some_block) {
//!     println!("Entry dominates the target block");
//! }
//!
//! // Get dominance frontiers for SSA construction
//! let frontiers = graph.dominance_frontiers();
//! ```
//!
//! # Thread Safety
//!
//! [`ControlFlowGraph`] is [`Send`] and [`Sync`], enabling safe concurrent read
//! access after construction. The lazy-initialized dominator tree and loop info
//! use [`std::sync::OnceLock`] for thread-safe initialization.

mod edge;
mod graph;
mod semantics;

pub use edge::{CfgEdge, CfgEdgeKind};
pub use graph::ControlFlowGraph;
pub use semantics::{BlockSemantics, LoopSemantics, SemanticAnalyzer};

// `LoopAnalyzer` and the extended-loop primitives live analyssa-side. CIL
// callers reach them through these aliases / re-exports.
use crate::analysis::ssa::CilTarget;

#[cfg(feature = "compiler")]
pub use analyssa::analysis::loop_analyzer::SsaLoopAnalysis;
#[cfg(feature = "x86")]
pub use analyssa::analysis::loops::has_back_edges;
pub use analyssa::analysis::loops::{detect_loops, InductionVar, LoopForest, LoopInfo};

/// CIL-defaulted alias of [`analyssa::analysis::loop_analyzer::LoopAnalyzer`].
pub type LoopAnalyzer<'a, T = CilTarget> = analyssa::analysis::loop_analyzer::LoopAnalyzer<'a, T>;
