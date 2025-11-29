//! Control Flow Graph (CFG) construction and analysis.
//!
//! This module provides a proper graph abstraction over CIL basic blocks with
//! efficient traversal, dominator computation, and loop detection capabilities.
//!
//! # Architecture
//!
//! The CFG builds upon the generic [`crate::utils::graph::DirectedGraph`] infrastructure,
//! providing CIL-specific node and edge types while leveraging shared algorithms for
//! dominators, traversals, and strongly connected components.
//!
//! # Key Components
//!
//! - [`ControlFlowGraph`] - The main CFG structure wrapping basic blocks
//! - [`CfgEdge`] - Edge representation with control flow semantics
//! - [`CfgEdgeKind`] - Classification of edge types (unconditional, conditional, etc.)
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
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! println!("CFG has {} blocks", cfg.block_count());
//! println!("Entry block: {:?}", cfg.entry());
//! ```
//!
//! ## Traversing the CFG
//!
//! ```rust,ignore
//! use dotscope::analysis::ControlFlowGraph;
//!
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Iterate in reverse postorder (useful for data flow)
//! for block_id in cfg.reverse_postorder() {
//!     let block = cfg.block(block_id).unwrap();
//!     println!("Block {} at RVA 0x{:x}", block_id, block.basic_block.rva);
//! }
//! ```
//!
//! ## Computing Dominators
//!
//! ```rust,ignore
//! use dotscope::analysis::ControlFlowGraph;
//!
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//! let dominators = cfg.dominators();
//!
//! // Check domination relationships
//! if dominators.dominates(cfg.entry(), some_block) {
//!     println!("Entry dominates the target block");
//! }
//!
//! // Get dominance frontiers for SSA construction
//! let frontiers = cfg.dominance_frontiers();
//! ```
//!
//! # Thread Safety
//!
//! [`ControlFlowGraph`] is [`Send`] and [`Sync`], enabling safe concurrent read
//! access after construction. The lazy-initialized dominator tree and loop info
//! use [`std::sync::OnceLock`] for thread-safe initialization.

mod edge;
mod graph;

pub use edge::{CfgEdge, CfgEdgeKind};
pub use graph::{ControlFlowGraph, NaturalLoop};
