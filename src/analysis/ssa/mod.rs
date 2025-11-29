//! Static Single Assignment (SSA) form for CIL methods.
//!
//! This module provides SSA transformation for .NET CIL bytecode, converting
//! stack-based operations into an explicit variable form where each variable
//! is assigned exactly once. This representation enables powerful optimizations
//! and analyses like constant propagation, dead code elimination, and type inference.
//!
//! # Architecture
//!
//! The SSA module is organized into focused sub-modules:
//!
//! - [`variable`] - SSA variable representation and identifiers
//! - [`phi`] - Phi node representation for control flow merges
//! - [`instruction`] - SSA-form instructions with explicit def/use chains
//! - [`block`] - SSA basic blocks containing phi nodes and instructions
//! - [`function`] - Complete SSA representation of a method
//! - [`builder`] - SSA construction algorithm (Cytron et al.)
//! - [`types`] - SSA type system for CIL types
//! - [`value`] - Value tracking for constant propagation and CSE
//! - [`ops`] - Decomposed SSA operations
//!
//! # CIL to SSA Transformation
//!
//! CIL is a stack-based instruction set, while SSA uses explicit variables.
//! The transformation involves several phases:
//!
//! 1. **Stack Simulation**: Convert implicit stack operations to explicit variables
//! 2. **Phi Placement**: Insert phi nodes at dominance frontiers
//! 3. **Variable Renaming**: Assign unique versions using dominator tree traversal
//!
//! ## Variable Origins
//!
//! SSA variables can originate from several sources:
//!
//! - **Arguments**: Method parameters (`ldarg`, `starg`)
//! - **Locals**: Local variables (`ldloc`, `stloc`)
//! - **Stack slots**: Temporary values from stack operations
//! - **Phi nodes**: Merged values at control flow joins
//!
//! ## Address-Taking Considerations
//!
//! Variables whose address is taken (`ldarga`, `ldloca`) require special handling
//! as they may be modified through pointers. These are tracked separately and
//! may be excluded from full SSA optimization.
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{ControlFlowGraph, ssa::SsaBuilder};
//! use dotscope::assembly::decode_blocks;
//!
//! // Build CFG from decoded blocks
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Construct SSA form
//! let ssa = SsaBuilder::build(&cfg, num_args, num_locals)?;
//!
//! // Analyze phi nodes at merge points
//! for block in ssa.blocks() {
//!     for phi in block.phi_nodes() {
//!         println!("Phi: {:?} = phi({:?})", phi.result(), phi.operands());
//!     }
//! }
//! ```
//!
//! # References
//!
//! - Cytron et al., "Efficiently Computing Static Single Assignment Form and the
//!   Control Dependence Graph", ACM TOPLAS 1991
//! - Cooper & Torczon, "Engineering a Compiler", Chapter 9

mod block;
mod builder;
mod decompose;
mod function;
mod instruction;
mod ops;
mod phi;
mod stack;
mod types;
mod value;
mod variable;

// Re-export primary types at module level
pub use block::SsaBlock;
pub use builder::SsaBuilder;
pub use function::SsaFunction;
pub use instruction::SsaInstruction;
pub use ops::SsaOp;
pub use phi::{PhiNode, PhiOperand};
pub use stack::{SimulationResult, StackSimulator};
pub use types::{FieldRef, FnPtrSig, MethodRef, SigRef, SsaType, TypeRef};
pub use value::{AbstractValue, ComputedOp, ComputedValue, ConstValue};
pub use variable::{DefSite, SsaVarId, SsaVariable, UseSite, VariableOrigin};
