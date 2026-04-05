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
//! use dotscope::analysis::{ControlFlowGraph, SsaConverter};
//! use dotscope::assembly::decode_blocks;
//!
//! // Build CFG from decoded blocks
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Construct SSA form
//! let ssa = SsaConverter::build(&cfg, num_args, num_locals, resolver)?;
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
mod cfg;
mod constraints;
mod consts;
mod converter;
mod decompose;
mod evaluator;
mod exception;
mod function;
mod instruction;
mod liveness;
mod memory;
mod ops;
mod patterns;
mod phi;
mod phis;
mod resolver;
mod stack;
mod symbolic;
mod types;
mod value;
mod variable;
pub(crate) mod verifier;

pub use block::{ReplaceResult, SsaBlock};
pub use builder::SsaFunctionBuilder;
pub use cfg::SsaCfg;
pub use consts::{evaluate_const_op, ConstEvaluator};
pub use converter::SsaConverter;
pub use evaluator::SsaEvaluator;
pub use exception::SsaExceptionHandler;
pub use function::{MethodPurity, ReturnInfo, SsaFunction, TrivialPhiOptions};
pub use instruction::SsaInstruction;
pub use ops::{BinaryOpKind, CmpKind, SsaOp, UnaryOpKind};
pub use phi::{PhiNode, PhiOperand};
pub use phis::PhiAnalyzer;
pub use resolver::ValueResolver;
pub use stack::{SimulationResult, StackSimulator, StackSlot, StackSlotSource};
#[cfg(feature = "z3")]
pub use symbolic::Z3Solver;
pub use symbolic::{SymbolicEvaluator, SymbolicExpr};
pub use types::{FieldRef, MethodRef, SsaType, TypeClass, TypeContext, TypeProvider, TypeRef};
pub use value::{AbstractValue, ConstValue};
pub use variable::{DefSite, FunctionVarAllocator, SsaVarId, SsaVariable, UseSite, VariableOrigin};
