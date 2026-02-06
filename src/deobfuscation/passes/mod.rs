//! Built-in deobfuscation passes.
//!
//! This module contains the standard SSA transformation passes used for
//! deobfuscation. Each pass operates on SSA form and returns an
//! [`EventLog`](crate::deobfuscation::EventLog) describing the modifications made.
//!
//! # Pipeline Phases
//!
//! The [`DeobfuscationEngine`](crate::deobfuscation::DeobfuscationEngine) organizes
//! passes into phases that run in a specific order. Within each phase, passes run
//! iteratively until a fixpoint is reached.
//!
//! ## Phase 1: Control-Flow Unflattening
//!
//! Recovers original control flow from dispatcher-based obfuscation.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`CffReconstructionPass`] | Full CFG reconstruction using Z3-backed state discovery |
//!
//! ## Phase 2: Normalization
//!
//! Cleans up code and propagates values after unflattening.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DeadCodeEliminationPass`] | Removes unreachable blocks, unused definitions, and op-less instructions |
//! | [`BlockMergingPass`] | Eliminates trampoline blocks (single-jump blocks) |
//! | [`ConstantPropagationPass`] | Propagates and folds constant values using SCCP |
//! | [`GlobalValueNumberingPass`] | Eliminates redundant computations via value numbering |
//! | [`CopyPropagationPass`] | Eliminates redundant copy operations and phi nodes |
//! | [`StrengthReductionPass`] | Replaces expensive operations with cheaper equivalents |
//! | [`AlgebraicSimplificationPass`] | Simplifies algebraic expressions (x + 0 → x, etc.) |
//! | [`ReassociationPass`] | Reorders associative operations for optimization |
//!
//! ## Phase 3: Opaque Predicate Removal
//!
//! Removes always-true/false conditions inserted by obfuscators.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`OpaquePredicatePass`] | Removes always-true/false conditions, simplifies comparisons |
//!
//! ## Phase 4: CFG Recovery
//!
//! Simplifies control flow after predicate removal.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`ControlFlowSimplificationPass`] | Jump threading, branch simplification, dead tail removal |
//! | [`LoopCanonicalizationPass`] | Ensures loops have single preheaders and latches |
//! | [`JumpThreadingPass`] | Threads jumps through empty blocks |
//!
//! ## Phase 5: Inlining
//!
//! Inlines small methods and proxy functions.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`InliningPass`] | Inlines small methods and constant-returning functions |
//!
//! ## Phase 6: Decryption
//!
//! Recovers encrypted constants and string literals.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DecryptionPass`] | Decrypts values via emulation of registered decryptor methods |
//!
//! ## Phase 7: VM Devirtualization
//!
//! Recovers code from virtual machine interpreters (not yet implemented).
//!
//! # Utility Passes
//!
//! These passes are available but not part of the standard pipeline:
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DeadMethodEliminationPass`] | Identifies and marks methods with no live callers |
//! | [`LicmPass`] | Loop-invariant code motion optimization |
//! | [`ValueRangePropagationPass`] | Propagates value range information |
//!
//! # Pass Execution
//!
//! Passes are executed by the [`PassScheduler`](crate::deobfuscation::PassScheduler)
//! phase by phase. Within each phase, passes run iteratively until no more changes
//! occur. Each pass implements the [`SsaPass`](crate::deobfuscation::SsaPass) trait.
//!
//! # Analysis Integration
//!
//! Many passes integrate with the analysis infrastructure:
//!
//! - **SCCP** ([`ConstantPropagation`](crate::analysis::ConstantPropagation)): Used by
//!   constant propagation and CFF reconstruction for precise value tracking
//! - **Loop Analysis** ([`LoopAnalyzer`](crate::analysis::LoopAnalyzer)): Used by
//!   loop canonicalization to identify and restructure loops
//! - **Symbolic Execution** ([`SymbolicEvaluator`](crate::analysis::SymbolicEvaluator)):
//!   Used by CFF reconstruction to build expression trees for Z3 solving
//! - **Emulation** ([`EmulationController`](crate::emulation::EmulationController)):
//!   Used by string decryption to execute decryptor methods

mod algebraic;
mod blockmerge;
mod constants;
mod controlflow;
mod copying;
mod deadcode;
mod decryption;
mod gvn;
mod inlining;
mod licm;
mod loopcanon;
mod native;
mod neutralize;
mod predicates;
mod ranges;
mod reassociate;
mod strength;
mod threading;
mod unflattening;
pub(crate) mod utils;

// Re-export passes for public API (may not be used internally but exposed for crate users)
pub use self::algebraic::AlgebraicSimplificationPass;
pub use self::blockmerge::BlockMergingPass;
pub use self::constants::ConstantPropagationPass;
pub use self::controlflow::ControlFlowSimplificationPass;
pub use self::copying::CopyPropagationPass;
pub use self::deadcode::{DeadCodeEliminationPass, DeadMethodEliminationPass};
pub use self::decryption::DecryptionPass;
pub use self::gvn::GlobalValueNumberingPass;
pub use self::inlining::InliningPass;
pub use self::licm::LicmPass;
pub use self::loopcanon::LoopCanonicalizationPass;
pub use self::native::{ConversionStats, NativeMethodConversionPass};
pub use self::neutralize::NeutralizationPass;
pub use self::predicates::{OpaquePredicatePass, PredicateResult};
pub use self::ranges::ValueRangePropagationPass;
pub use self::reassociate::ReassociationPass;
pub use self::strength::StrengthReductionPass;
pub use self::threading::JumpThreadingPass;
pub use self::unflattening::{
    trace_method_tree, CffReconstructionPass, TraceTree, UnflattenConfig,
};
