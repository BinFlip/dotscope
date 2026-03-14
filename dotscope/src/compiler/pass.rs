//! Pass traits and infrastructure for the SSA optimization pipeline.
//!
//! This module defines the `SsaPass` trait that all SSA transformation passes implement.
//! Passes are organized into a fixed pipeline following a canonical multi-phase
//! optimization sequence.
//!
//! # Modification Scope
//!
//! Each pass declares a [`ModificationScope`] that describes the extent of its
//! modifications to the SSA function. The scheduler uses this to select the
//! appropriate repair strategy after each pass:
//!
//! - [`ModificationScope::UsesOnly`] — No repair needed (SSA invariants preserved)
//! - [`ModificationScope::InstructionsOnly`] — Lightweight repair (recompute def-use, clean up)
//! - [`ModificationScope::CfgModifying`] — Full `rebuild_ssa()` (recompute dominators, phis, etc.)

use crate::{
    analysis::SsaFunction, compiler::CompilerContext, metadata::token::Token, CilObject, Result,
};

/// Describes the extent of modifications a pass makes to the SSA function.
///
/// The scheduler uses this to select the minimum repair necessary after a pass
/// runs, avoiding expensive full SSA reconstruction when it isn't needed.
///
/// Passes should declare the **tightest** scope that covers all their
/// modifications. For example, a pass that only forwards uses should declare
/// `UsesOnly`, not `CfgModifying`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModificationScope {
    /// The pass only replaces uses of variables with other existing variables.
    ///
    /// Examples: GVN (forwarding redundant uses to earlier definitions).
    ///
    /// SSA invariants are preserved automatically — no repair needed.
    /// The pass does not create new variables, does not change instruction
    /// opcodes (except possibly Nop-ing dead copies as a side effect),
    /// and does not modify the CFG.
    UsesOnly,

    /// The pass replaces or removes instructions but does not change the CFG.
    ///
    /// Examples: constant propagation (replacing ops with Const), copy
    /// propagation (Nop-ing propagated copies), DCE (Nop-ing dead
    /// instructions), algebraic simplification, strength reduction.
    ///
    /// After this scope, a lightweight repair is needed to:
    /// - Strip Nop instructions and reindex DefSites
    /// - Recompute variable metadata from surviving instructions
    /// - Eliminate trivial phis and compact variables
    ///
    /// No dominator/dominance frontier recomputation is needed since
    /// the CFG structure is unchanged.
    InstructionsOnly,

    /// The pass may add or remove blocks, change successors/predecessors,
    /// or otherwise modify control flow.
    ///
    /// Examples: control-flow unflattening, jump threading, block merging,
    /// loop canonicalization, inlining.
    ///
    /// After this scope, a full `rebuild_ssa()` is required to restore
    /// SSA invariants (recompute dominators, place phis, rename variables).
    CfgModifying,
}

/// An SSA transformation pass that operates on SSA form.
///
/// All passes must be thread-safe (Send + Sync) to allow parallel execution.
/// Passes receive mutable access to the SSA function and shared access to
/// the analysis context.
///
/// # Pipeline Integration
///
/// Passes don't declare their own priority or triggers. Instead, the scheduler
/// runs passes in a fixed pipeline order based on a canonical optimization
/// sequence:
///
/// 1. **Normalize**: ADCE, GVN, constant folding (loop until stable)
/// 2. **Opaque predicates**: Range analysis, predicate removal
/// 3. **CFG recovery**: Structuring, loop identification
/// 4. **Unflattening**: Control-flow unflattening
/// 5. **Proxy inlining**: Delegate/proxy method inlining
/// 6. **Decryption**: String and constant decryption
/// 7. **Devirtualization**: VM handler recovery (if present)
/// 8. **Cleanup**: Final DCE, GVN, small function inlining
///
/// # Assembly Access
///
/// Passes that need access to the assembly (e.g., for emulation) receive it
/// as a parameter. The assembly flows linearly through the pipeline with clear
/// ownership semantics - it is NOT stored in the context.
pub trait SsaPass: Send + Sync {
    /// Unique name for logging and debugging.
    fn name(&self) -> &'static str;

    /// Should this pass run on a specific method?
    ///
    /// Called before `run_on_method`. Override to skip methods that
    /// don't need this pass (e.g., already processed, too simple).
    ///
    /// NOTE: Dead method skipping is NOT done here. Dead method detection
    /// can be inaccurate for obfuscated code (e.g., CFF hides call sites).
    /// All methods with SSA are processed; dead method filtering is handled
    /// during code generation.
    fn should_run(&self, _method_token: Token, _ctx: &CompilerContext) -> bool {
        true
    }

    /// Run the pass on a single method's SSA.
    ///
    /// This is the main entry point for per-method passes.
    /// Returns `true` if any changes were made, `false` otherwise.
    /// Events should be recorded directly to `ctx.events`.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to transform.
    /// * `method_token` - The metadata token of the method.
    /// * `ctx` - The compiler context (thread-safe, uses shared reference).
    /// * `assembly` - Shared reference to the assembly (for emulation, lookups, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the pass fails to process the method.
    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool>;

    /// Run on the entire assembly (for interprocedural passes).
    ///
    /// Override this for passes that need to see all methods at once,
    /// like dead method detection or whole-program constant propagation.
    /// Returns `true` if any changes were made, `false` otherwise.
    /// Events should be recorded directly to `ctx.events`.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context (thread-safe, uses shared reference).
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Errors
    ///
    /// Returns an error if the pass fails to process the assembly.
    fn run_global(&self, _ctx: &CompilerContext, _assembly: &CilObject) -> Result<bool> {
        Ok(false)
    }

    /// Does this pass operate globally (across all methods)?
    ///
    /// Global passes have their `run_global` called instead of
    /// iterating over methods with `run_on_method`.
    fn is_global(&self) -> bool {
        false
    }

    /// Called once before the pass runs in a phase.
    ///
    /// Use this to initialize pass-specific state or caches.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    fn initialize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        Ok(())
    }

    /// Called once after the pass completes in a phase.
    ///
    /// Use this to clean up pass-specific state.
    ///
    /// # Errors
    ///
    /// Returns an error if finalization fails.
    fn finalize(&mut self, _ctx: &CompilerContext) -> Result<()> {
        Ok(())
    }

    /// Declares the extent of modifications this pass makes to the SSA function.
    ///
    /// The scheduler uses this to select the appropriate repair strategy:
    ///
    /// - [`ModificationScope::UsesOnly`] — No repair needed
    /// - [`ModificationScope::InstructionsOnly`] — Lightweight [`SsaFunction::repair_ssa`]
    /// - [`ModificationScope::CfgModifying`] — Full [`SsaFunction::rebuild_ssa`]
    ///
    /// The default is `CfgModifying` (conservative). Override this to declare
    /// a tighter scope for passes that don't modify the CFG.
    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::CfgModifying
    }

    /// Get a description of what this pass does.
    fn description(&self) -> &'static str {
        "No description available"
    }
}
