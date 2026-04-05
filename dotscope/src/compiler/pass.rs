//! Pass traits and infrastructure for the SSA optimization pipeline.
//!
//! This module defines the `SsaPass` trait that all SSA transformation passes implement,
//! along with the [`PassCapability`] enum used for capability-based pass scheduling.
//!
//! # Capability-Based Scheduling
//!
//! Passes can declare what they [`provides`](SsaPass::provides) and
//! [`requires`](SsaPass::requires) using [`PassCapability`] values. The scheduler
//! uses these declarations to build a dependency graph and topologically sort
//! passes into execution layers. Passes that don't declare capabilities fall back
//! to their assigned phase ordering.
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

/// Execution phase for an SSA pass.
///
/// Determines when in the pipeline a pass runs. The scheduler groups passes
/// by phase and executes them in layer order: `Structure` → `Value` →
/// `Simplify` → `Inline`. `Normalize` passes run between every layer's
/// fixpoint iterations rather than as a layer themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassPhase {
    /// Structural transformations (e.g., control flow unflattening).
    Structure,
    /// Value-level transformations (e.g., constant decryption, string decryption).
    Value,
    /// Simplification passes (e.g., proxy resolution, anti-debug neutralization).
    Simplify,
    /// Inlining passes (e.g., delegate inlining).
    Inline,
    /// Normalization passes (e.g., nop removal, dead code elimination).
    Normalize,
}

impl PassPhase {
    /// Returns the fallback scheduler layer for this phase.
    ///
    /// Convention: Structure=0, Value=1, Simplify=2, Inline=3.
    /// Normalize passes don't participate in layered scheduling.
    #[must_use]
    pub fn as_layer(self) -> usize {
        match self {
            Self::Structure => 0,
            Self::Value => 1,
            Self::Simplify => 2,
            Self::Inline => 3,
            Self::Normalize => 0,
        }
    }
}

/// Capability that a pass can provide or require.
///
/// The scheduler uses these to build a dependency graph: if pass A provides
/// `ResolvedStaticFields` and pass B requires it, A is scheduled before B.
/// Passes that don't declare any capabilities fall back to phase-based ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassCapability {
    /// Static field values have been resolved to concrete constants.
    ResolvedStaticFields,
    /// Encrypted strings have been decrypted.
    DecryptedStrings,
    /// Control flow flattening has been reversed.
    RestoredControlFlow,
    /// Opaque predicates have been simplified/removed.
    SimplifiedPredicates,
    /// Proxy/delegate calls have been devirtualized.
    DevirtualizedCalls,
    /// Small methods have been inlined at call sites.
    InlinedMethods,
}

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

    /// Capabilities this pass provides after successful execution.
    ///
    /// The scheduler uses this to determine which passes can run after this one.
    /// Passes that don't override this return an empty slice and are scheduled
    /// based on their fallback phase.
    fn provides(&self) -> &[PassCapability] {
        &[]
    }

    /// Capabilities this pass requires before it can run.
    ///
    /// The scheduler ensures all providers of required capabilities are
    /// scheduled in earlier layers. If no provider is registered for a
    /// required capability, the requirement is ignored (allows the pass
    /// to run at its fallback layer).
    fn requires(&self) -> &[PassCapability] {
        &[]
    }

    /// Whether this pass requires a full scan of all methods every iteration.
    ///
    /// If `true`, the scheduler calls `run_on_method` for every method with SSA,
    /// regardless of dirty tracking state. If `false` (default), the scheduler
    /// only processes methods in the dirty set.
    ///
    /// Most passes operate on individual methods independently and should use
    /// the default. Only passes that read other methods' SSA or need whole-program
    /// visibility should return `true`.
    fn requires_full_scan(&self) -> bool {
        false
    }
}
