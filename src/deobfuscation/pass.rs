//! Pass traits and infrastructure for the deobfuscation pipeline.
//!
//! This module defines the `SsaPass` trait that all deobfuscation passes implement.
//! Passes are organized into a fixed pipeline following the canonical 8-phase
//! deobfuscation sequence used by state-of-the-art tools.

use std::sync::Arc;

use crate::{
    analysis::SsaFunction, deobfuscation::context::AnalysisContext, metadata::token::Token,
    CilObject, Result,
};

/// A deobfuscation pass that operates on SSA form.
///
/// All passes must be thread-safe (Send + Sync) to allow parallel execution.
/// Passes receive mutable access to the SSA function and shared access to
/// the analysis context.
///
/// # Pipeline Integration
///
/// Passes don't declare their own priority or triggers. Instead, the scheduler
/// runs passes in a fixed pipeline order based on the canonical deobfuscation
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
    fn should_run(&self, _method_token: Token, _ctx: &AnalysisContext) -> bool {
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
    /// * `ctx` - The analysis context (thread-safe, uses shared reference).
    /// * `assembly` - Shared reference to the assembly (for emulation, lookups, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the pass fails to process the method.
    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &AnalysisContext,
        assembly: &Arc<CilObject>,
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
    /// * `ctx` - The analysis context (thread-safe, uses shared reference).
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Errors
    ///
    /// Returns an error if the pass fails to process the assembly.
    fn run_global(&self, _ctx: &AnalysisContext, _assembly: &Arc<CilObject>) -> Result<bool> {
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
    fn initialize(&mut self, _ctx: &AnalysisContext) -> Result<()> {
        Ok(())
    }

    /// Called once after the pass completes in a phase.
    ///
    /// Use this to clean up pass-specific state.
    ///
    /// # Errors
    ///
    /// Returns an error if finalization fails.
    fn finalize(&mut self, _ctx: &AnalysisContext) -> Result<()> {
        Ok(())
    }

    /// Get a description of what this pass does.
    fn description(&self) -> &'static str {
        "No description available"
    }
}
