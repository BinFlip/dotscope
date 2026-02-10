//! Pass scheduler for orchestrating SSA pass execution.
//!
//! The `PassScheduler` manages the execution of SSA optimization passes using
//! a 4-phase pipeline, each phase runs to fixpoint with normalization after
//! each structural change.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use rayon::prelude::*;

use crate::{
    compiler::{context::CompilerContext, pass::SsaPass},
    CilObject, Result,
};

/// Orchestrates SSA pass execution in a phased pipeline.
///
/// The scheduler runs passes in a 4-phase pipeline:
///
/// 1. **Structure Recovery**: Control-flow unflattening + normalize
/// 2. **Value Recovery**: String/constant decryption + normalize
/// 3. **Simplification**: Opaque predicates, CFG recovery, jump threading + normalize
/// 4. **Inlining**: Proxy/delegate method inlining + normalize
///
/// Each phase runs to fixpoint (until no more changes) before proceeding.
/// The entire pipeline is then repeated until global fixpoint or max iterations.
#[allow(clippy::struct_field_names)]
pub struct PassScheduler {
    /// Maximum iterations for the entire pipeline.
    max_iterations: usize,
    /// Number of stable iterations before stopping.
    stable_iterations: usize,
    /// Maximum iterations for a single phase before moving on.
    max_phase_iterations: usize,
    /// Phase 1: Structure recovery (e.g., control-flow unflattening).
    pub structure: Vec<Box<dyn SsaPass>>,
    /// Phase 2: Value recovery (e.g., string/constant decryption).
    pub value: Vec<Box<dyn SsaPass>>,
    /// Phase 3: Simplification (e.g., opaque predicates, CFG recovery).
    pub simplify: Vec<Box<dyn SsaPass>>,
    /// Phase 4: Inlining (e.g., proxy/delegate inlining).
    pub inline: Vec<Box<dyn SsaPass>>,
    /// Normalization passes (DCE, GVN, const/copy propagation).
    /// Run after each phase to clean up before the next.
    pub normalize: Vec<Box<dyn SsaPass>>,
}

impl Default for PassScheduler {
    fn default() -> Self {
        Self::new(5, 2, 15)
    }
}

impl PassScheduler {
    /// Creates a new scheduler with the specified iteration limits.
    ///
    /// # Arguments
    ///
    /// * `max_iterations` - Maximum iterations for the entire pipeline before stopping.
    /// * `stable_iterations` - Stop early if no changes for this many iterations.
    /// * `max_phase_iterations` - Maximum iterations for a single phase before moving on.
    ///
    /// # Returns
    ///
    /// A new `PassScheduler`.
    #[must_use]
    pub fn new(
        max_iterations: usize,
        stable_iterations: usize,
        max_phase_iterations: usize,
    ) -> Self {
        Self {
            max_iterations,
            stable_iterations,
            max_phase_iterations,
            structure: Vec::new(),
            value: Vec::new(),
            simplify: Vec::new(),
            inline: Vec::new(),
            normalize: Vec::new(),
        }
    }

    /// Runs normalization passes until no more changes occur.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context.
    /// * `passes` - The passes to run in this phase.
    /// * `max_phase_iterations` - Maximum iterations before stopping.
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Returns
    ///
    /// `true` if any changes were made during this phase, `false` otherwise.
    fn normalize_to_fixpoint(
        ctx: &CompilerContext,
        passes: &mut [Box<dyn SsaPass>],
        max_phase_iterations: usize,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut any_changed = false;

        for _ in 0..max_phase_iterations {
            let changed = Self::run_passes_once(ctx, passes, assembly)?;

            if !changed {
                break;
            }

            any_changed = true;
        }

        Ok(any_changed)
    }

    /// Runs a phase to fixpoint: execute phase passes, then normalize until stable.
    ///
    /// Each phase:
    /// 1. Runs its specific passes (e.g., unflattening)
    /// 2. Normalizes the result (DCE, constant prop, etc.)
    /// 3. Repeats until no more changes
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context.
    /// * `phase_passes` - The main passes for this phase.
    /// * `normalize_passes` - Normalization passes to run after each change.
    /// * `max_phase_iterations` - Maximum iterations before stopping.
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Returns
    ///
    /// `true` if any changes were made during this phase, `false` otherwise.
    fn phase_to_fixpoint(
        ctx: &CompilerContext,
        phase_passes: &mut [Box<dyn SsaPass>],
        normalize_passes: &mut [Box<dyn SsaPass>],
        max_phase_iterations: usize,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        if phase_passes.is_empty() {
            return Ok(false);
        }

        let mut phase_changed = false;

        for _ in 0..max_phase_iterations {
            let pass_changed = Self::run_passes_once(ctx, phase_passes, assembly)?;
            if !pass_changed {
                break;
            }

            phase_changed = true;

            // Normalize after each successful phase pass to clean up
            // This is critical: normalization can expose new opportunities
            // for the phase passes on the next iteration
            if !normalize_passes.is_empty() {
                Self::normalize_to_fixpoint(ctx, normalize_passes, max_phase_iterations, assembly)?;
            }
        }

        Ok(phase_changed)
    }

    /// Runs all passes once over all methods.
    ///
    /// Returns `true` if any pass made changes, `false` otherwise.
    ///
    /// Per-method passes are executed in parallel using rayon. Each method's SSA
    /// is processed independently, leveraging the thread-safe CompilerContext.
    fn run_passes_once(
        ctx: &CompilerContext,
        passes: &mut [Box<dyn SsaPass>],
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let any_changed = AtomicBool::new(false);

        // Initialize passes
        for pass in passes.iter_mut() {
            pass.initialize(ctx)?;
        }

        // Run global passes first (sequential - they need to see all methods)
        for pass in passes.iter() {
            if pass.is_global() && pass.run_global(ctx, assembly)? {
                any_changed.store(true, Ordering::Relaxed);
            }
        }

        // Get method order (callees before callers for better propagation)
        let method_order: Vec<_> = {
            let topo = ctx.methods_reverse_topological();
            if topo.is_empty() {
                ctx.all_methods().collect()
            } else {
                topo
            }
        };

        // Filter to methods that have SSA
        let methods_with_ssa: Vec<_> = method_order
            .into_iter()
            .filter(|token| ctx.ssa_functions.contains_key(token))
            .collect();

        // Run per-method passes
        // NOTE: We process ALL methods with SSA, including those previously
        // marked as "dead". Dead method detection can be inaccurate for
        // obfuscated code (e.g., CFF hides call sites from the call graph).
        for pass in passes.iter() {
            if pass.is_global() {
                continue;
            }

            // Process methods in parallel for this pass
            methods_with_ssa.par_iter().for_each(|&method_token| {
                if !pass.should_run(method_token, ctx) {
                    return;
                }

                // Remove SSA (brief lock, then released)
                let Some((_, mut ssa)) = ctx.ssa_functions.remove(&method_token) else {
                    return;
                };

                // Run the pass with no locks held
                let result = pass.run_on_method(&mut ssa, method_token, ctx, assembly);

                // If pass made changes, rebuild SSA to ensure valid state.
                // This cleans up orphan Pop instructions and fixes def-use chains.
                // rebuild_ssa also eliminates trivial PHIs to prevent oscillation.
                if let Ok(true) = result {
                    ssa.rebuild_ssa();
                }

                // Reinsert SSA (brief lock, then released)
                ctx.ssa_functions.insert(method_token, ssa);

                // Track if changes were made and mark method for code regeneration
                if let Ok(true) = result {
                    any_changed.store(true, Ordering::Relaxed);
                    // Only mark methods as processed (needing code regeneration) if they
                    // actually had changes. This preserves original method bodies for
                    // methods that don't need modification.
                    ctx.processed_methods.insert(method_token);
                }
            });
        }

        // Finalize passes
        for pass in passes.iter_mut() {
            pass.finalize(ctx)?;
        }

        Ok(any_changed.load(Ordering::Relaxed))
    }

    /// Runs the complete deobfuscation pipeline.
    ///
    /// Executes a 4-phase pipeline where each phase runs to fixpoint:
    ///
    /// 1. **Structure Recovery**: Unflattening + normalize
    /// 2. **Value Recovery**: Decryption + normalize
    /// 3. **Simplification**: Opaque predicates + CFG + normalize
    /// 4. **Inlining**: Proxy inlining + normalize
    ///
    /// The entire pipeline repeats until no phase makes changes or max iterations.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The compiler context.
    /// * `assembly` - Shared reference to the assembly.
    ///
    /// # Returns
    ///
    /// The number of iterations completed. Events are accumulated in `ctx.events`.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass fails during execution.
    pub fn run_pipeline(
        &mut self,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<usize> {
        let mut stable_count = 0;
        let mut iterations = 0;
        let max_phase = self.max_phase_iterations;
        let max_iterations = self.max_iterations;
        let stable_iterations = self.stable_iterations;

        for iteration in 0..max_iterations {
            iterations = iteration + 1;
            let mut iteration_changed = false;

            // Phase 1: Structure Recovery (unflattening)
            // Run to fixpoint with normalize after each change
            if Self::phase_to_fixpoint(
                ctx,
                &mut self.structure,
                &mut self.normalize,
                max_phase,
                assembly,
            )? {
                iteration_changed = true;
            }

            // Phase 2: Value Recovery (decryption)
            // Run to fixpoint with normalize after each change
            if Self::phase_to_fixpoint(
                ctx,
                &mut self.value,
                &mut self.normalize,
                max_phase,
                assembly,
            )? {
                iteration_changed = true;
            }

            // Phase 3: Simplification (opaque predicates, CFG recovery)
            // Run to fixpoint with normalize after each change
            if Self::phase_to_fixpoint(
                ctx,
                &mut self.simplify,
                &mut self.normalize,
                max_phase,
                assembly,
            )? {
                iteration_changed = true;
            }

            // Phase 4: Inlining (proxy/delegate inlining)
            // Run to fixpoint with normalize after each change
            if Self::phase_to_fixpoint(
                ctx,
                &mut self.inline,
                &mut self.normalize,
                max_phase,
                assembly,
            )? {
                iteration_changed = true;
            }

            // This ensures DCE, const prop, etc. run even if phase passes don't make changes
            if iteration == 0 && !iteration_changed && !self.normalize.is_empty() {
                iteration_changed =
                    Self::normalize_to_fixpoint(ctx, &mut self.normalize, max_phase, assembly)?;
            }

            // Check for global fixpoint
            if iteration_changed {
                stable_count = 0;
            } else {
                stable_count += 1;
                if stable_count >= stable_iterations {
                    break;
                }
            }
        }

        Ok(iterations)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::SsaFunction,
        compiler::{context::CompilerContext, pass::SsaPass, EventKind, PassScheduler},
        metadata::token::Token,
        CilObject, Result,
    };

    struct TestPass {
        name: &'static str,
        changes_to_make: usize,
    }

    impl TestPass {
        fn new(name: &'static str, changes: usize) -> Self {
            Self {
                name,
                changes_to_make: changes,
            }
        }
    }

    impl SsaPass for TestPass {
        fn name(&self) -> &'static str {
            self.name
        }

        fn run_on_method(
            &self,
            _ssa: &mut SsaFunction,
            method_token: Token,
            ctx: &CompilerContext,
            _assembly: &Arc<CilObject>,
        ) -> Result<bool> {
            for i in 0..self.changes_to_make {
                ctx.events
                    .record(EventKind::ConstantFolded)
                    .at(method_token, i)
                    .message("test");
            }
            Ok(self.changes_to_make > 0)
        }
    }

    #[test]
    fn test_scheduler_iteration_limits() {
        let scheduler = PassScheduler::new(10, 3, 5);
        assert_eq!(scheduler.max_iterations, 10);
        assert_eq!(scheduler.stable_iterations, 3);
        assert_eq!(scheduler.max_phase_iterations, 5);
    }

    #[test]
    fn test_default_scheduler() {
        let scheduler = PassScheduler::default();
        // Now uses reduced iterations since phases run to fixpoint
        assert_eq!(scheduler.max_iterations, 5);
        assert_eq!(scheduler.stable_iterations, 2);
        assert_eq!(scheduler.max_phase_iterations, 15);
    }

    #[test]
    fn test_pass_names() {
        let passes: Vec<Box<dyn SsaPass>> = vec![
            Box::new(TestPass::new("pass1", 0)),
            Box::new(TestPass::new("pass2", 0)),
        ];

        assert_eq!(passes.len(), 2);
        assert_eq!(passes[0].name(), "pass1");
        assert_eq!(passes[1].name(), "pass2");
    }
}
