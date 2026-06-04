//! CIL-side pass scheduler — thin wrapper around
//! [`analyssa::scheduling::PassScheduler`].
//!
//! All scheduling logic (capability layer assignment, fixpoint
//! iteration, parallel per-method dispatch, modification-scope-driven
//! repair) lives in analyssa. This module provides a CIL-flavored facade
//! that:
//!
//! - Maps [`PassPhase`] enum values to fallback layer numbers.
//! - Sets the assembly handle on the context before invoking the
//!   underlying scheduler.
//! - Bridges error types between analyssa and dotscope.
//!
//! Hosts targeting other ISAs use analyssa's scheduler directly.

use std::sync::Arc;

use analyssa::scheduling::{PassScheduler as AnalyssaPassScheduler, PipelineConfig};

use crate::{
    analysis::CilTarget,
    compiler::{
        context::CompilerContext,
        pass::{PassPhase, SsaPass},
        state::ProcessingState,
    },
    CilObject, Error, Result,
};

/// Orchestrates CIL SSA pass execution.
///
/// Wraps [`analyssa::scheduling::PassScheduler<CilTarget, CompilerContext>`]
/// with CIL-specific phase mapping. Passes are added with a
/// [`PassPhase`]; layered passes go through capability-based scheduling
/// in analyssa, normalize passes interleave between layer fixpoint
/// iterations.
///
/// # Example
///
/// ```rust,ignore
/// let mut scheduler = PassScheduler::new(5, 2, 15);
/// scheduler.add(Box::new(value_pass), PassPhase::Value);
/// scheduler.add(Box::new(cff_pass), PassPhase::Structure);
/// scheduler.add(Box::new(dce_pass), PassPhase::Normalize);
/// scheduler.run_pipeline(&ctx, &assembly, None)?;
/// ```
pub struct PassScheduler {
    inner: AnalyssaPassScheduler<CilTarget, CompilerContext>,
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
    /// * `stable_iterations` - Stop early if no changes for this many consecutive iterations.
    /// * `max_phase_iterations` - Maximum fixpoint iterations for a single layer before
    ///   moving to the next.
    #[must_use]
    pub fn new(
        max_iterations: usize,
        stable_iterations: usize,
        max_phase_iterations: usize,
    ) -> Self {
        // dotscope populates the scheduler with its own CIL passes (gated by
        // engine config), so start from an empty analyssa scheduler rather
        // than the default built-in pipeline. Only the iteration limits and
        // `verify_hard` flag are consumed by `empty`; the remaining
        // `PipelineConfig` fields tune analyssa's built-in passes, which we
        // do not register here.
        let config = PipelineConfig {
            max_iterations,
            stable_iterations,
            max_phase_iterations,
            ..PipelineConfig::default()
        };
        Self {
            inner: AnalyssaPassScheduler::empty(config),
        }
    }

    /// Returns the number of non-normalize passes registered.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.inner.pass_count()
    }

    /// Returns the number of normalization passes registered.
    #[must_use]
    pub fn normalize_count(&self) -> usize {
        self.inner.normalize_count()
    }

    /// Adds a pass to the scheduler with its execution phase.
    ///
    /// `Normalize` passes go to the analyssa normalize-pass list (run
    /// between every layer's fixpoint iterations). All other phases map
    /// to their numeric fallback layer via [`PassPhase::as_layer`].
    pub fn add(&mut self, pass: Box<dyn SsaPass<CilTarget, CompilerContext>>, phase: PassPhase) {
        match phase {
            PassPhase::Normalize => self.inner.add_normalize(pass),
            other => self.inner.add_at_layer(pass, other.as_layer()),
        }
    }

    /// Runs the complete deobfuscation pipeline.
    ///
    /// `assembly` is stored on `ctx` via [`CompilerContext::set_assembly`]
    /// so passes that need it (inlining, proxy devirt, constant folding)
    /// can reach it through the host. `state` is currently a no-op
    /// parameter retained for source-compatibility; dirty tracking
    /// flows through `ctx.processing_state`.
    ///
    /// # Errors
    ///
    /// Returns an error if a cycle is detected in the capability
    /// dependency graph or any pass fails.
    pub fn run_pipeline(
        &mut self,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
        _state: Option<&ProcessingState>,
    ) -> Result<usize> {
        ctx.set_assembly(assembly.clone());
        let result = self
            .inner
            .run_pipeline(ctx)
            .map_err(|e| Error::SsaError(e.0));
        // Release the in-context assembly handle so callers can unwrap
        // the `Arc<CilObject>` for code generation. Without this, the
        // strong-count never drops to one and `Arc::try_unwrap` fails.
        ctx.clear_assembly();
        result
    }
}
