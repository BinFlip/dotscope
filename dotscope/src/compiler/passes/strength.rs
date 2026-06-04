//! Strength reduction pass — thin wrapper.
//!
//! Transformation logic lives in [`analyssa::passes::strength`]. The wrapper
//! supplies the host-side "is this variable provably non-negative?"
//! predicate — looked up via `CompilerContext::with_known_range` against
//! the range-analysis cache.

use analyssa::passes::strength;

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction, ValueRange},
    compiler::{
        pass::{ModificationScope, SsaPass},
        CompilerContext,
    },
};

/// Strength reduction pass that transforms expensive operations to cheaper
/// equivalents.
pub struct StrengthReductionPass;

impl Default for StrengthReductionPass {
    fn default() -> Self {
        Self::new()
    }
}

impl StrengthReductionPass {
    /// Creates a new strength reduction pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SsaPass<CilTarget, CompilerContext> for StrengthReductionPass {
    fn name(&self) -> &'static str {
        "strength-reduction"
    }

    fn description(&self) -> &'static str {
        "Transform expensive operations (mul/div/rem) to cheaper equivalents (shl/shr/and)"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let token = method.0;
        let is_non_negative = |var| {
            host.with_known_range(token, var, ValueRange::is_always_non_negative)
                .unwrap_or(false)
        };
        Ok(strength::run(ssa, method, &host.events, &is_non_negative))
    }
}
