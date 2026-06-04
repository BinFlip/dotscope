//! Copy propagation pass — thin wrapper.
//!
//! Pure-SSA transformation logic lives in [`analyssa::passes::copying`]. This
//! file contributes:
//!
//! 1. The [`SsaPass`] trait impl that the dotscope scheduler consumes.
//! 2. `propagate_local_types` — the CIL-side post-step that runs once per
//!    iteration and propagates `SsaType` from local-origin destinations to
//!    their ultimate sources. It uses `ssa.original_local_types()` (CIL
//!    signature data) and `SsaType::from_type_signature(..., assembly)`,
//!    so it cannot move into analyssa.

use std::collections::BTreeMap;

use analyssa::passes::copying;

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction, SsaType, SsaVarId, VariableOrigin},
    compiler::{
        pass::{ModificationScope, SsaPass},
        CompilerContext,
    },
    CilObject,
};

/// Copy propagation pass.
///
/// Tracks copy operations and propagates the source to all uses of the
/// copy. Uses an iterative fixed-point algorithm to handle cascading copies
/// and newly exposed opportunities after each round of propagation.
pub struct CopyPropagationPass {
    /// Maximum fixpoint iterations before stopping.
    max_iterations: usize,
}

impl CopyPropagationPass {
    /// Creates a new copy propagation pass.
    ///
    /// `max_iterations` caps the inner fixpoint loop. Copy chains converge
    /// in ~3 iterations; the default config value is 15.
    #[must_use]
    pub fn new(max_iterations: usize) -> Self {
        Self { max_iterations }
    }
}

impl SsaPass<CilTarget, CompilerContext> for CopyPropagationPass {
    fn name(&self) -> &'static str {
        "copy-propagation"
    }

    fn description(&self) -> &'static str {
        "Propagates copy operations, replacing uses with original sources"
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
        let assembly = host
            .assembly()
            .ok_or_else(|| analyssa::Error::new("CopyPropagationPass requires an assembly"))?;
        let changed = copying::run_with_hook(
            ssa,
            method,
            &host.events,
            self.max_iterations,
            |ssa, resolved| propagate_local_types(ssa, resolved, &assembly),
        );
        Ok(changed)
    }
}

/// CIL-side post-step: propagates types from Local-origin destinations to
/// their ultimate sources.
///
/// When a Local-origin variable is a copy destination (e.g.
/// `local_0 = copy phi_result`), the source variable should inherit the
/// local's original type. This ensures that after copy propagation
/// eliminates the intermediate copy, the source retains the correct type
/// information for code generation.
///
/// Mirrors the .NET JIT's approach of keeping local slot types (`lvType`)
/// separate from IR/computational types (`gtType`).
fn propagate_local_types(
    ssa: &mut SsaFunction,
    resolved: &BTreeMap<SsaVarId, SsaVarId>,
    assembly: &CilObject,
) {
    let original_types = match ssa.original_local_types() {
        Some(types) => types.to_vec(),
        None => return,
    };

    let mut type_assignments: Vec<(SsaVarId, SsaType)> = Vec::new();

    for (dest, src) in resolved {
        if dest == src {
            continue;
        }

        let Some(dest_var) = ssa.variable(*dest) else {
            continue;
        };
        let VariableOrigin::Local(local_idx) = dest_var.origin() else {
            continue;
        };

        let local_type = match original_types.get(local_idx as usize) {
            Some(sig) => &sig.base,
            None => continue,
        };

        let ssa_type = SsaType::from_type_signature(local_type, assembly);

        if ssa_type.is_unknown() || matches!(ssa_type, SsaType::I32) {
            continue;
        }

        let should_propagate = match ssa.variable(*src) {
            Some(src_var) => src_var.var_type().is_unknown(),
            None => false,
        };

        if should_propagate {
            type_assignments.push((*src, ssa_type));
        }
    }

    for (var_id, ssa_type) in type_assignments {
        if let Some(var) = ssa.variable_mut(var_id) {
            var.set_type(ssa_type);
        }
    }
}
