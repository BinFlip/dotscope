//! Unified constant resolution for SSA variables.
//!
//! The [`ValueResolver`] composes [`ConstEvaluator`], [`PhiAnalyzer`], and optionally
//! [`SsaEvaluator`] into a single reusable entry point for demand-driven constant
//! resolution. It replaces ad-hoc tracing logic (like the former `trace_to_constant`)
//! with a three-tier fallback strategy:
//!
//! 1. **ConstEvaluator** — handles all instruction-defined ops (arithmetic, bitwise,
//!    comparisons, conversions) with caching and cycle detection.
//! 2. **PhiAnalyzer** — checks whether all PHI operands resolve to the same constant.
//! 3. **SsaEvaluator** (path-aware fallback) — uses `resolve_with_trace` for
//!    instruction-defined vars that `ConstEvaluator` couldn't fold (e.g., XOR with
//!    a Call operand).
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{ValueResolver, SsaFunction};
//! use dotscope::metadata::typesystem::PointerSize;
//!
//! let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64)
//!     .with_path_aware_fallback();
//! resolver.load_known_values(ctx, method_token);
//!
//! if let Some(value) = resolver.resolve(some_var) {
//!     println!("Resolved to: {:?}", value);
//! }
//! ```

use crate::{
    analysis::ssa::{ConstEvaluator, ConstValue, PhiAnalyzer, SsaEvaluator, SsaFunction, SsaVarId},
    compiler::CompilerContext,
    metadata::{token::Token, typesystem::PointerSize},
};

/// Demand-driven constant resolver composing multiple analysis components.
///
/// Provides a unified API for resolving SSA variables to constant values,
/// combining the strengths of [`ConstEvaluator`] (instruction folding),
/// [`PhiAnalyzer`] (uniform PHI detection), and optionally [`SsaEvaluator`]
/// (path-aware tracing for variables that pure constant folding can't handle).
pub struct ValueResolver<'a> {
    ssa: &'a SsaFunction,
    evaluator: ConstEvaluator<'a>,
    phi: PhiAnalyzer<'a>,
    resolve_phis: bool,
    path_aware_fallback: bool,
    ptr_size: PointerSize,
}

impl<'a> ValueResolver<'a> {
    /// Creates a new resolver with PHI resolution enabled and path-aware fallback disabled.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction, ptr_size: PointerSize) -> Self {
        Self {
            ssa,
            evaluator: ConstEvaluator::new(ssa, ptr_size),
            phi: PhiAnalyzer::new(ssa),
            resolve_phis: true,
            path_aware_fallback: false,
            ptr_size,
        }
    }

    /// Enables the path-aware fallback via [`SsaEvaluator`].
    ///
    /// When enabled, variables that `ConstEvaluator` can't fold (e.g., XOR where
    /// one operand comes from a Call) will be attempted via `resolve_with_trace`.
    #[must_use]
    pub fn with_path_aware_fallback(mut self) -> Self {
        self.path_aware_fallback = true;
        self
    }

    /// Bulk-injects all known values for a method from the [`CompilerContext`].
    ///
    /// This loads values discovered by earlier passes (e.g., constant propagation)
    /// into the inner [`ConstEvaluator`] so they're available during resolution.
    pub fn load_known_values(&mut self, ctx: &CompilerContext, method_token: Token) {
        ctx.for_each_known_value(method_token, |var, val| {
            self.evaluator.set_known(var, val.clone());
        });
    }

    /// Injects a single known value into the resolver.
    pub fn set_known(&mut self, var: SsaVarId, value: ConstValue) {
        self.evaluator.set_known(var, value);
    }

    /// Resolves a variable to a constant using a three-tier fallback strategy.
    ///
    /// 1. Try [`ConstEvaluator`] (all instruction-defined ops).
    /// 2. If PHI-defined, check for uniform constant via [`PhiAnalyzer`].
    /// 3. If path-aware fallback is enabled, try [`SsaEvaluator::resolve_with_trace`].
    pub fn resolve(&mut self, var: SsaVarId) -> Option<ConstValue> {
        // 1. Try ConstEvaluator (handles Const, arithmetic, bitwise, etc. with caching)
        if let Some(val) = self.evaluator.evaluate_var(var) {
            return Some(val);
        }

        // 2. PHI uniform constant check
        if self.resolve_phis {
            if let Some((_, phi)) = self.ssa.find_phi_defining(var) {
                let result = self.phi.uniform_constant(phi, &mut self.evaluator);
                if result.is_some() {
                    return result;
                }
            }
        }

        // 3. Path-aware fallback via SsaEvaluator (for instruction-defined vars
        //    that ConstEvaluator couldn't fold, e.g. XOR with a Call operand)
        if self.path_aware_fallback && self.ssa.get_definition(var).is_some() {
            let mut eval = SsaEvaluator::new(self.ssa, self.ptr_size);
            if let Some(resolved) = eval.resolve_with_trace(var, 15) {
                if let Some(c) = resolved.as_constant() {
                    self.evaluator.set_known(var, c.clone());
                    return Some(c.clone());
                }
            }
        }

        None
    }

    /// Resolves all variables to constants. Returns `None` if any variable can't be resolved.
    pub fn resolve_all(&mut self, vars: &[SsaVarId]) -> Option<Vec<ConstValue>> {
        let mut result = Vec::with_capacity(vars.len());
        for &var in vars {
            result.push(self.resolve(var)?);
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{
            ssa::{
                ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction,
                SsaOp, SsaVarId, SsaVariable, VariableOrigin,
            },
            CallGraph,
        },
        compiler::CompilerContext,
        metadata::{token::Token, typesystem::PointerSize},
    };

    use super::ValueResolver;

    // ── Basic constant resolution ────────────────────────────────────

    #[test]
    fn test_resolve_const() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let var = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let var_id = var.id();
        ssa.add_variable(var);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        assert_eq!(resolver.resolve(var_id), Some(ConstValue::I32(42)));
    }

    #[test]
    fn test_resolve_arithmetic_chain() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // v0 = 10
        let v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0_id = v0.id();
        ssa.add_variable(v0);

        // v1 = 3
        let v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let v1_id = v1.id();
        ssa.add_variable(v1);

        // v2 = v0 + v1
        let v2 = SsaVariable::new(VariableOrigin::Stack(2), 0, DefSite::instruction(0, 2));
        let v2_id = v2.id();
        ssa.add_variable(v2);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(10),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(3),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: v2_id,
            left: v0_id,
            right: v1_id,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        assert_eq!(resolver.resolve(v2_id), Some(ConstValue::I32(13)));
    }

    // ── PHI uniform constant ─────────────────────────────────────────

    #[test]
    fn test_resolve_phi_uniform() {
        let mut ssa = SsaFunction::new(0, 0);

        // Block 0: v0 = 42, jump to block 2
        let v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0_id = v0.id();
        ssa.add_variable(v0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(42),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block0);

        // Block 1: v1 = 42, jump to block 2
        let v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(1, 0));
        let v1_id = v1.id();
        ssa.add_variable(v1);

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(42),
        }));
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block1);

        // Block 2: phi(v0, v1) - both are 42
        let phi_result = SsaVariable::new(VariableOrigin::Local(0), 0, DefSite::phi(2));
        let phi_result_id = phi_result.id();
        ssa.add_variable(phi_result);

        let mut block2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(phi_result_id, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0_id, 0));
        phi.add_operand(PhiOperand::new(v1_id, 1));
        block2.add_phi(phi);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block2);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        assert_eq!(resolver.resolve(phi_result_id), Some(ConstValue::I32(42)));
    }

    #[test]
    fn test_resolve_phi_non_uniform() {
        let mut ssa = SsaFunction::new(0, 0);

        // v0 = 42
        let v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0_id = v0.id();
        ssa.add_variable(v0);

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(42),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block0);

        // v1 = 99 (different)
        let v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(1, 0));
        let v1_id = v1.id();
        ssa.add_variable(v1);

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(99),
        }));
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block1);

        // phi(v0, v1) - different values
        let phi_result = SsaVariable::new(VariableOrigin::Local(0), 0, DefSite::phi(2));
        let phi_result_id = phi_result.id();
        ssa.add_variable(phi_result);

        let mut block2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(phi_result_id, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0_id, 0));
        phi.add_operand(PhiOperand::new(v1_id, 1));
        block2.add_phi(phi);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block2);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        assert_eq!(resolver.resolve(phi_result_id), None);
    }

    // ── Known values / load_known_values ─────────────────────────────

    #[test]
    fn test_set_known() {
        let ssa = SsaFunction::new(0, 0);
        let var_id = SsaVarId::new();

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.set_known(var_id, ConstValue::I32(999));

        assert_eq!(resolver.resolve(var_id), Some(ConstValue::I32(999)));
    }

    #[test]
    fn test_load_known_values() {
        let ssa = SsaFunction::new(0, 0);
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let method = Token::new(0x06000001);

        let var1 = SsaVarId::new();
        let var2 = SsaVarId::new();
        ctx.add_known_value(method, var1, ConstValue::I32(10));
        ctx.add_known_value(method, var2, ConstValue::I32(20));

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values(&ctx, method);

        assert_eq!(resolver.resolve(var1), Some(ConstValue::I32(10)));
        assert_eq!(resolver.resolve(var2), Some(ConstValue::I32(20)));
    }

    // ── resolve_all ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_all_success() {
        let ssa = SsaFunction::new(0, 0);

        let var1 = SsaVarId::new();
        let var2 = SsaVarId::new();

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.set_known(var1, ConstValue::I32(1));
        resolver.set_known(var2, ConstValue::I32(2));

        let result = resolver.resolve_all(&[var1, var2]);
        assert_eq!(result, Some(vec![ConstValue::I32(1), ConstValue::I32(2)]));
    }

    #[test]
    fn test_resolve_all_partial_failure() {
        let ssa = SsaFunction::new(0, 0);

        let var1 = SsaVarId::new();
        let var2 = SsaVarId::new();

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.set_known(var1, ConstValue::I32(1));
        // var2 unknown

        assert_eq!(resolver.resolve_all(&[var1, var2]), None);
    }

    #[test]
    fn test_resolve_all_empty() {
        let ssa = SsaFunction::new(0, 0);
        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);

        assert_eq!(resolver.resolve_all(&[]), Some(vec![]));
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn test_resolve_unknown_var() {
        let ssa = SsaFunction::new(0, 0);
        let unknown = SsaVarId::new();

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        assert_eq!(resolver.resolve(unknown), None);
    }

    #[test]
    fn test_resolve_xor_both_const() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0_id = v0.id();
        ssa.add_variable(v0);

        let v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let v1_id = v1.id();
        ssa.add_variable(v1);

        let v2 = SsaVariable::new(VariableOrigin::Stack(2), 0, DefSite::instruction(0, 2));
        let v2_id = v2.id();
        ssa.add_variable(v2);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(0xFF),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(0x0F),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Xor {
            dest: v2_id,
            left: v0_id,
            right: v1_id,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        assert_eq!(resolver.resolve(v2_id), Some(ConstValue::I32(0xF0)));
    }
}
