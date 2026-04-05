//! Constant evaluation for SSA operations.
//!
//! This module provides unified constant folding capabilities for SSA analysis.
//! The [`ConstEvaluator`] can be used by multiple passes (unflattening, decryption,
//! SCCP, etc.) to evaluate SSA operations to constant values.
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{ConstEvaluator, SsaFunction};
//!
//! let mut evaluator = ConstEvaluator::new(&ssa, PointerSize::Bit64);
//!
//! // Inject known values from external analysis
//! evaluator.set_known(state_var, ConstValue::I32(42));
//!
//! // Evaluate a variable
//! if let Some(value) = evaluator.evaluate_var(some_var) {
//!     println!("Variable evaluates to: {:?}", value);
//! }
//!
//! // Get all computed constants
//! let constants = evaluator.into_results();
//! ```

use std::collections::HashMap;

use crate::{
    analysis::ssa::{ConstValue, SsaFunction, SsaOp, SsaVarId},
    metadata::typesystem::PointerSize,
    utils::BitSet,
};

/// Evaluates SSA operations to constant values.
///
/// This provides a unified implementation of constant folding that can be
/// used by multiple passes (unflattening, decryption, SCCP, etc.).
///
/// # Features
///
/// - Caches results for efficiency
/// - Detects cycles to prevent infinite recursion
/// - Supports injecting known values from external analysis
/// - Configurable depth limit
pub struct ConstEvaluator<'a> {
    /// Reference to the SSA function being analyzed.
    ssa: &'a SsaFunction,

    /// Cache of evaluated constants.
    /// `Some(value)` means the variable evaluates to that constant.
    /// `None` means the variable was evaluated but is not constant.
    cache: HashMap<SsaVarId, Option<ConstValue>>,

    /// Variables currently being evaluated (for cycle detection).
    visiting: BitSet,

    /// Maximum recursion depth.
    max_depth: usize,

    /// Target pointer size for native int/uint masking.
    pointer_size: PointerSize,
}

impl<'a> ConstEvaluator<'a> {
    /// Default maximum recursion depth.
    const DEFAULT_MAX_DEPTH: usize = 20;

    /// Creates a new evaluator with default settings.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction, ptr_size: PointerSize) -> Self {
        Self::with_max_depth(ssa, Self::DEFAULT_MAX_DEPTH, ptr_size)
    }

    /// Creates an evaluator with a custom depth limit.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `max_depth` - Maximum recursion depth for evaluation.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    #[must_use]
    pub fn with_max_depth(ssa: &'a SsaFunction, max_depth: usize, ptr_size: PointerSize) -> Self {
        Self {
            ssa,
            cache: HashMap::new(),
            visiting: BitSet::new(ssa.variable_count().max(1)),
            max_depth,
            pointer_size: ptr_size,
        }
    }

    /// Injects a known value from external analysis.
    ///
    /// This allows passes to provide values discovered through other means
    /// (e.g., from `ctx.known_values` in decryption). Injected values take
    /// precedence over computed values.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable to set.
    /// * `value` - The known constant value.
    pub fn set_known(&mut self, var: SsaVarId, value: ConstValue) {
        self.cache.insert(var, Some(value));
    }

    /// Evaluates a variable to a constant if possible.
    ///
    /// Results are cached, so repeated calls with the same variable are O(1).
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to evaluate.
    ///
    /// # Returns
    ///
    /// The constant value if the variable can be evaluated, `None` otherwise.
    pub fn evaluate_var(&mut self, var: SsaVarId) -> Option<ConstValue> {
        self.evaluate_var_depth(var, 0)
    }

    /// Internal evaluation with depth tracking.
    fn evaluate_var_depth(&mut self, var: SsaVarId, depth: usize) -> Option<ConstValue> {
        // Check depth limit
        if depth > self.max_depth {
            return None;
        }

        // Check cache first
        if let Some(cached) = self.cache.get(&var) {
            return cached.clone();
        }

        // Cycle detection
        if var.index() < self.visiting.len() && self.visiting.contains(var.index()) {
            return None;
        }

        // Mark as visiting
        if var.index() < self.visiting.len() {
            self.visiting.insert(var.index());
        }

        // Get definition and evaluate
        let result = self
            .ssa
            .get_definition(var)
            .and_then(|op| self.evaluate_op_depth(op, depth));

        // Remove from visiting set
        if var.index() < self.visiting.len() {
            self.visiting.remove(var.index());
        }

        // Cache the result
        self.cache.insert(var, result.clone());

        result
    }

    /// Evaluates an SSA operation to a constant if possible.
    ///
    /// # Arguments
    ///
    /// * `op` - The SSA operation to evaluate.
    ///
    /// # Returns
    ///
    /// The constant value if the operation can be evaluated, `None` otherwise.
    pub fn evaluate_op(&mut self, op: &SsaOp) -> Option<ConstValue> {
        self.evaluate_op_depth(op, 0)
    }

    /// Internal operation evaluation with depth tracking.
    fn evaluate_op_depth(&mut self, op: &SsaOp, depth: usize) -> Option<ConstValue> {
        // Check depth limit
        if depth > self.max_depth {
            return None;
        }

        // Copy needs recursive evaluation that the shared helper cannot provide,
        // because it resolves a variable rather than performing arithmetic.
        if let SsaOp::Copy { src, .. } = op {
            return self.evaluate_var_depth(*src, depth + 1);
        }

        let ptr_size = self.pointer_size;
        evaluate_const_op(op, |var| self.evaluate_var_depth(var, depth + 1), ptr_size)
    }

    /// Returns all computed constants.
    ///
    /// This consumes the evaluator and returns a map of all variables
    /// that were successfully evaluated to constants.
    #[must_use]
    pub fn into_results(self) -> HashMap<SsaVarId, ConstValue> {
        self.cache
            .into_iter()
            .filter_map(|(var, opt)| opt.map(|val| (var, val)))
            .collect()
    }

    /// Returns a reference to the SSA function being evaluated.
    #[must_use]
    pub fn ssa(&self) -> &SsaFunction {
        self.ssa
    }

    /// Clears the evaluation cache.
    ///
    /// This is useful if the SSA function has been modified and
    /// cached results are no longer valid.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Evaluates an SSA operation to a constant value using the provided operand resolver.
///
/// This is the shared arithmetic dispatch for constant evaluation. It handles all
/// pure arithmetic, bitwise, comparison, overflow-checked, and conversion operations.
/// Callers provide a `get_const` closure that resolves an [`SsaVarId`] to its constant
/// value (if known).
///
/// # Operations not handled
///
/// - `Copy` — requires variable-level resolution (trace-through), not arithmetic.
///   Callers should handle `Copy` before calling this function.
/// - Calls, loads, stores, and other side-effecting operations — always returns `None`.
///
/// # Arguments
///
/// * `op` - The SSA operation to evaluate.
/// * `get_const` - Closure that resolves a variable to its constant value.
/// * `ptr_size` - Target pointer size for native int/uint masking.
///
/// # Returns
///
/// The constant result if all operands resolve and the operation succeeds, `None` otherwise.
pub fn evaluate_const_op(
    op: &SsaOp,
    mut get_const: impl FnMut(SsaVarId) -> Option<ConstValue>,
    ptr_size: PointerSize,
) -> Option<ConstValue> {
    match op {
        SsaOp::Const { value, .. } => Some(value.clone()),

        // Binary arithmetic
        SsaOp::Add { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.add(&r, ptr_size)
        }
        SsaOp::Sub { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.sub(&r, ptr_size)
        }
        SsaOp::Mul { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.mul(&r, ptr_size)
        }
        SsaOp::Div { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.div(&r, ptr_size)
        }
        SsaOp::Rem { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.rem(&r, ptr_size)
        }

        // Bitwise
        SsaOp::Xor { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.bitwise_xor(&r, ptr_size)
        }
        SsaOp::And { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.bitwise_and(&r, ptr_size)
        }
        SsaOp::Or { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.bitwise_or(&r, ptr_size)
        }

        // Shifts
        SsaOp::Shl { value, amount, .. } => {
            let v = get_const(*value)?;
            let a = get_const(*amount)?;
            v.shl(&a, ptr_size)
        }
        SsaOp::Shr {
            value,
            amount,
            unsigned,
            ..
        } => {
            let v = get_const(*value)?;
            let a = get_const(*amount)?;
            v.shr(&a, *unsigned, ptr_size)
        }

        // Unary
        SsaOp::Neg { operand, .. } => {
            let v = get_const(*operand)?;
            v.negate(ptr_size)
        }
        SsaOp::Not { operand, .. } => {
            let v = get_const(*operand)?;
            v.bitwise_not(ptr_size)
        }

        // Comparisons
        SsaOp::Ceq { left, right, .. } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.ceq(&r)
        }
        SsaOp::Clt {
            left,
            right,
            unsigned,
            ..
        } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            if *unsigned {
                l.clt_un(&r)
            } else {
                l.clt(&r)
            }
        }
        SsaOp::Cgt {
            left,
            right,
            unsigned,
            ..
        } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            if *unsigned {
                l.cgt_un(&r)
            } else {
                l.cgt(&r)
            }
        }

        // Overflow-checked arithmetic
        SsaOp::AddOvf {
            left,
            right,
            unsigned,
            ..
        } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.add_checked(&r, *unsigned, ptr_size)
        }
        SsaOp::SubOvf {
            left,
            right,
            unsigned,
            ..
        } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.sub_checked(&r, *unsigned, ptr_size)
        }
        SsaOp::MulOvf {
            left,
            right,
            unsigned,
            ..
        } => {
            let l = get_const(*left)?;
            let r = get_const(*right)?;
            l.mul_checked(&r, *unsigned, ptr_size)
        }

        // Type conversion
        SsaOp::Conv {
            operand,
            target,
            overflow_check,
            unsigned,
            ..
        } => {
            let v = get_const(*operand)?;
            if *overflow_check {
                v.convert_to_checked(target, *unsigned, ptr_size)
            } else {
                v.convert_to(target, *unsigned, ptr_size)
            }
        }

        // All other operations cannot be evaluated to constants
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::ssa::{
            ConstEvaluator, ConstValue, DefSite, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
            SsaType, SsaVarId, VariableOrigin,
        },
        metadata::typesystem::PointerSize,
    };

    #[test]
    fn test_evaluate_constant() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // Create a constant: v0 = 42
        let var_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let mut evaluator = ConstEvaluator::new(&ssa, PointerSize::Bit64);
        let result = evaluator.evaluate_var(var_id);

        assert_eq!(result, Some(ConstValue::I32(42)));
    }

    #[test]
    fn test_evaluate_copy_chain() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // v0 = 100
        let v0_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        // v1 = v0 (copy)
        let v1_id = ssa.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(0, 1),
            SsaType::Unknown,
        );

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(100),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Copy {
            dest: v1_id,
            src: v0_id,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let mut evaluator = ConstEvaluator::new(&ssa, PointerSize::Bit64);
        let result = evaluator.evaluate_var(v1_id);

        assert_eq!(result, Some(ConstValue::I32(100)));
    }

    #[test]
    fn test_set_known_value() {
        let ssa = SsaFunction::new(0, 0);
        let var_id = SsaVarId::from_index(0);

        let mut evaluator = ConstEvaluator::new(&ssa, PointerSize::Bit64);
        evaluator.set_known(var_id, ConstValue::I32(999));

        let result = evaluator.evaluate_var(var_id);
        assert_eq!(result, Some(ConstValue::I32(999)));
    }

    #[test]
    fn test_into_results() {
        let ssa = SsaFunction::new(0, 0);
        let var1 = SsaVarId::from_index(0);
        let var2 = SsaVarId::from_index(1);

        let mut evaluator = ConstEvaluator::new(&ssa, PointerSize::Bit64);
        evaluator.set_known(var1, ConstValue::I32(1));
        evaluator.set_known(var2, ConstValue::I32(2));

        // Force evaluation to populate cache
        evaluator.evaluate_var(var1);
        evaluator.evaluate_var(var2);

        let results = evaluator.into_results();
        assert_eq!(results.len(), 2);
        assert_eq!(results.get(&var1), Some(&ConstValue::I32(1)));
        assert_eq!(results.get(&var2), Some(&ConstValue::I32(2)));
    }
}
