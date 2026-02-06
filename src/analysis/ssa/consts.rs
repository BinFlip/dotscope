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
//! let mut evaluator = ConstEvaluator::new(&ssa);
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

use std::collections::{HashMap, HashSet};

use crate::analysis::ssa::{ConstValue, SsaFunction, SsaOp, SsaVarId};

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
    visiting: HashSet<SsaVarId>,

    /// Maximum recursion depth.
    max_depth: usize,
}

impl<'a> ConstEvaluator<'a> {
    /// Default maximum recursion depth.
    const DEFAULT_MAX_DEPTH: usize = 20;

    /// Creates a new evaluator with default settings.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        Self::with_max_depth(ssa, Self::DEFAULT_MAX_DEPTH)
    }

    /// Creates an evaluator with a custom depth limit.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `max_depth` - Maximum recursion depth for evaluation.
    #[must_use]
    pub fn with_max_depth(ssa: &'a SsaFunction, max_depth: usize) -> Self {
        Self {
            ssa,
            cache: HashMap::new(),
            visiting: HashSet::new(),
            max_depth,
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
        if self.visiting.contains(&var) {
            return None;
        }

        // Mark as visiting
        self.visiting.insert(var);

        // Get definition and evaluate
        let result = self
            .ssa
            .get_definition(var)
            .and_then(|op| self.evaluate_op_depth(op, depth));

        // Remove from visiting set
        self.visiting.remove(&var);

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

        match op {
            // Direct constant
            SsaOp::Const { value, .. } => Some(value.clone()),

            // Copy - trace through to source
            SsaOp::Copy { src, .. } => self.evaluate_var_depth(*src, depth + 1),

            // Binary operations (Task 2.2 will expand this)
            SsaOp::Xor { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.bitwise_xor(&r)
            }
            SsaOp::And { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.bitwise_and(&r)
            }
            SsaOp::Or { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.bitwise_or(&r)
            }
            SsaOp::Add { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.add(&r)
            }
            SsaOp::Sub { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.sub(&r)
            }
            SsaOp::Mul { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.mul(&r)
            }
            SsaOp::Div { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.div(&r)
            }
            SsaOp::Rem { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.rem(&r)
            }
            SsaOp::Shl { value, amount, .. } => {
                let v = self.evaluate_var_depth(*value, depth + 1)?;
                let a = self.evaluate_var_depth(*amount, depth + 1)?;
                v.shl(&a)
            }
            SsaOp::Shr {
                value,
                amount,
                unsigned,
                ..
            } => {
                let v = self.evaluate_var_depth(*value, depth + 1)?;
                let a = self.evaluate_var_depth(*amount, depth + 1)?;
                v.shr(&a, *unsigned)
            }

            // Unary operations
            SsaOp::Neg { operand, .. } => {
                let v = self.evaluate_var_depth(*operand, depth + 1)?;
                v.negate()
            }
            SsaOp::Not { operand, .. } => {
                let v = self.evaluate_var_depth(*operand, depth + 1)?;
                v.bitwise_not()
            }

            // Comparison operations - use typed ConstValue methods
            SsaOp::Ceq { left, right, .. } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.ceq(&r)
            }
            SsaOp::Clt {
                left,
                right,
                unsigned,
                ..
            } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
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
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                if *unsigned {
                    l.cgt_un(&r)
                } else {
                    l.cgt(&r)
                }
            }

            // Overflow-checked arithmetic operations
            SsaOp::AddOvf {
                left,
                right,
                unsigned,
                ..
            } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.add_checked(&r, *unsigned)
            }
            SsaOp::SubOvf {
                left,
                right,
                unsigned,
                ..
            } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.sub_checked(&r, *unsigned)
            }
            SsaOp::MulOvf {
                left,
                right,
                unsigned,
                ..
            } => {
                let l = self.evaluate_var_depth(*left, depth + 1)?;
                let r = self.evaluate_var_depth(*right, depth + 1)?;
                l.mul_checked(&r, *unsigned)
            }

            // Type conversion
            SsaOp::Conv {
                operand,
                target,
                overflow_check,
                unsigned,
                ..
            } => {
                let v = self.evaluate_var_depth(*operand, depth + 1)?;
                if *overflow_check {
                    v.convert_to_checked(target, *unsigned)
                } else {
                    v.convert_to(target, *unsigned)
                }
            }

            // All other operations cannot be evaluated to constants
            _ => None,
        }
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

#[cfg(test)]
mod tests {
    use crate::analysis::ssa::{
        ConstEvaluator, ConstValue, DefSite, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
        SsaVarId, SsaVariable, VariableOrigin,
    };

    #[test]
    fn test_evaluate_constant() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // Create a constant: v0 = 42
        let var = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let var_id = var.id();
        ssa.add_variable(var);

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(block);

        let mut evaluator = ConstEvaluator::new(&ssa);
        let result = evaluator.evaluate_var(var_id);

        assert_eq!(result, Some(ConstValue::I32(42)));
    }

    #[test]
    fn test_evaluate_copy_chain() {
        let mut ssa = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // v0 = 100
        let v0 = SsaVariable::new(VariableOrigin::Stack(0), 0, DefSite::instruction(0, 0));
        let v0_id = v0.id();
        ssa.add_variable(v0);

        // v1 = v0 (copy)
        let v1 = SsaVariable::new(VariableOrigin::Stack(1), 0, DefSite::instruction(0, 1));
        let v1_id = v1.id();
        ssa.add_variable(v1);

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

        let mut evaluator = ConstEvaluator::new(&ssa);
        let result = evaluator.evaluate_var(v1_id);

        assert_eq!(result, Some(ConstValue::I32(100)));
    }

    #[test]
    fn test_set_known_value() {
        let ssa = SsaFunction::new(0, 0);
        let var_id = SsaVarId::new();

        let mut evaluator = ConstEvaluator::new(&ssa);
        evaluator.set_known(var_id, ConstValue::I32(999));

        let result = evaluator.evaluate_var(var_id);
        assert_eq!(result, Some(ConstValue::I32(999)));
    }

    #[test]
    fn test_into_results() {
        let ssa = SsaFunction::new(0, 0);
        let var1 = SsaVarId::new();
        let var2 = SsaVarId::new();

        let mut evaluator = ConstEvaluator::new(&ssa);
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
