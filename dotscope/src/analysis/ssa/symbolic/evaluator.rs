//! Symbolic evaluator for building expression trees from SSA operations.
//!
//! This module provides [`SymbolicEvaluator`], which tracks SSA operations
//! symbolically to build [`SymbolicExpr`] trees. Unlike concrete evaluation,
//! symbolic evaluation preserves the relationship between operations, enabling
//! constraint solving with Z3.

use std::collections::HashMap;

use crate::{
    analysis::ssa::{
        symbolic::{expr::SymbolicExpr, ops::SymbolicOp},
        ConstValue, SsaFunction, SsaOp, SsaVarId,
    },
    metadata::typesystem::PointerSize,
};

/// Symbolic evaluator that builds expression trees from SSA operations.
///
/// Unlike `SsaEvaluator` which computes concrete values, `SymbolicEvaluator`
/// tracks operations symbolically, building `SymbolicExpr` trees that can
/// later be solved using Z3.
#[derive(Debug)]
pub struct SymbolicEvaluator<'a> {
    ssa: &'a SsaFunction,
    /// Expressions computed for each variable.
    expressions: HashMap<SsaVarId, SymbolicExpr>,
    /// Target pointer size for native int/uint masking.
    pointer_size: PointerSize,
}

impl<'a> SymbolicEvaluator<'a> {
    /// Creates a new symbolic evaluator for the given SSA function.
    ///
    /// The evaluator starts with no known expressions. Use [`set_symbolic`](Self::set_symbolic)
    /// or [`set_constant`](Self::set_constant) to initialize variable values before
    /// evaluating blocks.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    ///
    /// # Returns
    ///
    /// A new evaluator with no expressions.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction, ptr_size: PointerSize) -> Self {
        Self {
            ssa,
            expressions: HashMap::new(),
            pointer_size: ptr_size,
        }
    }

    /// Sets a variable to a named symbolic value.
    ///
    /// Named symbolic values represent external inputs whose concrete values
    /// are unknown. Use this to mark the "state" variable in control flow
    /// unflattening.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to set.
    /// * `name` - The symbolic name (e.g., "state").
    pub fn set_symbolic(&mut self, var: SsaVarId, name: impl Into<String>) {
        self.expressions.insert(var, SymbolicExpr::named(name));
    }

    /// Sets a variable to a typed constant value.
    ///
    /// Use this to provide known initial values for variables with type preservation.
    /// The caller is responsible for providing the correct `ConstValue` type.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to set.
    /// * `value` - The typed constant value.
    pub fn set_constant(&mut self, var: SsaVarId, value: ConstValue) {
        self.expressions.insert(var, SymbolicExpr::constant(value));
    }

    /// Gets the expression for a variable, if known.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to look up.
    ///
    /// # Returns
    ///
    /// The expression for the variable, or `None` if not yet evaluated.
    #[must_use]
    pub fn get_expression(&self, var: SsaVarId) -> Option<&SymbolicExpr> {
        self.expressions.get(&var)
    }

    /// Gets the expression for a variable, simplified.
    ///
    /// Returns a copy of the expression with constant folding and algebraic
    /// simplifications applied.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable to look up.
    ///
    /// # Returns
    ///
    /// A simplified copy of the expression, or `None` if not yet evaluated.
    #[must_use]
    pub fn get_simplified(&self, var: SsaVarId) -> Option<SymbolicExpr> {
        self.expressions
            .get(&var)
            .map(|e| e.simplify(self.pointer_size))
    }

    /// Returns all computed expressions.
    ///
    /// # Returns
    ///
    /// A reference to the map from variable IDs to their symbolic expressions.
    #[must_use]
    pub fn expressions(&self) -> &HashMap<SsaVarId, SymbolicExpr> {
        &self.expressions
    }

    /// Evaluates all instructions in a block symbolically.
    ///
    /// Processes each instruction in the block, building symbolic expressions
    /// for any variables they define.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The index of the block to evaluate.
    pub fn evaluate_block(&mut self, block_idx: usize) {
        let Some(block) = self.ssa.block(block_idx) else {
            return;
        };

        for instr in block.instructions() {
            self.evaluate_op(instr.op());
        }
    }

    /// Evaluates a sequence of blocks in order.
    ///
    /// # Arguments
    ///
    /// * `block_indices` - The indices of blocks to evaluate, in order.
    pub fn evaluate_blocks(&mut self, block_indices: &[usize]) {
        for &block_idx in block_indices {
            self.evaluate_block(block_idx);
        }
    }

    /// Evaluates a single SSA operation symbolically.
    ///
    /// Builds a symbolic expression for the operation's result based on its
    /// operands. If operands have known expressions, those are used; otherwise,
    /// the operands are treated as symbolic variables.
    ///
    /// # Arguments
    ///
    /// * `op` - The SSA operation to evaluate.
    pub fn evaluate_op(&mut self, op: &SsaOp) {
        match op {
            SsaOp::Const { dest, value } => {
                self.expressions
                    .insert(*dest, SymbolicExpr::constant(value.clone()));
            }

            SsaOp::Copy { dest, src } => {
                if let Some(expr) = self.expressions.get(src) {
                    self.expressions.insert(*dest, expr.clone());
                } else {
                    self.expressions.insert(*dest, SymbolicExpr::variable(*src));
                }
            }

            SsaOp::Add { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::Add);
            }
            SsaOp::Sub { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::Sub);
            }
            SsaOp::Mul { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::Mul);
            }
            SsaOp::Div {
                dest,
                left,
                right,
                unsigned,
            } => {
                let op = if *unsigned {
                    SymbolicOp::DivU
                } else {
                    SymbolicOp::DivS
                };
                self.eval_binary(*dest, *left, *right, op);
            }
            SsaOp::Rem {
                dest,
                left,
                right,
                unsigned,
            } => {
                let op = if *unsigned {
                    SymbolicOp::RemU
                } else {
                    SymbolicOp::RemS
                };
                self.eval_binary(*dest, *left, *right, op);
            }
            SsaOp::Xor { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::Xor);
            }
            SsaOp::And { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::And);
            }
            SsaOp::Or { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::Or);
            }
            SsaOp::Shl {
                dest,
                value,
                amount,
            } => {
                self.eval_binary(*dest, *value, *amount, SymbolicOp::Shl);
            }
            SsaOp::Shr {
                dest,
                value,
                amount,
                unsigned,
            } => {
                let op = if *unsigned {
                    SymbolicOp::ShrU
                } else {
                    SymbolicOp::ShrS
                };
                self.eval_binary(*dest, *value, *amount, op);
            }
            SsaOp::Neg { dest, operand } => {
                self.eval_unary(*dest, *operand, SymbolicOp::Neg);
            }
            SsaOp::Not { dest, operand } => {
                self.eval_unary(*dest, *operand, SymbolicOp::Not);
            }
            SsaOp::Ceq { dest, left, right } => {
                self.eval_binary(*dest, *left, *right, SymbolicOp::Eq);
            }
            SsaOp::Cgt {
                dest,
                left,
                right,
                unsigned,
            } => {
                let op = if *unsigned {
                    SymbolicOp::GtU
                } else {
                    SymbolicOp::GtS
                };
                self.eval_binary(*dest, *left, *right, op);
            }
            SsaOp::Clt {
                dest,
                left,
                right,
                unsigned,
            } => {
                let op = if *unsigned {
                    SymbolicOp::LtU
                } else {
                    SymbolicOp::LtS
                };
                self.eval_binary(*dest, *left, *right, op);
            }
            SsaOp::Conv { dest, operand, .. } => {
                if let Some(expr) = self.expressions.get(operand) {
                    self.expressions.insert(*dest, expr.clone());
                } else {
                    self.expressions
                        .insert(*dest, SymbolicExpr::variable(*operand));
                }
            }
            _ => {}
        }
    }

    /// Evaluates a binary operation and stores the result expression.
    ///
    /// Looks up expressions for the operands (or creates variable references
    /// if unknown), combines them with the operation, simplifies, and stores.
    ///
    /// # Arguments
    ///
    /// * `dest` - The destination variable for the result.
    /// * `left` - The left operand variable.
    /// * `right` - The right operand variable.
    /// * `op` - The binary operation to apply.
    fn eval_binary(&mut self, dest: SsaVarId, left: SsaVarId, right: SsaVarId, op: SymbolicOp) {
        let left_expr = self
            .expressions
            .get(&left)
            .cloned()
            .unwrap_or_else(|| SymbolicExpr::variable(left));
        let right_expr = self
            .expressions
            .get(&right)
            .cloned()
            .unwrap_or_else(|| SymbolicExpr::variable(right));

        let result = SymbolicExpr::binary(op, left_expr, right_expr).simplify(self.pointer_size);
        self.expressions.insert(dest, result);
    }

    /// Evaluates a unary operation and stores the result expression.
    ///
    /// Looks up the expression for the operand (or creates a variable reference
    /// if unknown), applies the operation, simplifies, and stores.
    ///
    /// # Arguments
    ///
    /// * `dest` - The destination variable for the result.
    /// * `operand` - The operand variable.
    /// * `op` - The unary operation to apply.
    fn eval_unary(&mut self, dest: SsaVarId, operand: SsaVarId, op: SymbolicOp) {
        let operand_expr = self
            .expressions
            .get(&operand)
            .cloned()
            .unwrap_or_else(|| SymbolicExpr::variable(operand));

        let result = SymbolicExpr::unary(op, operand_expr).simplify(self.pointer_size);
        self.expressions.insert(dest, result);
    }
}
