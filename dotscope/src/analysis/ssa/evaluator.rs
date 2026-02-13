//! SSA evaluator for computing values.
//!
//! This module provides an interpreter for SSA operations that can evaluate
//! arithmetic and logical operations given known input values. It supports:
//!
//! - **Concrete values**: Known integer constants (fast, direct evaluation)
//! - **Symbolic values**: Expressions depending on unknown inputs (enables Z3 solving)
//! - **Unknown values**: Values that cannot be determined statically (represented as `None`)
//!
//! # Use Cases
//!
//! - Control flow unflattening (computing state transitions)
//! - Constant propagation verification
//! - Opaque predicate detection
//! - Symbolic execution of small code fragments
//!
//! # Design
//!
//! The evaluator operates directly on SSA form without needing full CIL emulation
//! infrastructure. Values are represented as [`SymbolicExpr`], where:
//! - `SymbolicExpr::Constant(v)` represents a known concrete value
//! - Other `SymbolicExpr` variants represent symbolic expressions
//! - `None` (absence from the value map) represents unknown values
//!
//! # CIL Semantics
//!
//! All arithmetic operations use 32-bit wrapping semantics as per ECMA-335.
//! Values are stored as i64 for convenience, but operations intentionally
//! truncate to i32/u32 to match CLR behavior.
//!
//! # Path-Aware Evaluation
//!
//! The evaluator supports path-aware phi node evaluation. When traversing a specific
//! path through the CFG, use [`set_predecessor`](SsaEvaluator::set_predecessor) before
//! evaluating a block to select the correct phi operand.
//!
//! # Usage
//!
//! ```rust,ignore
//! use dotscope::analysis::{SsaEvaluator, SymbolicExpr};
//!
//! let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
//!
//! // Set known concrete values
//! eval.set_concrete(state_var, initial_state);
//!
//! // Or mark as symbolic
//! eval.set_symbolic(arg_var, "arg0");
//!
//! // Evaluate a block's instructions
//! eval.evaluate_block(block_idx);
//!
//! // Get computed result
//! match eval.get(result_var) {
//!     Some(expr) if expr.is_constant() => println!("Known: {}", expr.as_constant().unwrap()),
//!     Some(expr) => println!("Symbolic: {}", expr),
//!     None => println!("Cannot determine"),
//! }
//!
//! // Or use convenience method for concrete values
//! if let Some(next_state) = eval.get_concrete(result_var) {
//!     println!("Next state: {}", next_state);
//! }
//! ```

use std::collections::HashMap;

use crate::{
    analysis::ssa::{
        constraints::Constraint,
        memory::{MemoryLocation, MemoryState},
        symbolic::{SymbolicExpr, SymbolicOp},
        CmpKind, ConstValue, SsaFunction, SsaOp, SsaType, SsaVarId,
    },
    metadata::typesystem::PointerSize,
};

/// Result of evaluating a control flow decision.
///
/// This represents the outcome of analyzing a terminator instruction to
/// determine the next block to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlow {
    /// Continue to the specified block.
    Continue(usize),
    /// Terminal instruction - execution ends here (return, throw, etc.).
    Terminal,
    /// Cannot determine the next block - condition is unknown or symbolic.
    Unknown,
}

impl ControlFlow {
    /// Returns the target block if this is a `Continue` result.
    #[must_use]
    pub fn target(&self) -> Option<usize> {
        match self {
            Self::Continue(block) => Some(*block),
            _ => None,
        }
    }

    /// Returns `true` if this is a terminal result.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal)
    }

    /// Returns `true` if the control flow cannot be determined.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Configuration for SSA evaluators.
///
/// This struct controls the behavior of [`SsaEvaluator`], allowing it to be
/// configured for different use cases like general evaluation, path-aware
/// analysis, or CFF deobfuscation.
#[derive(Debug, Clone, Default)]
pub struct EvaluatorConfig {
    /// Track the execution path (sequence of visited blocks).
    pub track_path: bool,
    /// Track memory state (field loads/stores).
    pub track_memory: bool,
    /// Require predecessor for phi evaluation (strict path-aware mode).
    pub strict_phi: bool,
}

impl EvaluatorConfig {
    /// Creates a new default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration for path-aware analysis.
    ///
    /// Enables path tracking, memory tracking, and strict phi evaluation.
    #[must_use]
    pub fn path_aware() -> Self {
        Self {
            track_path: true,
            track_memory: true,
            strict_phi: true,
        }
    }

    /// Creates a configuration with memory tracking only.
    #[must_use]
    pub fn with_memory() -> Self {
        Self {
            track_path: false,
            track_memory: true,
            strict_phi: false,
        }
    }

    /// Enables path tracking.
    #[must_use]
    pub fn with_path_tracking(mut self) -> Self {
        self.track_path = true;
        self
    }

    /// Enables memory state tracking.
    #[must_use]
    pub fn with_memory_tracking(mut self) -> Self {
        self.track_memory = true;
        self
    }

    /// Enables strict phi evaluation (requires predecessor).
    #[must_use]
    pub fn with_strict_phi(mut self) -> Self {
        self.strict_phi = true;
        self
    }
}

/// Records the execution trace of SSA evaluation.
///
/// This struct tracks the sequence of blocks visited during SSA evaluation,
/// along with optional state values at each step. This is essential for
/// CFF (Control Flow Flattening) deobfuscation, where we need to record
/// the dispatcher state transitions to reconstruct the original control flow.
#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    /// Sequence of block indices visited.
    blocks: Vec<usize>,
    /// Optional state values captured at each block (for state machines).
    states: Vec<Option<ConstValue>>,
    /// Whether execution completed normally (reached terminal).
    completed: bool,
    /// Maximum blocks to trace before stopping (prevents infinite loops).
    limit: usize,
}

impl ExecutionTrace {
    /// Creates a new execution trace with the given block limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            blocks: Vec::new(),
            states: Vec::new(),
            completed: false,
            limit,
        }
    }

    /// Returns the blocks visited during execution.
    #[must_use]
    pub fn blocks(&self) -> &[usize] {
        &self.blocks
    }

    /// Returns the state values captured during execution.
    #[must_use]
    pub fn states(&self) -> &[Option<ConstValue>] {
        &self.states
    }

    /// Returns `true` if execution completed (reached a terminal instruction).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completed
    }

    /// Returns the number of blocks visited.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns `true` if no blocks were visited.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the last visited block, if any.
    #[must_use]
    pub fn last_block(&self) -> Option<usize> {
        self.blocks.last().copied()
    }

    /// Returns `true` if the trace reached the block limit.
    #[must_use]
    pub fn hit_limit(&self) -> bool {
        self.blocks.len() >= self.limit
    }

    /// Records a block visit.
    fn record_block(&mut self, block_idx: usize, state: Option<ConstValue>) {
        self.blocks.push(block_idx);
        self.states.push(state);
    }

    /// Marks execution as complete.
    fn mark_complete(&mut self) {
        self.completed = true;
    }
}

/// SSA evaluator with hybrid concrete/symbolic value tracking.
///
/// This evaluator interprets SSA operations to compute values without needing
/// full CIL emulation. Values are represented as [`SymbolicExpr`]:
///
/// - **Concrete**: `SymbolicExpr::Constant(v)` - Known integer values
/// - **Symbolic**: Other `SymbolicExpr` variants - Expressions depending on unknown inputs
/// - **Unknown**: `None` (not in the values map) - Values that cannot be determined
///
/// # Value Representation
///
/// Values are represented as `i64` internally to accommodate both 32-bit and 64-bit
/// integer operations. For 32-bit operations, the evaluator applies appropriate
/// wrapping/truncation semantics.
#[derive(Debug, Clone)]
pub struct SsaEvaluator<'a> {
    /// Reference to the SSA function being evaluated.
    ssa: &'a SsaFunction,
    /// Tracked values for variables. Missing entries represent unknown values.
    values: HashMap<SsaVarId, SymbolicExpr>,
    /// Current predecessor block for path-aware phi evaluation.
    /// When set, phi nodes will select the operand from this predecessor.
    predecessor: Option<usize>,
    /// Constraints on variable values derived from branch conditions.
    /// Used to detect dead code and propagate information after branches.
    constraints: HashMap<SsaVarId, Vec<Constraint>>,
    /// Evaluator configuration controlling behavior.
    config: EvaluatorConfig,
    /// Execution path (sequence of visited blocks). Only populated if `config.track_path`.
    path: Vec<usize>,
    /// Memory state tracking for fields. Only used if `config.track_memory`.
    memory: MemoryState,
    /// Target pointer size for native int/uint masking.
    pointer_size: PointerSize,
}

impl<'a> SsaEvaluator<'a> {
    /// Creates a new evaluator for the given SSA function.
    ///
    /// The evaluator starts with no known values. Use the `set_*` methods
    /// to provide initial values for input variables.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction, ptr_size: PointerSize) -> Self {
        Self::with_config(ssa, EvaluatorConfig::default(), ptr_size)
    }

    /// Creates an evaluator with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `config` - Configuration controlling evaluator behavior.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    #[must_use]
    pub fn with_config(
        ssa: &'a SsaFunction,
        config: EvaluatorConfig,
        ptr_size: PointerSize,
    ) -> Self {
        Self {
            ssa,
            values: HashMap::new(),
            predecessor: None,
            constraints: HashMap::new(),
            config,
            path: Vec::new(),
            memory: MemoryState::new(),
            pointer_size: ptr_size,
        }
    }

    /// Creates a path-aware evaluator with memory tracking.
    ///
    /// This is equivalent to `PathAwareEvaluator::with_memory_tracking()` and is
    /// the recommended configuration for CFF deobfuscation.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    #[must_use]
    pub fn path_aware(ssa: &'a SsaFunction, ptr_size: PointerSize) -> Self {
        Self::with_config(ssa, EvaluatorConfig::path_aware(), ptr_size)
    }

    /// Creates an evaluator with pre-populated concrete values.
    ///
    /// Useful when you already have a set of known constants from SCCP or
    /// other analyses.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to evaluate.
    /// * `values` - Pre-populated concrete values.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    #[must_use]
    pub fn with_values(
        ssa: &'a SsaFunction,
        values: HashMap<SsaVarId, ConstValue>,
        ptr_size: PointerSize,
    ) -> Self {
        let exprs = values
            .into_iter()
            .map(|(k, v)| (k, SymbolicExpr::constant(v)))
            .collect();
        Self {
            ssa,
            values: exprs,
            predecessor: None,
            constraints: HashMap::new(),
            config: EvaluatorConfig::default(),
            path: Vec::new(),
            memory: MemoryState::new(),
            pointer_size: ptr_size,
        }
    }

    /// Returns the target pointer size.
    #[must_use]
    pub fn pointer_size(&self) -> PointerSize {
        self.pointer_size
    }

    /// Returns a reference to the underlying SSA function.
    #[must_use]
    pub fn ssa(&self) -> &SsaFunction {
        self.ssa
    }

    /// Returns a reference to the evaluator configuration.
    #[must_use]
    pub fn config(&self) -> &EvaluatorConfig {
        &self.config
    }

    /// Returns the execution path if path tracking is enabled.
    #[must_use]
    pub fn path(&self) -> &[usize] {
        &self.path
    }

    /// Clears the recorded execution path.
    pub fn clear_path(&mut self) {
        self.path.clear();
    }

    /// Returns whether memory tracking is enabled.
    #[must_use]
    pub fn memory_tracking_enabled(&self) -> bool {
        self.config.track_memory
    }

    // Value Setting

    /// Sets a concrete (known) value for a variable.
    ///
    /// The caller is responsible for providing the correct `ConstValue` type
    /// that matches the variable's type in the SSA function.
    pub fn set_concrete(&mut self, var: SsaVarId, value: ConstValue) {
        self.values.insert(var, SymbolicExpr::constant(value));
    }

    /// Sets a symbolic value for a variable using a named expression.
    ///
    /// This is useful for marking method arguments or other external inputs
    /// as symbolic with descriptive names.
    pub fn set_symbolic(&mut self, var: SsaVarId, name: impl Into<String>) {
        self.values.insert(var, SymbolicExpr::named(name));
    }

    /// Sets a symbolic value for a variable using an expression.
    pub fn set_symbolic_expr(&mut self, var: SsaVarId, expr: SymbolicExpr) {
        self.values.insert(var, expr);
    }

    /// Sets a variable as unknown by removing it from the values map.
    pub fn set_unknown(&mut self, var: SsaVarId) {
        self.values.remove(&var);
    }

    /// Sets an expression for a variable.
    pub fn set(&mut self, var: SsaVarId, value: SymbolicExpr) {
        self.values.insert(var, value);
    }

    // Value Getting

    /// Gets the expression for a variable.
    ///
    /// Returns `None` if the variable hasn't been assigned a value (unknown).
    #[must_use]
    pub fn get(&self, var: SsaVarId) -> Option<&SymbolicExpr> {
        self.values.get(&var)
    }

    /// Gets the typed constant value for a variable, if it's a constant.
    ///
    /// Returns `None` if the variable is symbolic, unknown, or not set.
    /// Use [`ConstValue`] methods to extract specific types (e.g., `as_i64()`, `as_i32()`).
    #[must_use]
    pub fn get_concrete(&self, var: SsaVarId) -> Option<&ConstValue> {
        self.values.get(&var).and_then(SymbolicExpr::as_constant)
    }

    /// Gets the symbolic expression for a variable, if it's not a constant.
    #[must_use]
    pub fn get_symbolic(&self, var: SsaVarId) -> Option<&SymbolicExpr> {
        self.values.get(&var).filter(|e| !e.is_constant())
    }

    /// Checks if a variable has a concrete (constant) value.
    #[must_use]
    pub fn is_concrete(&self, var: SsaVarId) -> bool {
        self.values.get(&var).is_some_and(SymbolicExpr::is_constant)
    }

    /// Checks if a variable has a symbolic (non-constant) value.
    #[must_use]
    pub fn is_symbolic(&self, var: SsaVarId) -> bool {
        self.values.get(&var).is_some_and(|e| !e.is_constant())
    }

    /// Checks if a variable is unknown (not in the values map).
    #[must_use]
    pub fn is_unknown(&self, var: SsaVarId) -> bool {
        !self.values.contains_key(&var)
    }

    /// Returns all tracked values as expressions.
    #[must_use]
    pub fn values(&self) -> &HashMap<SsaVarId, SymbolicExpr> {
        &self.values
    }

    /// Returns all concrete values as a map of i64 values.
    ///
    /// This is useful for compatibility with code that expects `HashMap<SsaVarId, i64>`.
    /// Values that can't be converted to i64 are skipped.
    #[must_use]
    pub fn concrete_values(&self) -> HashMap<SsaVarId, i64> {
        self.values
            .iter()
            .filter_map(|(k, v)| v.as_i64().map(|c| (*k, c)))
            .collect()
    }

    /// Returns all concrete values as typed `ConstValue`.
    #[must_use]
    pub fn const_values(&self) -> HashMap<SsaVarId, ConstValue> {
        self.values
            .iter()
            .filter_map(|(k, v)| v.as_constant().map(|c| (*k, c.clone())))
            .collect()
    }

    /// Clears all tracked values.
    pub fn clear(&mut self) {
        self.values.clear();
        self.predecessor = None;
        self.constraints.clear();
    }

    // Constraint Management

    /// Adds a constraint on a variable.
    ///
    /// If the constraint is an equality constraint, also sets the variable's value
    /// to concrete. This allows constraint propagation to directly affect evaluation.
    pub fn add_constraint(&mut self, var: SsaVarId, constraint: Constraint) {
        // If it's an equality constraint, we can directly set the value
        if let Constraint::Equal(ref v) = constraint {
            self.values.insert(var, SymbolicExpr::constant(v.clone()));
        }

        self.constraints.entry(var).or_default().push(constraint);
    }

    /// Gets all constraints on a variable.
    #[must_use]
    pub fn constraints(&self, var: SsaVarId) -> &[Constraint] {
        self.constraints.get(&var).map_or(&[], |v| v.as_slice())
    }

    /// Checks if a variable has any constraints.
    #[must_use]
    pub fn has_constraints(&self, var: SsaVarId) -> bool {
        self.constraints.get(&var).is_some_and(|v| !v.is_empty())
    }

    /// Clears constraints for a specific variable.
    pub fn clear_constraints(&mut self, var: SsaVarId) {
        self.constraints.remove(&var);
    }

    /// Applies constraints derived from taking a specific branch.
    ///
    /// When we know which branch was taken, we can derive facts about the condition
    /// variable. For example, if we took the true branch of `if (ceq x, 5)`, we know x == 5.
    ///
    /// # Arguments
    ///
    /// * `condition` - The variable used as the branch condition
    /// * `took_true_branch` - Whether we followed the true or false branch
    ///
    /// # Returns
    ///
    /// `true` if constraints were successfully derived, `false` otherwise.
    pub fn apply_branch_constraint(&mut self, condition: SsaVarId, took_true_branch: bool) -> bool {
        // Find the definition of the condition variable to understand what comparison it represents
        let Some(ssa_var) = self.ssa.variable(condition) else {
            return false;
        };

        let def_site = ssa_var.def_site();
        let Some(block) = self.ssa.block(def_site.block) else {
            return false;
        };

        let Some(instr_idx) = def_site.instruction else {
            return false;
        };

        let Some(instr) = block.instruction(instr_idx) else {
            return false;
        };

        self.derive_constraints_from_comparison(instr.op(), took_true_branch)
    }

    /// Derives constraints from a comparison operation.
    fn derive_constraints_from_comparison(&mut self, op: &SsaOp, took_true_branch: bool) -> bool {
        match op {
            SsaOp::Ceq { left, right, .. } => {
                // ceq: true branch means left == right, false means left != right
                let left_val = self.get(*left).cloned();
                let right_val = self.get(*right).cloned();

                if took_true_branch {
                    // left == right
                    match (&left_val, &right_val) {
                        (Some(l), None) => {
                            if let Some(v) = l.as_constant() {
                                self.add_constraint(*right, Constraint::Equal(v.clone()));
                                true
                            } else {
                                false
                            }
                        }
                        (None, Some(r)) => {
                            if let Some(v) = r.as_constant() {
                                self.add_constraint(*left, Constraint::Equal(v.clone()));
                                true
                            } else {
                                false
                            }
                        }
                        (Some(l), Some(r)) if l.as_constant() == r.as_constant() => {
                            // Both concrete and equal - constraint is satisfied
                            true
                        }
                        _ => false,
                    }
                } else {
                    // left != right
                    match (&left_val, &right_val) {
                        (Some(l), None) => {
                            if let Some(v) = l.as_constant() {
                                self.add_constraint(*right, Constraint::NotEqual(v.clone()));
                                true
                            } else {
                                false
                            }
                        }
                        (None, Some(r)) => {
                            if let Some(v) = r.as_constant() {
                                self.add_constraint(*left, Constraint::NotEqual(v.clone()));
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                }
            }

            SsaOp::Cgt {
                left,
                right,
                unsigned,
                ..
            } => {
                // cgt: true branch means left > right
                let right_val = self.get(*right).and_then(|e| e.as_constant().cloned());

                if took_true_branch {
                    // left > right
                    if let Some(v) = right_val {
                        if *unsigned {
                            self.add_constraint(*left, Constraint::GreaterThanUnsigned(v));
                        } else {
                            self.add_constraint(*left, Constraint::GreaterThan(v));
                        }
                        return true;
                    }
                } else {
                    // left <= right
                    if let Some(v) = right_val {
                        self.add_constraint(*left, Constraint::LessOrEqual(v));
                        return true;
                    }
                }
                false
            }

            SsaOp::Clt {
                left,
                right,
                unsigned,
                ..
            } => {
                // clt: true branch means left < right
                let right_val = self.get(*right).and_then(|e| e.as_constant().cloned());

                if took_true_branch {
                    // left < right
                    if let Some(v) = right_val {
                        if *unsigned {
                            self.add_constraint(*left, Constraint::LessThanUnsigned(v));
                        } else {
                            self.add_constraint(*left, Constraint::LessThan(v));
                        }
                        return true;
                    }
                } else {
                    // left >= right
                    if let Some(v) = right_val {
                        self.add_constraint(*left, Constraint::GreaterOrEqual(v));
                        return true;
                    }
                }
                false
            }

            _ => false,
        }
    }

    /// Checks if the current constraints imply that a condition is always true or false.
    ///
    /// This is useful for detecting dead code after branch conditions.
    ///
    /// # Returns
    ///
    /// - `Some(true)` if the condition is always true given current constraints
    /// - `Some(false)` if the condition is always false given current constraints
    /// - `None` if the condition cannot be determined
    #[must_use]
    pub fn evaluate_condition_with_constraints(&self, condition: SsaVarId) -> Option<bool> {
        if let Some(v) = self.get_concrete(condition) {
            return Some(!v.is_zero());
        }

        // Check if constraints imply a value
        // For now, we handle the case where we have conflicting constraints
        // which would indicate dead code
        let ssa_var = self.ssa.variable(condition)?;
        let def_site = ssa_var.def_site();
        let block = self.ssa.block(def_site.block)?;
        let instr_idx = def_site.instruction?;
        let instr = block.instruction(instr_idx)?;
        self.check_condition_against_constraints(instr.op())
    }

    /// Checks if a comparison's result can be determined from constraints.
    fn check_condition_against_constraints(&self, op: &SsaOp) -> Option<bool> {
        match op {
            SsaOp::Ceq { left, right, .. } => {
                // Check if we know both operands are equal or not equal
                let left_constraints = self.constraints(*left);
                let right_val = self.get_concrete(*right)?;

                for constraint in left_constraints {
                    match constraint {
                        Constraint::Equal(v) => {
                            // v == right_val means ceq is true
                            return Some(v.ceq(right_val).is_some_and(|r| !r.is_zero()));
                        }
                        Constraint::NotEqual(v) => {
                            // If v == right_val, then left != right_val, so ceq is false
                            if v.ceq(right_val).is_some_and(|r| !r.is_zero()) {
                                return Some(false);
                            }
                        }
                        Constraint::GreaterThan(v) => {
                            // left > v, so if right_val <= v, then left != right_val
                            if right_val.cgt(v).is_none_or(|r| r.is_zero()) {
                                return Some(false);
                            }
                        }
                        Constraint::LessThan(v) => {
                            // left < v, so if right_val >= v, then left != right_val
                            if right_val.clt(v).is_none_or(|r| r.is_zero()) {
                                return Some(false);
                            }
                        }
                        _ => {}
                    }
                }
                None
            }

            SsaOp::Cgt { left, right, .. } => {
                let left_constraints = self.constraints(*left);
                let right_val = self.get_concrete(*right)?;

                for constraint in left_constraints {
                    match constraint {
                        Constraint::GreaterThan(v) => {
                            // left > v, so if v >= right_val, then left > right_val
                            if v.clt(right_val).is_none_or(|r| r.is_zero()) {
                                return Some(true);
                            }
                        }
                        Constraint::LessOrEqual(v) => {
                            // left <= v, so if v <= right_val, then left <= right_val
                            if v.cgt(right_val).is_none_or(|r| r.is_zero()) {
                                return Some(false);
                            }
                        }
                        Constraint::LessThan(v) => {
                            // left < v, so if v <= right_val, then left < right_val <= right_val
                            if v.cgt(right_val).is_none_or(|r| r.is_zero()) {
                                return Some(false);
                            }
                        }
                        Constraint::Equal(v) => {
                            // left == v, so return v > right_val
                            return Some(v.cgt(right_val).is_some_and(|r| !r.is_zero()));
                        }
                        _ => {}
                    }
                }
                None
            }

            SsaOp::Clt { left, right, .. } => {
                let left_constraints = self.constraints(*left);
                let right_val = self.get_concrete(*right)?;

                for constraint in left_constraints {
                    match constraint {
                        Constraint::LessThan(v) => {
                            // left < v, so if v <= right_val, then left < right_val
                            if v.cgt(right_val).is_none_or(|r| r.is_zero()) {
                                return Some(true);
                            }
                        }
                        Constraint::GreaterOrEqual(v) => {
                            // left >= v, so if v >= right_val, then left >= right_val
                            if v.clt(right_val).is_none_or(|r| r.is_zero()) {
                                return Some(false);
                            }
                        }
                        Constraint::GreaterThan(v) => {
                            // left > v, so if v >= right_val, then left > right_val >= right_val
                            if v.clt(right_val).is_none_or(|r| r.is_zero()) {
                                return Some(false);
                            }
                        }
                        Constraint::Equal(v) => {
                            // left == v, so return v < right_val
                            return Some(v.clt(right_val).is_some_and(|r| !r.is_zero()));
                        }
                        _ => {}
                    }
                }
                None
            }

            _ => None,
        }
    }

    // Path-Aware Evaluation

    /// Sets the predecessor block for path-aware phi evaluation.
    ///
    /// When evaluating a block, phi nodes will select the operand that
    /// corresponds to this predecessor. This enables accurate evaluation
    /// when following a specific path through the CFG.
    ///
    /// # Arguments
    ///
    /// * `pred` - The predecessor block index, or `None` to clear.
    pub fn set_predecessor(&mut self, pred: Option<usize>) {
        self.predecessor = pred;
    }

    /// Gets the current predecessor for phi evaluation.
    #[must_use]
    pub fn predecessor(&self) -> Option<usize> {
        self.predecessor
    }

    // Block Evaluation

    /// Evaluates all phi nodes in a block.
    ///
    /// **REQUIRES** a predecessor to be set via [`set_predecessor`](Self::set_predecessor).
    /// If no predecessor is set, phi results will be `None` (removed from value map).
    ///
    /// # Phi Node Semantics
    ///
    /// Phi nodes execute "simultaneously" - all source values are read BEFORE any
    /// results are written. This is critical for correct swap semantics:
    ///
    /// ```text
    /// v1 = phi(v2 from pred)
    /// v2 = phi(v1 from pred)
    /// ```
    ///
    /// This swaps v1 and v2. If we wrote v1 before reading for v2, we'd get the
    /// wrong value. The implementation uses a two-phase approach:
    /// 1. Read all source values into a temporary buffer
    /// 2. Write all results from the buffer
    pub fn evaluate_phis(&mut self, block_idx: usize) {
        let Some(block) = self.ssa.block(block_idx) else {
            return;
        };

        // Phase 1: Read all phi source values BEFORE any writes
        // This ensures correct "simultaneous" phi semantics (no swap problem)
        let phi_results: Vec<(SsaVarId, Option<SymbolicExpr>)> = block
            .phi_nodes()
            .iter()
            .map(|phi| {
                let result = phi.result();
                // REQUIRE predecessor - no fallback, no merging
                let value = self.predecessor.and_then(|pred| {
                    phi.operands()
                        .iter()
                        .find(|op| op.predecessor() == pred)
                        .and_then(|op| self.values.get(&op.value()).cloned())
                });
                (result, value)
            })
            .collect();

        // Phase 2: Write all results
        for (result, value) in phi_results {
            if let Some(v) = value {
                self.values.insert(result, v);
            } else {
                // No predecessor or no operand from predecessor = no value
                self.values.remove(&result);
            }
        }
    }

    /// Evaluates all instructions in a block, updating tracked values.
    ///
    /// This evaluates phi nodes first (if predecessor is set), then
    /// evaluates all other instructions in order.
    pub fn evaluate_block(&mut self, block_idx: usize) {
        // Record path if tracking is enabled
        if self.config.track_path {
            self.path.push(block_idx);
        }

        // First evaluate phi nodes
        self.evaluate_phis(block_idx);

        // Then evaluate instructions
        let Some(block) = self.ssa.block(block_idx) else {
            return;
        };

        for instr in block.instructions() {
            self.evaluate_op(instr.op());
        }
    }

    /// Evaluates a sequence of blocks in order.
    ///
    /// This is useful for evaluating a path through the CFG.
    /// Note: This does not set predecessors automatically.
    pub fn evaluate_blocks(&mut self, block_indices: &[usize]) {
        for &block_idx in block_indices {
            self.evaluate_block(block_idx);
        }
    }

    /// Evaluates a sequence of blocks along a path.
    ///
    /// For each block after the first, sets the predecessor to the previous
    /// block before evaluation. This enables accurate phi node evaluation.
    pub fn evaluate_path(&mut self, path: &[usize]) {
        for (i, &block_idx) in path.iter().enumerate() {
            if i > 0 {
                self.set_predecessor(Some(path[i - 1]));
            }
            self.evaluate_block(block_idx);
        }
    }

    // Fixed-Point Iteration for Loops

    /// Evaluates a loop until values reach a fixed point.
    ///
    /// This is useful for analyzing loops where variable values may change each
    /// iteration until they stabilize. The method iterates up to `max_iterations`
    /// times, or until all tracked values stop changing.
    ///
    /// # Arguments
    ///
    /// * `loop_blocks` - The blocks that form the loop body (in execution order)
    /// * `max_iterations` - Maximum number of iterations before giving up
    ///
    /// # Returns
    ///
    /// The number of iterations performed before reaching fixed point (or max).
    pub fn evaluate_loop_to_fixpoint(
        &mut self,
        loop_blocks: &[usize],
        max_iterations: usize,
    ) -> usize {
        if loop_blocks.is_empty() {
            return 0;
        }

        for iteration in 0..max_iterations {
            // Snapshot current values
            let snapshot: HashMap<SsaVarId, SymbolicExpr> = self.values.clone();

            // Evaluate all loop blocks
            for (i, &block_idx) in loop_blocks.iter().enumerate() {
                if i > 0 {
                    self.set_predecessor(Some(loop_blocks[i - 1]));
                } else if loop_blocks.len() > 1 {
                    // First block - predecessor is the last block (loop back edge)
                    self.set_predecessor(Some(loop_blocks[loop_blocks.len() - 1]));
                }
                self.evaluate_block(block_idx);
            }

            // Check if values changed
            if self.values_match(&snapshot) {
                return iteration + 1;
            }
        }

        // Didn't reach fixed point - mark variables that changed as widened
        self.widen_unstable_values(loop_blocks);
        max_iterations
    }

    /// Checks if current values match a snapshot.
    fn values_match(&self, snapshot: &HashMap<SsaVarId, SymbolicExpr>) -> bool {
        if self.values.len() != snapshot.len() {
            return false;
        }

        for (var, value) in &self.values {
            match snapshot.get(var) {
                Some(old_value) => {
                    // Compare expressions
                    match (value.as_constant(), old_value.as_constant()) {
                        (Some(a), Some(b)) => {
                            if a != b {
                                return false;
                            }
                        }
                        (None, None) => {
                            // For symbolic, compare by structure (simple equality check)
                            if format!("{value}") != format!("{old_value}") {
                                return false;
                            }
                        }
                        _ => return false, // One constant, one symbolic
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// Widens values that didn't stabilize in a loop to Unknown.
    ///
    /// This is called when fixed-point iteration doesn't converge. Variables
    /// defined in loop blocks that still have different values are marked Unknown.
    fn widen_unstable_values(&mut self, loop_blocks: &[usize]) {
        // Find all variables defined in the loop
        for &block_idx in loop_blocks {
            let Some(block) = self.ssa.block(block_idx) else {
                continue;
            };

            // Mark phi results as unknown (they depend on loop iteration)
            for phi in block.phi_nodes() {
                self.values.remove(&phi.result());
            }

            // Check instructions for variables that might not have stabilized
            for instr in block.instructions() {
                // If this op defines a variable, consider widening it
                if let Some(dest) = instr.op().dest() {
                    // Keep concrete values if they're stable, widen symbolic to unknown
                    if let Some(expr) = self.values.get(&dest) {
                        if !expr.is_constant() {
                            // Symbolic values that didn't stabilize become unknown
                            self.values.remove(&dest);
                        }
                    }
                }
            }
        }
    }

    /// Evaluates a loop with a specific iteration count.
    ///
    /// This is useful when you know exactly how many times a loop should run
    /// (e.g., from a constant loop bound).
    pub fn evaluate_loop_iterations(&mut self, loop_blocks: &[usize], iterations: usize) {
        for _ in 0..iterations {
            for (i, &block_idx) in loop_blocks.iter().enumerate() {
                if i > 0 {
                    self.set_predecessor(Some(loop_blocks[i - 1]));
                }
                self.evaluate_block(block_idx);
            }
        }
    }

    /// Evaluates a single SSA operation, updating tracked values.
    ///
    /// Returns the computed expression for operations that produce a result,
    /// or `None` for operations without results (stores, branches, etc.) or
    /// when the result is unknown.
    pub fn evaluate_op(&mut self, op: &SsaOp) -> Option<SymbolicExpr> {
        match op {
            SsaOp::Const { dest, value } => {
                let expr = SymbolicExpr::constant(value.clone());
                self.values.insert(*dest, expr.clone());
                Some(expr)
            }

            SsaOp::Copy { dest, src } => {
                let value = self.values.get(src).cloned();
                if let Some(v) = value {
                    self.values.insert(*dest, v.clone());
                    Some(v)
                } else {
                    self.values.remove(dest);
                    None
                }
            }

            SsaOp::Add { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::Add)
            }

            SsaOp::Sub { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::Sub)
            }

            SsaOp::Mul { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::Mul)
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
                self.eval_binary_op(*dest, *left, *right, op)
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
                self.eval_binary_op(*dest, *left, *right, op)
            }

            SsaOp::Xor { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::Xor)
            }

            SsaOp::And { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::And)
            }

            SsaOp::Or { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::Or)
            }

            SsaOp::Shl {
                dest,
                value,
                amount,
            } => self.eval_binary_op(*dest, *value, *amount, SymbolicOp::Shl),

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
                self.eval_binary_op(*dest, *value, *amount, op)
            }

            SsaOp::Neg { dest, operand } => self.eval_unary_op(*dest, *operand, SymbolicOp::Neg),

            SsaOp::Not { dest, operand } => self.eval_unary_op(*dest, *operand, SymbolicOp::Not),

            SsaOp::Ceq { dest, left, right } => {
                self.eval_binary_op(*dest, *left, *right, SymbolicOp::Eq)
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
                self.eval_binary_op(*dest, *left, *right, op)
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
                self.eval_binary_op(*dest, *left, *right, op)
            }

            SsaOp::Conv {
                dest,
                operand,
                target,
                unsigned,
                ..
            } => {
                let value = self.values.get(operand).cloned();
                if let Some(expr) = value {
                    if let Some(v) = expr.as_i64() {
                        // Apply proper truncation/extension and store with correct type
                        let converted = self.apply_conversion(v, target, *unsigned);
                        let result = SymbolicExpr::constant(converted);
                        self.values.insert(*dest, result.clone());
                        Some(result)
                    } else {
                        // Symbolic/Unknown pass through (conversions don't change symbolic structure)
                        self.values.insert(*dest, expr.clone());
                        Some(expr)
                    }
                } else {
                    self.values.remove(dest);
                    None
                }
            }

            // Operations with Option<SsaVarId> dest that produce unknown results
            SsaOp::Call { dest, .. }
            | SsaOp::CallVirt { dest, .. }
            | SsaOp::CallIndirect { dest, .. } => {
                if let Some(d) = dest {
                    self.values.remove(d);
                }
                None
            }

            // Memory operations (when tracking is enabled)
            SsaOp::LoadStaticField { dest, field } => {
                if self.config.track_memory {
                    let location = MemoryLocation::StaticField(*field);
                    if let Some(stored_var) = self.memory.load(&location) {
                        // Propagate the stored value
                        if let Some(expr) = self.values.get(&stored_var).cloned() {
                            self.values.insert(*dest, expr.clone());
                            return Some(expr);
                        }
                        self.values
                            .insert(*dest, SymbolicExpr::variable(stored_var));
                        return Some(SymbolicExpr::variable(stored_var));
                    }
                }
                self.values.remove(dest);
                None
            }

            SsaOp::StoreStaticField { value, field } => {
                if self.config.track_memory {
                    let location = MemoryLocation::StaticField(*field);
                    // Use 0 as version for simple tracking (version not critical for evaluation)
                    self.memory.store(location, *value, 0);
                }
                None
            }

            SsaOp::LoadField {
                dest,
                object,
                field,
            } => {
                if self.config.track_memory {
                    let location = MemoryLocation::InstanceField(*object, *field);
                    if let Some(stored_var) = self.memory.load(&location) {
                        if let Some(expr) = self.values.get(&stored_var).cloned() {
                            self.values.insert(*dest, expr.clone());
                            return Some(expr);
                        }
                        self.values
                            .insert(*dest, SymbolicExpr::variable(stored_var));
                        return Some(SymbolicExpr::variable(stored_var));
                    }
                }
                self.values.remove(dest);
                None
            }

            SsaOp::StoreField {
                object,
                field,
                value,
            } => {
                if self.config.track_memory {
                    let location = MemoryLocation::InstanceField(*object, *field);
                    self.memory.store(location, *value, 0);
                }
                None
            }

            // Operations with SsaVarId dest that produce unknown results
            SsaOp::NewObj { dest, .. }
            | SsaOp::NewArr { dest, .. }
            | SsaOp::LoadElement { dest, .. }
            | SsaOp::LoadIndirect { dest, .. }
            | SsaOp::Box { dest, .. }
            | SsaOp::Unbox { dest, .. }
            | SsaOp::UnboxAny { dest, .. }
            | SsaOp::CastClass { dest, .. }
            | SsaOp::IsInst { dest, .. }
            | SsaOp::ArrayLength { dest, .. }
            | SsaOp::LoadArgAddr { dest, .. }
            | SsaOp::LoadLocalAddr { dest, .. }
            | SsaOp::LoadToken { dest, .. }
            | SsaOp::SizeOf { dest, .. }
            | SsaOp::Ckfinite { dest, .. }
            | SsaOp::LocalAlloc { dest, .. }
            | SsaOp::LoadFunctionPtr { dest, .. }
            | SsaOp::LoadVirtFunctionPtr { dest, .. }
            | SsaOp::LoadFieldAddr { dest, .. }
            | SsaOp::LoadStaticFieldAddr { dest, .. }
            | SsaOp::LoadElementAddr { dest, .. }
            | SsaOp::LoadObj { dest, .. } => {
                self.values.remove(dest);
                None
            }

            // Operations without results (stores, branches, etc.)
            _ => None,
        }
    }

    /// Helper to evaluate a binary operation.
    fn eval_binary_op(
        &mut self,
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        op: SymbolicOp,
    ) -> Option<SymbolicExpr> {
        let left_expr = self.values.get(&left)?;
        let right_expr = self.values.get(&right)?;

        // Build expression and simplify (handles constant folding automatically)
        let result = SymbolicExpr::binary(op, left_expr.clone(), right_expr.clone())
            .simplify(self.pointer_size);

        // Mask native int/uint results to target pointer width
        let result = self.mask_symbolic_native(result);

        self.values.insert(dest, result.clone());
        Some(result)
    }

    /// Helper to evaluate a unary operation.
    fn eval_unary_op(
        &mut self,
        dest: SsaVarId,
        operand: SsaVarId,
        op: SymbolicOp,
    ) -> Option<SymbolicExpr> {
        let operand_expr = self.values.get(&operand)?;

        // Build expression and simplify
        let result = SymbolicExpr::unary(op, operand_expr.clone()).simplify(self.pointer_size);

        // Mask native int/uint results to target pointer width
        let result = self.mask_symbolic_native(result);

        self.values.insert(dest, result.clone());
        Some(result)
    }

    /// Masks a `SymbolicExpr` constant to the target pointer width if it contains
    /// a `NativeInt` or `NativeUInt` value.
    fn mask_symbolic_native(&self, expr: SymbolicExpr) -> SymbolicExpr {
        if let Some(cv) = expr.as_constant() {
            match cv {
                ConstValue::NativeInt(_) | ConstValue::NativeUInt(_) => {
                    SymbolicExpr::constant(cv.clone().mask_native(self.pointer_size))
                }
                _ => expr,
            }
        } else {
            expr
        }
    }

    /// Applies a CIL type conversion to a value, returning the properly typed ConstValue.
    ///
    /// This handles truncation and sign/zero extension according to ECMA-335 semantics,
    /// and returns a ConstValue with the correct type variant.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    fn apply_conversion(&self, value: i64, target: &SsaType, unsigned: bool) -> ConstValue {
        match target {
            SsaType::I8 => {
                if unsigned {
                    ConstValue::I8((value as u8) as i8)
                } else {
                    ConstValue::I8(value as i8)
                }
            }
            SsaType::U8 | SsaType::Bool => ConstValue::U8(value as u8),
            SsaType::I16 => {
                if unsigned {
                    ConstValue::I16((value as u16) as i16)
                } else {
                    ConstValue::I16(value as i16)
                }
            }
            SsaType::U16 => ConstValue::U16(value as u16),
            SsaType::I32 => {
                if unsigned {
                    ConstValue::I32((value as u32) as i32)
                } else {
                    ConstValue::I32(value as i32)
                }
            }
            SsaType::U32 => ConstValue::U32(value as u32),
            SsaType::NativeInt => match self.pointer_size {
                PointerSize::Bit32 => {
                    if unsigned {
                        ConstValue::NativeInt(i64::from((value as u32) as i32))
                    } else {
                        ConstValue::NativeInt(i64::from(value as i32))
                    }
                }
                PointerSize::Bit64 => ConstValue::NativeInt(value),
            },
            SsaType::NativeUInt => match self.pointer_size {
                PointerSize::Bit32 => ConstValue::NativeUInt(u64::from(value as u32)),
                PointerSize::Bit64 => ConstValue::NativeUInt(value as u64),
            },
            SsaType::U64 => ConstValue::U64(value as u64),
            // Safe: precision loss is acceptable for integer-to-float conversion
            #[allow(clippy::cast_precision_loss)]
            SsaType::F32 => {
                let float_val = if unsigned {
                    (value as u64) as f32
                } else {
                    value as f32
                };
                ConstValue::F32(float_val)
            }
            // Safe: precision loss is acceptable for integer-to-float conversion
            #[allow(clippy::cast_precision_loss)]
            SsaType::F64 => {
                let float_val = if unsigned {
                    (value as u64) as f64
                } else {
                    value as f64
                };
                ConstValue::F64(float_val)
            }
            // For other types, default to I64
            _ => ConstValue::I64(value),
        }
    }

    /// Tries to resolve a variable's value by tracing back through its definition.
    ///
    /// This is useful when a variable's value depends on earlier computations
    /// that haven't been evaluated yet. It recursively evaluates dependencies.
    ///
    /// # Arguments
    ///
    /// * `var` - The variable to resolve
    /// * `max_depth` - Maximum recursion depth to prevent infinite loops
    pub fn resolve_with_trace(&mut self, var: SsaVarId, max_depth: usize) -> Option<SymbolicExpr> {
        // Already known?
        if let Some(v) = self.values.get(&var) {
            return Some(v.clone());
        }

        if max_depth == 0 {
            return None;
        }

        // Find the definition of this variable
        let ssa_var = self.ssa.variable(var)?;
        let def_site = ssa_var.def_site();
        let block = self.ssa.block(def_site.block)?;
        // Is it defined by a phi node? Without path context, it's unknown
        let instr_idx = def_site.instruction?;
        let instr = block.instruction(instr_idx)?;
        let op = instr.op();

        // Recursively resolve operands first
        for operand in op.uses() {
            if !self.values.contains_key(&operand) {
                if let Some(resolved) = self.resolve_with_trace(operand, max_depth - 1) {
                    self.values.insert(operand, resolved);
                }
            }
        }

        // Now evaluate this operation
        self.evaluate_op(op)
    }

    /// Tries to evaluate a variable by tracing back through its definition.
    ///
    /// Alias for [`resolve_with_trace`](Self::resolve_with_trace) that returns
    /// `Option<i64>` for API compatibility.
    pub fn evaluate_with_trace(&mut self, var: SsaVarId, max_depth: usize) -> Option<i64> {
        self.resolve_with_trace(var, max_depth)
            .and_then(|e| e.as_i64())
    }

    /// Determines the next block to execute based on the terminator of the given block.
    ///
    /// This is the core method for control flow analysis. It evaluates the terminating
    /// instruction of a block and determines which block(s) execution should continue to.
    ///
    /// # Returns
    ///
    /// - `ControlFlow::Continue(block)` - Continue to the specified block
    /// - `ControlFlow::Terminal` - No successor (return, throw, etc.)
    /// - `ControlFlow::Unknown` - Cannot determine (condition is unknown/symbolic)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
    /// eval.set_concrete(state_var, initial_state);
    /// eval.evaluate_block(0);
    ///
    /// match eval.next_block(0) {
    ///     ControlFlow::Continue(next) => { /* continue to next */ }
    ///     ControlFlow::Terminal => { /* execution ends */ }
    ///     ControlFlow::Unknown => { /* cannot determine */ }
    /// }
    /// ```
    #[must_use]
    pub fn next_block(&self, block_idx: usize) -> ControlFlow {
        let Some(block) = self.ssa.block(block_idx) else {
            return ControlFlow::Unknown;
        };

        // Find the terminating instruction
        let terminator = block
            .instructions()
            .iter()
            .rev()
            .find(|instr| instr.op().is_terminator());

        let Some(instr) = terminator else {
            // No terminator - fall through to next block if it exists
            let next_idx = block_idx + 1;
            if next_idx < self.ssa.block_count() {
                return ControlFlow::Continue(next_idx);
            }
            return ControlFlow::Unknown;
        };

        self.evaluate_control_flow(instr.op())
    }

    /// Evaluates a control flow operation to determine the next block.
    ///
    /// Uses typed `ConstValue` operations for comparisons and truthiness checks.
    fn evaluate_control_flow(&self, op: &SsaOp) -> ControlFlow {
        match op {
            // Unconditional jumps
            SsaOp::Jump { target } | SsaOp::Leave { target } => ControlFlow::Continue(*target),

            // Conditional branch (bool condition)
            SsaOp::Branch {
                condition,
                true_target,
                false_target,
            } => match self.get_concrete(*condition) {
                Some(v) => {
                    // Non-zero is true in CIL
                    if v.is_zero() {
                        ControlFlow::Continue(*false_target)
                    } else {
                        ControlFlow::Continue(*true_target)
                    }
                }
                None => ControlFlow::Unknown,
            },

            // Compare and branch
            SsaOp::BranchCmp {
                left,
                right,
                cmp,
                unsigned,
                true_target,
                false_target,
            } => {
                let left_val = self.get_concrete(*left);
                let right_val = self.get_concrete(*right);

                match (left_val, right_val) {
                    (Some(l), Some(r)) => {
                        let result = Self::evaluate_comparison(l, r, *cmp, *unsigned);
                        if result {
                            ControlFlow::Continue(*true_target)
                        } else {
                            ControlFlow::Continue(*false_target)
                        }
                    }
                    _ => ControlFlow::Unknown,
                }
            }

            // Switch - needs a non-negative integer index
            SsaOp::Switch {
                value,
                targets,
                default,
            } => match self.get_concrete(*value).and_then(ConstValue::as_u64) {
                Some(v) => {
                    #[allow(clippy::cast_possible_truncation)]
                    let idx = v as usize;
                    if idx < targets.len() {
                        ControlFlow::Continue(targets[idx])
                    } else {
                        ControlFlow::Continue(*default)
                    }
                }
                None => ControlFlow::Unknown,
            },

            // Terminal instructions
            SsaOp::Return { .. }
            | SsaOp::Throw { .. }
            | SsaOp::Rethrow
            | SsaOp::EndFinally
            | SsaOp::EndFilter { .. } => ControlFlow::Terminal,

            // Not a control flow operation
            _ => ControlFlow::Unknown,
        }
    }

    /// Evaluates a comparison between two typed constant values.
    ///
    /// Uses the typed comparison methods on `ConstValue` which properly
    /// handle signedness based on the operand types.
    fn evaluate_comparison(
        left: &ConstValue,
        right: &ConstValue,
        cmp: CmpKind,
        unsigned: bool,
    ) -> bool {
        match cmp {
            CmpKind::Eq => left.ceq(right).is_some_and(|v| !v.is_zero()),
            CmpKind::Ne => left.ceq(right).is_some_and(|v| v.is_zero()),
            CmpKind::Lt => if unsigned {
                left.clt_un(right)
            } else {
                left.clt(right)
            }
            .is_some_and(|v| !v.is_zero()),
            CmpKind::Le => {
                // x <= y is !(x > y)
                if unsigned {
                    left.cgt_un(right)
                } else {
                    left.cgt(right)
                }
                .is_some_and(|v| v.is_zero())
            }
            CmpKind::Gt => if unsigned {
                left.cgt_un(right)
            } else {
                left.cgt(right)
            }
            .is_some_and(|v| !v.is_zero()),
            CmpKind::Ge => {
                // x >= y is !(x < y)
                if unsigned {
                    left.clt_un(right)
                } else {
                    left.clt(right)
                }
                .is_some_and(|v| v.is_zero())
            }
        }
    }

    /// Executes the SSA function starting from a given block and records the trace.
    ///
    /// This method steps through the SSA, evaluating each block and following
    /// control flow decisions based on computed values. It records the sequence
    /// of blocks visited and optionally captures state values at each step.
    ///
    /// # Arguments
    ///
    /// * `start_block` - The block to start execution from
    /// * `state_var` - Optional variable to capture state values (for CFF analysis)
    /// * `max_steps` - Maximum number of blocks to visit (prevents infinite loops)
    ///
    /// # Returns
    ///
    /// An [`ExecutionTrace`] containing the visited blocks and state values.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
    /// eval.set_concrete(state_var, initial_state);
    ///
    /// let trace = eval.execute(0, Some(state_var), 1000);
    /// for (block, state) in trace.blocks().iter().zip(trace.states()) {
    ///     println!("Block {}: state = {:?}", block, state);
    /// }
    /// ```
    pub fn execute(
        &mut self,
        start_block: usize,
        state_var: Option<SsaVarId>,
        max_steps: usize,
    ) -> ExecutionTrace {
        let mut trace = ExecutionTrace::new(max_steps);
        let mut current_block = start_block;

        loop {
            // Check if we've hit the limit
            if trace.hit_limit() {
                break;
            }

            // Record the current state before evaluation
            let state = state_var.and_then(|v| self.get_concrete(v).cloned());
            trace.record_block(current_block, state);

            // Set predecessor for phi evaluation
            if let Some(prev) = trace.blocks().iter().rev().nth(1) {
                self.set_predecessor(Some(*prev));
            }

            // Evaluate the block
            self.evaluate_block(current_block);

            // Determine next block
            match self.next_block(current_block) {
                ControlFlow::Continue(next) => {
                    current_block = next;
                }
                ControlFlow::Terminal => {
                    trace.mark_complete();
                    break;
                }
                ControlFlow::Unknown => {
                    // Can't determine next block - stop execution
                    break;
                }
            }
        }

        trace
    }

    /// Executes starting from block 0 with default settings.
    ///
    /// This is a convenience method for simple cases where you want to execute
    /// from the entry block without state tracking.
    pub fn execute_from_entry(&mut self, max_steps: usize) -> ExecutionTrace {
        self.execute(0, None, max_steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ssa::{PhiNode, PhiOperand, SsaBlock, SsaInstruction, VariableOrigin};
    use crate::analysis::{SsaFunctionBuilder, SsaType};

    #[test]
    fn test_const_evaluation() {
        let (ssa, v0) = {
            let mut v0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    v0_out = b.const_i32(42);
                    b.ret();
                });
            });
            (ssa, v0_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        assert_eq!(eval.get_concrete(v0).and_then(ConstValue::as_i32), Some(42));
    }

    #[test]
    fn test_add_evaluation() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(10);
                    let v1 = b.const_i32(32);
                    v2_out = b.add(v0, v1);
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        assert_eq!(eval.get_concrete(v2).and_then(ConstValue::as_i32), Some(42));
    }

    #[test]
    fn test_xor_mul_pattern() {
        // Test the typical ConfuserEx-style state computation:
        // next_state = (current_state * mul_const) ^ xor_const
        let (ssa, current_state, next_state) = {
            let mut current_state_out = SsaVarId::new();
            let mut next_state_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                // Use an argument as current_state (so it's "external" input)
                let current_state = f.arg(0);
                current_state_out = current_state;
                f.block(0, |b| {
                    let mul_const = b.const_i32(785121953);
                    let xor_const = b.const_i32(-934590555);
                    let mul_result = b.mul(current_state, mul_const);
                    next_state_out = b.xor(mul_result, xor_const);
                    b.ret();
                });
            });
            (ssa, current_state_out, next_state_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        // Set the input state (this would come from the dispatcher)
        eval.set_concrete(current_state, ConstValue::I32(120931986)); // The XORed state value

        eval.evaluate_block(0);

        // Verify we can compute the next state
        assert!(eval.get_concrete(next_state).is_some());
    }

    #[test]
    fn test_rem_un_evaluation() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(120931986); // Some large positive number
                    let v1 = b.const_i32(13);
                    v2_out = b.rem_un(v0, v1);
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        // 120931986 % 13 = 6
        assert_eq!(eval.get_concrete(v2).and_then(ConstValue::as_i32), Some(6));
    }

    #[test]
    fn test_wrapping_mul() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    // Test overflow wrapping
                    let v0 = b.const_i32(i32::MAX);
                    let v1 = b.const_i32(2);
                    v2_out = b.mul(v0, v1);
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        // Should wrap around
        assert_eq!(
            eval.get_concrete(v2).and_then(ConstValue::as_i32),
            Some(i32::MAX.wrapping_mul(2))
        );
    }

    #[test]
    fn test_comparison_ops() {
        let (ssa, ceq_result, clt_result, cgt_result) = {
            let mut ceq_out = SsaVarId::new();
            let mut clt_out = SsaVarId::new();
            let mut cgt_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(5);
                    let v1 = b.const_i32(10);
                    ceq_out = b.ceq(v0, v1);
                    clt_out = b.clt(v0, v1);
                    cgt_out = b.cgt(v0, v1);
                    b.ret();
                });
            });
            (ssa, ceq_out, clt_out, cgt_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        assert_eq!(
            eval.get_concrete(ceq_result).and_then(ConstValue::as_i32),
            Some(0)
        ); // 5 != 10
        assert_eq!(
            eval.get_concrete(clt_result).and_then(ConstValue::as_i32),
            Some(1)
        ); // 5 < 10
        assert_eq!(
            eval.get_concrete(cgt_result).and_then(ConstValue::as_i32),
            Some(0)
        ); // 5 !> 10
    }

    #[test]
    fn test_set_value_manual() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });
        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);

        let v0 = SsaVarId::new();
        eval.set_concrete(v0, ConstValue::I32(12345));

        assert_eq!(
            eval.get_concrete(v0).and_then(ConstValue::as_i32),
            Some(12345)
        );
        assert_eq!(
            eval.get_concrete(v0).and_then(ConstValue::as_i32),
            Some(12345)
        );
    }

    #[test]
    fn test_unknown_operand_returns_unknown() {
        let (ssa, v2) = {
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                // Use an argument as unknown variable (it won't have a value set)
                let unknown = f.arg(0);
                f.block(0, |b| {
                    let v1 = b.const_i32(10);
                    v2_out = b.add(unknown, v1);
                    b.ret();
                });
            });
            (ssa, v2_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        // Result should be unknown (not set)
        assert!(eval.is_unknown(v2));
        assert_eq!(eval.get_concrete(v2), None);
    }

    #[test]
    fn test_symbolic_evaluation() {
        let (ssa, arg0, v2) = {
            let mut arg0_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                arg0_out = f.arg(0);
                f.block(0, |b| {
                    let v1 = b.const_i32(10);
                    v2_out = b.add(arg0_out, v1);
                    b.ret();
                });
            });
            (ssa, arg0_out, v2_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        // Mark the argument as symbolic
        eval.set_symbolic(arg0, "arg0");
        eval.evaluate_block(0);

        // Result should be symbolic (arg0 + 10)
        assert!(eval.is_symbolic(v2));
        let expr = eval.get(v2).unwrap();
        // Check the expression contains our named variable
        assert!(format!("{}", expr).contains("arg0"));
    }

    #[test]
    fn test_xor_rem_pattern() {
        // Test the ConfuserEx-style dispatch computation:
        // switch_idx = (state ^ xor_const) % modulo
        let (ssa, state_var, result_var) = {
            let mut state_out = SsaVarId::new();
            let mut result_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                state_out = f.arg(0);
                f.block(0, |b| {
                    let xor_const = b.const_i32(-557527955);
                    let modulo = b.const_i32(13);
                    let xored = b.xor(state_out, xor_const);
                    result_out = b.rem_un(xored, modulo);
                    b.ret();
                });
            });
            (ssa, state_out, result_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        // Mark state as symbolic
        eval.set_symbolic(state_var, "state");
        eval.evaluate_block(0);

        // Result should be symbolic
        assert!(eval.is_symbolic(result_var));

        // Now with concrete value
        let mut eval2 = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval2.set_concrete(state_var, ConstValue::I32(-638481665_i32));
        eval2.evaluate_block(0);

        // Result should be concrete and correct
        assert!(eval2.is_concrete(result_var));
        assert_eq!(
            eval2.get_concrete(result_var).and_then(ConstValue::as_i32),
            Some(6)
        );
    }

    #[test]
    fn test_mixed_operations() {
        // Test: (arg0 * const1) ^ const2
        let (ssa, arg0, result) = {
            let mut arg0_out = SsaVarId::new();
            let mut result_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                arg0_out = f.arg(0);
                f.block(0, |b| {
                    let const1 = b.const_i32(785121953);
                    let const2 = b.const_i32(-934590555);
                    let mul_result = b.mul(arg0_out, const1);
                    result_out = b.xor(mul_result, const2);
                    b.ret();
                });
            });
            (ssa, arg0_out, result_out)
        };

        // With symbolic input
        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.set_symbolic(arg0, "state");
        eval.evaluate_block(0);
        assert!(eval.is_symbolic(result));

        // With concrete input - should produce concrete result
        let mut eval2 = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval2.set_concrete(arg0, ConstValue::I32(120931986));
        eval2.evaluate_block(0);
        assert!(eval2.is_concrete(result));
    }

    #[test]
    fn test_with_values_constructor() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let mut initial = HashMap::new();
        initial.insert(v0, ConstValue::I64(42));
        initial.insert(v1, ConstValue::I64(100));

        let eval = SsaEvaluator::with_values(&ssa, initial, PointerSize::Bit64);

        assert_eq!(eval.get_concrete(v0).and_then(ConstValue::as_i64), Some(42));
        assert_eq!(
            eval.get_concrete(v1).and_then(ConstValue::as_i64),
            Some(100)
        );
    }

    #[test]
    fn test_concrete_values_extraction() {
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                let arg0 = f.arg(0);
                v0_out = arg0;
                f.block(0, |b| {
                    v1_out = b.const_i32(42);
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.set_symbolic(v0, "arg0"); // symbolic
        eval.evaluate_block(0); // v1 = 42 (concrete)

        let concrete = eval.concrete_values();
        assert!(!concrete.contains_key(&v0)); // symbolic not included
        assert_eq!(concrete.get(&v1), Some(&42)); // concrete included
    }

    #[test]
    fn test_conversion_truncation() {
        // Test that conversions properly truncate values
        let (ssa, v1) = {
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(256); // Larger than byte
                    v1_out = b.conv_un(v0, SsaType::U8);
                    b.ret();
                });
            });
            (ssa, v1_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        // 256 truncated to u8 should be 0
        assert_eq!(eval.get_concrete(v1).and_then(ConstValue::as_i32), Some(0));
    }

    #[test]
    fn test_conversion_sign_extension() {
        // Test that signed conversions sign-extend
        let (ssa, v1) = {
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(255); // 0xFF as u8, -1 as i8
                    v1_out = b.conv(v0, SsaType::I8);
                    b.ret();
                });
            });
            (ssa, v1_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);

        // 255 as i8 is -1, sign-extended to i32
        assert_eq!(eval.get_concrete(v1).and_then(ConstValue::as_i32), Some(-1));
    }

    #[test]
    fn test_constraint_equal() {
        // Test that Equal constraint propagates value
        let (ssa, arg0) = {
            let mut arg0_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                arg0_out = f.arg(0);
                f.block(0, |b| {
                    b.ret();
                });
            });
            (ssa, arg0_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        assert!(eval.is_unknown(arg0));

        // Add equality constraint
        eval.add_constraint(arg0, Constraint::Equal(ConstValue::I32(42)));

        // Now we should know the value
        assert!(eval.is_concrete(arg0));
        assert_eq!(
            eval.get_concrete(arg0).and_then(ConstValue::as_i32),
            Some(42)
        );
    }

    #[test]
    fn test_constraint_conflicts() {
        // Test constraint conflict detection
        let c1 = Constraint::Equal(ConstValue::I32(5));
        let c2 = Constraint::Equal(ConstValue::I32(10));
        assert!(c1.conflicts_with(&c2, PointerSize::Bit64));

        let c3 = Constraint::NotEqual(ConstValue::I32(5));
        assert!(c1.conflicts_with(&c3, PointerSize::Bit64));

        let c4 = Constraint::GreaterThan(ConstValue::I32(5));
        assert!(c1.conflicts_with(&c4, PointerSize::Bit64)); // 5 is not > 5

        let c5 = Constraint::GreaterThan(ConstValue::I32(4));
        assert!(!c1.conflicts_with(&c5, PointerSize::Bit64)); // 5 > 4 is ok
    }

    #[test]
    fn test_evaluate_loop_to_fixpoint() {
        // Test loop fixed-point iteration with a simple loop structure:
        // B0: entry, jump to B1
        // B1: header with computation, branch to B2 or B3
        // B2: body, jump back to B1 (back edge)
        // B3: exit, ret

        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                // B0: entry with initial value
                f.block(0, |b| {
                    v0_out = b.const_i32(0);
                    b.jump(1);
                });
                // B1: header with conditional
                f.block(1, |b| {
                    // Increment the value (simulating an induction variable)
                    let one = b.const_i32(1);
                    v1_out = b.add(v0_out, one);
                    let cond = b.const_true();
                    b.branch(cond, 2, 3);
                });
                // B2: body, jump back
                f.block(2, |b| b.jump(1));
                // B3: exit
                f.block(3, |b| b.ret());
            });
            (ssa, v0_out, v1_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);

        // First evaluate entry block to establish initial values
        eval.evaluate_block(0);
        assert_eq!(eval.get_concrete(v0).and_then(ConstValue::as_i32), Some(0));

        // Now evaluate loop blocks with fixed-point iteration
        // Loop body is blocks 1 and 2
        let iterations = eval.evaluate_loop_to_fixpoint(&[1, 2], 5);

        // Should terminate (either reaching fixed point or max iterations)
        assert!(iterations > 0);
        assert!(iterations <= 5);

        // Value v1 should have been computed (0 + 1 = 1)
        assert_eq!(eval.get_concrete(v1).and_then(ConstValue::as_i32), Some(1));
    }

    #[test]
    fn test_evaluate_loop_to_fixpoint_empty() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);

        // Empty loop blocks should return 0 iterations
        let iterations = eval.evaluate_loop_to_fixpoint(&[], 10);
        assert_eq!(iterations, 0);
    }

    #[test]
    fn test_phi_simple_path_aware() {
        // Test basic phi evaluation with predecessor
        //
        // B0: v0 = 10, jump B2
        // B1: v1 = 20, jump B2
        // B2: v2 = phi(v0 from B0, v1 from B1), ret
        //
        // Coming from B0, v2 should be 10
        // Coming from B1, v2 should be 20

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        let mut ssa = SsaFunction::new(0, 0);

        // Block 0: v0 = 10, jump B2
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(10),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(b0);

        // Block 1: v1 = 20, jump B2
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(20),
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(b1);

        // Block 2: v2 = phi(v0 from B0, v1 from B1), ret
        let mut b2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(v2, VariableOrigin::Stack(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v1, 1));
        b2.add_phi(phi);
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v2) }));
        ssa.add_block(b2);

        // Evaluate B0 first to set v0
        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);
        assert_eq!(eval.get_concrete(v0).and_then(ConstValue::as_i32), Some(10));

        // Now evaluate B2 coming from B0
        eval.set_predecessor(Some(0));
        eval.evaluate_block(2);
        assert_eq!(
            eval.get_concrete(v2).and_then(ConstValue::as_i32),
            Some(10),
            "v2 should be 10 when coming from B0"
        );

        // Fresh evaluator: evaluate B1 first to set v1
        let mut eval2 = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval2.evaluate_block(1);
        assert_eq!(
            eval2.get_concrete(v1).and_then(ConstValue::as_i32),
            Some(20)
        );

        // Now evaluate B2 coming from B1
        eval2.set_predecessor(Some(1));
        eval2.evaluate_block(2);
        assert_eq!(
            eval2.get_concrete(v2).and_then(ConstValue::as_i32),
            Some(20),
            "v2 should be 20 when coming from B1"
        );
    }

    #[test]
    fn test_phi_swap_semantics() {
        // CRITICAL TEST: Verify phi nodes execute "simultaneously"
        //
        // This is the "swap problem" - phi nodes must read all values BEFORE
        // writing any results.
        //
        // B0: v1 = 10, v2 = 20, jump B1
        // B1: v1' = phi(v2 from B0), v2' = phi(v1 from B0), ret
        //
        // After evaluating B1 coming from B0:
        //   v1' should be 20 (original v2)
        //   v2' should be 10 (original v1)
        //
        // If phi nodes executed sequentially (bug), we'd get:
        //   v1' = 20 (correct)
        //   v2' = 20 (WRONG - read v1' instead of v1)

        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v1_prime = SsaVarId::new();
        let v2_prime = SsaVarId::new();

        let mut ssa = SsaFunction::new(0, 0);

        // Block 0: v1 = 10, v2 = 20, jump B1
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(10),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v2,
            value: ConstValue::I32(20),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // Block 1: phi nodes that swap v1 and v2
        let mut b1 = SsaBlock::new(1);
        // v1' = phi(v2 from B0) - reads v2
        let mut phi1 = PhiNode::new(v1_prime, VariableOrigin::Stack(0));
        phi1.add_operand(PhiOperand::new(v2, 0));
        // v2' = phi(v1 from B0) - reads v1
        let mut phi2 = PhiNode::new(v2_prime, VariableOrigin::Stack(1));
        phi2.add_operand(PhiOperand::new(v1, 0));
        b1.add_phi(phi1);
        b1.add_phi(phi2);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(b1);

        // Evaluate B0 to set v1=10, v2=20
        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);
        assert_eq!(eval.get_concrete(v1).and_then(ConstValue::as_i32), Some(10));
        assert_eq!(eval.get_concrete(v2).and_then(ConstValue::as_i32), Some(20));

        // Now evaluate B1 coming from B0 - this should swap the values
        eval.set_predecessor(Some(0));
        eval.evaluate_block(1);

        // CRITICAL ASSERTIONS: values should be swapped
        assert_eq!(
            eval.get_concrete(v1_prime).and_then(ConstValue::as_i32),
            Some(20),
            "v1' should be 20 (swapped from v2)"
        );
        assert_eq!(
            eval.get_concrete(v2_prime).and_then(ConstValue::as_i32),
            Some(10),
            "v2' should be 10 (swapped from v1)"
        );
    }

    #[test]
    fn test_phi_triple_rotate() {
        // Test a three-way rotation: a, b, c = c, a, b
        //
        // B0: a = 1, b = 2, c = 3, jump B1
        // B1: a' = phi(c), b' = phi(a), c' = phi(b), ret
        //
        // After: a' = 3, b' = 1, c' = 2

        let a = SsaVarId::new();
        let b = SsaVarId::new();
        let c = SsaVarId::new();
        let a_prime = SsaVarId::new();
        let b_prime = SsaVarId::new();
        let c_prime = SsaVarId::new();

        let mut ssa = SsaFunction::new(0, 0);

        // Block 0: a = 1, b = 2, c = 3
        let mut blk0 = SsaBlock::new(0);
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: a,
            value: ConstValue::I32(1),
        }));
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: b,
            value: ConstValue::I32(2),
        }));
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: c,
            value: ConstValue::I32(3),
        }));
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(blk0);

        // Block 1: rotate a, b, c = c, a, b
        let mut blk1 = SsaBlock::new(1);
        let mut phi_a = PhiNode::new(a_prime, VariableOrigin::Stack(0));
        phi_a.add_operand(PhiOperand::new(c, 0));
        blk1.add_phi(phi_a);
        let mut phi_b = PhiNode::new(b_prime, VariableOrigin::Stack(1));
        phi_b.add_operand(PhiOperand::new(a, 0));
        blk1.add_phi(phi_b);
        let mut phi_c = PhiNode::new(c_prime, VariableOrigin::Stack(2));
        phi_c.add_operand(PhiOperand::new(b, 0));
        blk1.add_phi(phi_c);
        blk1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(blk1);

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);
        eval.set_predecessor(Some(0));
        eval.evaluate_block(1);

        assert_eq!(
            eval.get_concrete(a_prime).and_then(ConstValue::as_i32),
            Some(3),
            "a' should be 3 (from c)"
        );
        assert_eq!(
            eval.get_concrete(b_prime).and_then(ConstValue::as_i32),
            Some(1),
            "b' should be 1 (from a)"
        );
        assert_eq!(
            eval.get_concrete(c_prime).and_then(ConstValue::as_i32),
            Some(2),
            "c' should be 2 (from b)"
        );
    }

    #[test]
    fn test_phi_self_reference_blocked() {
        // Test that phi reading from itself doesn't cause issues
        // (This would be a malformed SSA but we should handle it gracefully)
        //
        // B0: v1 = 10, jump B1
        // B1: v2 = phi(v1 from B0, v2 from B1), ret
        //
        // Coming from B0: v2 = 10
        // Coming from B1: v2 should remain as its current value (or unknown if not set)

        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        let mut ssa = SsaFunction::new(0, 0);

        // Block 0: v1 = 10, jump B1
        let mut blk0 = SsaBlock::new(0);
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(10),
        }));
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(blk0);

        // Block 1: v2 = phi(v1 from B0, v2 from B1)
        let mut blk1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(v2, VariableOrigin::Stack(0));
        phi.add_operand(PhiOperand::new(v1, 0));
        phi.add_operand(PhiOperand::new(v2, 1));
        blk1.add_phi(phi);
        blk1.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v2) }));
        ssa.add_block(blk1);

        // Coming from B0
        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);
        eval.set_predecessor(Some(0));
        eval.evaluate_block(1);
        assert_eq!(
            eval.get_concrete(v2).and_then(ConstValue::as_i32),
            Some(10),
            "v2 should be 10 from B0"
        );

        // Coming from B1 (self-reference) - v2 should keep its value
        eval.set_predecessor(Some(1));
        eval.evaluate_block(1);
        assert_eq!(
            eval.get_concrete(v2).and_then(ConstValue::as_i32),
            Some(10),
            "v2 should still be 10 (self-reference)"
        );
    }

    #[test]
    fn test_phi_merge_same_values() {
        // Test phi evaluation with predecessor set (Phase 1: no phi merging without predecessor)
        //
        // B0: v0 = 42, jump B2
        // B1: v1 = 42, jump B2
        // B2: v2 = phi(v0 from B0, v1 from B1), ret
        //
        // With predecessor set to B0, should get 42 from v0

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        let mut ssa = SsaFunction::new(0, 0);

        let mut blk0 = SsaBlock::new(0);
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        }));
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(blk0);

        let mut blk1 = SsaBlock::new(1);
        blk1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(42),
        }));
        blk1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(blk1);

        let mut blk2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(v2, VariableOrigin::Stack(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v1, 1));
        blk2.add_phi(phi);
        blk2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v2) }));
        ssa.add_block(blk2);

        // Phase 1: Require predecessor context for phi evaluation
        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);
        eval.evaluate_block(1);

        // Without predecessor set - should NOT merge (returns None)
        eval.evaluate_block(2);
        assert_eq!(
            eval.get_concrete(v2),
            None,
            "phi should NOT merge without predecessor (Phase 1 behavior)"
        );

        // With predecessor set - should get 42 from v0
        let mut eval2 = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval2.evaluate_block(0);
        eval2.set_predecessor(Some(0));
        eval2.evaluate_block(2);
        assert_eq!(
            eval2.get_concrete(v2).and_then(ConstValue::as_i32),
            Some(42),
            "phi should get 42 from predecessor B0"
        );
    }

    #[test]
    fn test_phi_merge_different_values_unknown() {
        // Test phi merge when operands have different values (no predecessor set)
        //
        // B0: v0 = 10, jump B2
        // B1: v1 = 20, jump B2
        // B2: v2 = phi(v0 from B0, v1 from B1), ret
        //
        // Without predecessor, should be unknown since 10 != 20

        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();

        let mut ssa = SsaFunction::new(0, 0);

        let mut blk0 = SsaBlock::new(0);
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(10),
        }));
        blk0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(blk0);

        let mut blk1 = SsaBlock::new(1);
        blk1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(20),
        }));
        blk1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(blk1);

        let mut blk2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(v2, VariableOrigin::Stack(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v1, 1));
        blk2.add_phi(phi);
        blk2.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: Some(v2) }));
        ssa.add_block(blk2);

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0);
        eval.evaluate_block(1);
        // No predecessor set - should be unknown
        eval.evaluate_block(2);
        assert!(
            eval.is_unknown(v2),
            "phi should be unknown when operands differ and no predecessor set"
        );
    }

    #[test]
    fn test_next_block_jump() {
        // Test unconditional jump
        // B0: jump B2
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.jump(2));
            f.block(1, |b| b.ret());
            f.block(2, |b| b.ret());
        });

        let eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        let result = eval.next_block(0);
        assert_eq!(result, ControlFlow::Continue(2));
    }

    #[test]
    fn test_next_block_return() {
        // Test return (terminal)
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.ret());
        });

        let eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        let result = eval.next_block(0);
        assert_eq!(result, ControlFlow::Terminal);
    }

    #[test]
    fn test_next_block_branch_known_true() {
        // Test conditional branch with known true condition
        // B0: cond = true, branch(cond, B1, B2)
        let (ssa, cond) = {
            let mut cond_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    cond_out = b.const_true();
                    b.branch(cond_out, 1, 2);
                });
                f.block(1, |b| b.ret());
                f.block(2, |b| b.ret());
            });
            (ssa, cond_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0); // Evaluate to set cond = true
        let result = eval.next_block(0);
        assert_eq!(result, ControlFlow::Continue(1));
        assert!(eval.is_concrete(cond));
    }

    #[test]
    fn test_next_block_branch_known_false() {
        // Test conditional branch with known false condition
        // B0: cond = false, branch(cond, B1, B2)
        let (ssa, _cond) = {
            let mut cond_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    cond_out = b.const_false();
                    b.branch(cond_out, 1, 2);
                });
                f.block(1, |b| b.ret());
                f.block(2, |b| b.ret());
            });
            (ssa, cond_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        eval.evaluate_block(0); // Evaluate to set cond = false
        let result = eval.next_block(0);
        assert_eq!(result, ControlFlow::Continue(2));
    }

    #[test]
    fn test_next_block_branch_unknown() {
        // Test conditional branch with unknown condition
        let (ssa, cond) = {
            let mut cond_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
                cond_out = f.arg(0); // Argument is unknown
                f.block(0, |b| {
                    b.branch(cond_out, 1, 2);
                });
                f.block(1, |b| b.ret());
                f.block(2, |b| b.ret());
            });
            (ssa, cond_out)
        };

        let eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        // Don't evaluate - cond is unknown
        assert!(eval.is_unknown(cond));
        let result = eval.next_block(0);
        assert_eq!(result, ControlFlow::Unknown);
    }

    #[test]
    fn test_execute_simple_path() {
        // Test execute with a simple linear path
        // B0: v0 = 10, jump B1
        // B1: v1 = v0 + 5, jump B2
        // B2: ret
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    v0_out = b.const_i32(10);
                    b.jump(1);
                });
                f.block(1, |b| {
                    let five = b.const_i32(5);
                    v1_out = b.add(v0_out, five);
                    b.jump(2);
                });
                f.block(2, |b| b.ret());
            });
            (ssa, v0_out, v1_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        let trace = eval.execute(0, None, 100);

        assert!(trace.is_complete());
        assert_eq!(trace.blocks(), &[0, 1, 2]);
        assert_eq!(eval.get_concrete(v0).and_then(ConstValue::as_i32), Some(10));
        assert_eq!(eval.get_concrete(v1).and_then(ConstValue::as_i32), Some(15));
    }

    #[test]
    fn test_execute_with_branch() {
        // Test execute with a branch
        // B0: state = 5, jump B1
        // B1: cmp = state == 5, branch(cmp, B2, B3)
        // B2: ret (true path)
        // B3: ret (false path)
        let (ssa, state, cmp_result) = {
            let mut state_out = SsaVarId::new();
            let mut cmp_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    state_out = b.const_i32(5);
                    b.jump(1);
                });
                f.block(1, |b| {
                    let five = b.const_i32(5);
                    cmp_out = b.ceq(state_out, five);
                    b.branch(cmp_out, 2, 3);
                });
                f.block(2, |b| b.ret());
                f.block(3, |b| b.ret());
            });
            (ssa, state_out, cmp_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        let trace = eval.execute(0, Some(state), 100);

        assert!(trace.is_complete());
        // Should go B0 -> B1 -> B2 (true branch because state == 5)
        assert_eq!(trace.blocks(), &[0, 1, 2]);
        assert_eq!(
            eval.get_concrete(cmp_result).and_then(ConstValue::as_i32),
            Some(1)
        ); // true
    }

    #[test]
    fn test_execute_max_steps() {
        // Test that execute respects max_steps limit
        // Infinite loop: B0 -> B0 -> B0 -> ...
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| b.jump(0)); // Self-loop
        });

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        let trace = eval.execute(0, None, 5);

        assert!(!trace.is_complete()); // Did not complete
        assert!(trace.hit_limit()); // Hit the limit
        assert_eq!(trace.len(), 5); // Exactly 5 blocks visited
    }

    #[test]
    fn test_execute_state_tracking() {
        // Test state variable tracking - captures state at start of each block
        // We track a single variable that's only assigned in B0
        // B0: state = 10, jump B1
        // B1: jump B2 (state unchanged)
        // B2: ret
        let (ssa, state) = {
            let mut state_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    state_out = b.const_i32(10);
                    b.jump(1);
                });
                f.block(1, |b| {
                    b.jump(2);
                });
                f.block(2, |b| b.ret());
            });
            (ssa, state_out)
        };

        let mut eval = SsaEvaluator::new(&ssa, PointerSize::Bit64);
        let trace = eval.execute(0, Some(state), 100);

        assert!(trace.is_complete());
        assert_eq!(trace.blocks(), &[0, 1, 2]);
        // State tracking captures state at the START of each block BEFORE evaluation
        // B0: state not yet set (None)
        // B1: state was set to 10 in B0 (and remains 10)
        // B2: state still 10
        assert_eq!(trace.states()[0], None); // Before B0 evaluation
        assert_eq!(
            trace.states()[1].as_ref().and_then(ConstValue::as_i32),
            Some(10)
        ); // After B0 evaluation, before B1
        assert_eq!(
            trace.states()[2].as_ref().and_then(ConstValue::as_i32),
            Some(10)
        ); // Still 10 after B1, before B2
    }

    #[test]
    fn test_control_flow_result_helpers() {
        // Test ControlFlow helper methods
        let cont = ControlFlow::Continue(5);
        assert_eq!(cont.target(), Some(5));
        assert!(!cont.is_terminal());
        assert!(!cont.is_unknown());

        let term = ControlFlow::Terminal;
        assert_eq!(term.target(), None);
        assert!(term.is_terminal());
        assert!(!term.is_unknown());

        let unknown = ControlFlow::Unknown;
        assert_eq!(unknown.target(), None);
        assert!(!unknown.is_terminal());
        assert!(unknown.is_unknown());
    }

    #[test]
    fn test_execution_trace_helpers() {
        let mut trace = ExecutionTrace::new(100);
        assert!(trace.is_empty());
        assert!(!trace.is_complete());
        assert!(!trace.hit_limit());
        assert_eq!(trace.last_block(), None);

        trace.record_block(0, Some(ConstValue::I32(10)));
        trace.record_block(1, Some(ConstValue::I32(20)));
        trace.record_block(2, None);

        assert_eq!(trace.len(), 3);
        assert!(!trace.is_empty());
        assert_eq!(trace.blocks(), &[0, 1, 2]);
        assert_eq!(
            trace.states(),
            &[Some(ConstValue::I32(10)), Some(ConstValue::I32(20)), None]
        );
        assert_eq!(trace.last_block(), Some(2));

        trace.mark_complete();
        assert!(trace.is_complete());
    }
}
