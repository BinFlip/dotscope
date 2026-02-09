//! Z3-based constraint solver for symbolic expressions.
//!
//! This module provides [`Z3Solver`], which translates [`SymbolicExpr`] trees
//! to Z3's AST and uses Z3's SMT solver to find solutions to constraints.
//! All computations use 32-bit bitvectors matching CIL's `int32` semantics.

use std::collections::HashMap;

use crate::{
    analysis::ssa::symbolic::{expr::SymbolicExpr, ops::SymbolicOp},
    metadata::typesystem::PointerSize,
};

/// Z3-based constraint solver for symbolic expressions.
///
/// This solver translates our `SymbolicExpr` IR to Z3's AST and uses Z3's
/// SMT solver to find solutions to constraints. The solver is stateless;
/// each solving operation creates a fresh Z3 context internally.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::analysis::{SymbolicExpr, SymbolicOp, Z3Solver};
///
/// let solver = Z3Solver::new();
///
/// // Find all state values where (state XOR 0x12345678) % 13 == 5
/// let expr = SymbolicExpr::binary(
///     SymbolicOp::RemU,
///     SymbolicExpr::binary(
///         SymbolicOp::Xor,
///         SymbolicExpr::named("state"),
///         SymbolicExpr::constant_i32(0x12345678),
///     ),
///     SymbolicExpr::constant_i32(13),
/// );
///
/// let solutions = solver.solve_for_value(&expr, "state", 5, 100);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Z3Solver;

impl Z3Solver {
    /// Creates a new Z3 solver instance.
    ///
    /// The solver uses Z3's default configuration with 32-bit bitvector logic.
    ///
    /// # Returns
    ///
    /// A new [`Z3Solver`] ready to solve constraints.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Finds values for a named variable that make the expression equal to a target.
    ///
    /// Uses Z3 to enumerate solutions by repeatedly solving and excluding found
    /// solutions until `max_solutions` are found or no more solutions exist.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to solve.
    /// * `var_name` - The name of the variable to solve for (must appear in `expr`).
    /// * `target` - The target value the expression should equal.
    /// * `max_solutions` - Maximum number of solutions to return.
    ///
    /// # Returns
    ///
    /// A vector of values for `var_name` that make `expr == target`.
    /// May contain fewer than `max_solutions` if fewer solutions exist.
    #[must_use]
    pub fn solve_for_value(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        target: i64,
        max_solutions: usize,
    ) -> Vec<i64> {
        let solver = z3::Solver::new();

        // Create the variable we're solving for as a 32-bit bitvector
        let var = z3::ast::BV::new_const(var_name, 32);

        // Build variable map
        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map.insert(var_name.to_string(), var.clone());

        // Translate expression to Z3
        let z3_expr = self.translate_to_z3(expr, &var_map);

        // Add constraint: expr == target
        let target_bv = z3::ast::BV::from_i64(target, 32);
        solver.assert(z3_expr.eq(&target_bv));

        // Enumerate solutions
        let mut solutions = Vec::new();
        while solutions.len() < max_solutions {
            match solver.check() {
                z3::SatResult::Sat => {
                    let Some(model) = solver.get_model() else {
                        break;
                    };
                    let Some(val) = model.eval(&var, true) else {
                        break;
                    };
                    let solution = val.as_i64().unwrap_or(0);
                    solutions.push(solution);

                    // Exclude this solution and continue
                    let exclude = var.eq(z3::ast::BV::from_i64(solution, 32));
                    solver.assert(exclude.not());
                }
                _ => break,
            }
        }

        solutions
    }

    /// Finds values within a range that make the expression equal to a target.
    ///
    /// Similar to [`solve_for_value`](Self::solve_for_value), but adds range
    /// constraints to restrict the search space. More efficient when you know
    /// the valid range of input values.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to solve.
    /// * `var_name` - The name of the variable to solve for.
    /// * `target` - The target value the expression should equal.
    /// * `min_val` - Minimum allowed value for the variable (inclusive).
    /// * `max_val` - Maximum allowed value for the variable (inclusive).
    /// * `max_solutions` - Maximum number of solutions to return.
    ///
    /// # Returns
    ///
    /// A vector of values in `[min_val, max_val]` that make `expr == target`.
    #[must_use]
    pub fn solve_in_range(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        target: i64,
        min_val: i64,
        max_val: i64,
        max_solutions: usize,
    ) -> Vec<i64> {
        let solver = z3::Solver::new();

        let var = z3::ast::BV::new_const(var_name, 32);

        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map.insert(var_name.to_string(), var.clone());

        let z3_expr = self.translate_to_z3(expr, &var_map);

        // Constraint: expr == target
        let target_bv = z3::ast::BV::from_i64(target, 32);
        solver.assert(z3_expr.eq(&target_bv));

        // Range constraints (signed comparison)
        let min_bv = z3::ast::BV::from_i64(min_val, 32);
        let max_bv = z3::ast::BV::from_i64(max_val, 32);
        solver.assert(var.bvsge(&min_bv));
        solver.assert(var.bvsle(&max_bv));

        let mut solutions = Vec::new();
        while solutions.len() < max_solutions {
            match solver.check() {
                z3::SatResult::Sat => {
                    let Some(model) = solver.get_model() else {
                        break;
                    };
                    let Some(val) = model.eval(&var, true) else {
                        break;
                    };
                    let solution = val.as_i64().unwrap_or(0);
                    solutions.push(solution);

                    let exclude = var.eq(z3::ast::BV::from_i64(solution, 32));
                    solver.assert(exclude.not());
                }
                _ => break,
            }
        }

        solutions
    }

    /// Builds a complete mapping from case indices to input values.
    ///
    /// For each possible case index (0 to `num_cases - 1`), finds input values
    /// that produce that case index. This is the primary method for control flow
    /// unflattening, where we need to know which state values reach which switch cases.
    ///
    /// # Arguments
    ///
    /// * `expr` - The switch selector expression (e.g., `(state XOR C) % N`).
    /// * `var_name` - The name of the state variable to solve for.
    /// * `num_cases` - The number of switch cases to map.
    /// * `solutions_per_case` - Maximum solutions to find for each case.
    ///
    /// # Returns
    ///
    /// A map from case index to the list of input values that reach that case.
    /// Cases with no reachable inputs are omitted from the map.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)] // case_idx is small (switch case count) - safe to convert to i64
    pub fn build_case_mapping(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        num_cases: usize,
        solutions_per_case: usize,
    ) -> HashMap<usize, Vec<i64>> {
        let mut mapping = HashMap::new();

        for case_idx in 0..num_cases {
            let solutions =
                self.solve_for_value(expr, var_name, case_idx as i64, solutions_per_case);
            if !solutions.is_empty() {
                mapping.insert(case_idx, solutions);
            }
        }

        mapping
    }

    /// Checks if any value exists that makes the expression equal to a target.
    ///
    /// This is faster than [`solve_for_value`](Self::solve_for_value) when you
    /// only need to know if a solution exists, not what the solutions are.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to check.
    /// * `var_name` - The name of the variable in the expression.
    /// * `target` - The target value to check for satisfiability.
    ///
    /// # Returns
    ///
    /// `true` if there exists a value for `var_name` that makes `expr == target`.
    #[must_use]
    pub fn is_satisfiable(&self, expr: &SymbolicExpr, var_name: &str, target: i64) -> bool {
        let solver = z3::Solver::new();

        let var = z3::ast::BV::new_const(var_name, 32);

        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map.insert(var_name.to_string(), var);

        let z3_expr = self.translate_to_z3(expr, &var_map);
        let target_bv = z3::ast::BV::from_i64(target, 32);
        solver.assert(z3_expr.eq(&target_bv));

        matches!(solver.check(), z3::SatResult::Sat)
    }

    /// Checks if a boolean expression is an opaque predicate.
    ///
    /// An opaque predicate is a condition that always evaluates to the same
    /// boolean value regardless of inputs. Obfuscators use these to add fake
    /// branches that are never/always taken.
    ///
    /// This method checks satisfiability for both outcomes (true and false)
    /// to determine if the predicate is opaque:
    /// - Always true: can be true but never false
    /// - Always false: can be false but never true
    /// - Not opaque: can be both true and false
    ///
    /// # Arguments
    ///
    /// * `expr` - The condition expression to analyze.
    /// * `var_names` - Names of symbolic variables in the expression.
    ///
    /// # Returns
    ///
    /// - `Some(true)` if the predicate is always true
    /// - `Some(false)` if the predicate is always false
    /// - `None` if the predicate is not opaque (can be both true and false)
    #[must_use]
    pub fn check_opaque_predicate(&self, expr: &SymbolicExpr, var_names: &[&str]) -> Option<bool> {
        // Check if the expression can evaluate to true (non-zero)
        let can_be_true = self.is_satisfiable_bool(expr, var_names, true);

        // Check if the expression can evaluate to false (zero)
        let can_be_false = self.is_satisfiable_bool(expr, var_names, false);

        match (can_be_true, can_be_false) {
            (true, false) => Some(true),  // Always true - opaque predicate
            (false, true) => Some(false), // Always false - opaque predicate
            _ => None,                    // Not opaque - can be both
        }
    }

    /// Checks if a boolean expression can evaluate to a specific truth value.
    ///
    /// For boolean expressions (comparisons), we check if the expression can
    /// be non-zero (true) or zero (false).
    ///
    /// # Arguments
    ///
    /// * `expr` - The boolean expression to check.
    /// * `var_names` - Names of symbolic variables in the expression.
    /// * `target_true` - If true, check if expr can be non-zero; if false, check if expr can be zero.
    ///
    /// # Returns
    ///
    /// `true` if the expression can evaluate to the target truth value.
    #[must_use]
    pub fn is_satisfiable_bool(
        &self,
        expr: &SymbolicExpr,
        var_names: &[&str],
        target_true: bool,
    ) -> bool {
        let solver = z3::Solver::new();

        // Create all symbolic variables
        let mut var_map: HashMap<String, z3::ast::BV> = HashMap::new();
        for name in var_names {
            let var = z3::ast::BV::new_const(*name, 32);
            var_map.insert((*name).to_string(), var);
        }

        // Translate expression to Z3
        let z3_expr = self.translate_to_z3(expr, &var_map);

        // For boolean: true means non-zero, false means zero
        let zero = z3::ast::BV::from_i64(0, 32);
        if target_true {
            // Check if expr can be non-zero (true)
            solver.assert(z3_expr.eq(&zero).not());
        } else {
            // Check if expr can be zero (false)
            solver.assert(z3_expr.eq(&zero));
        }

        matches!(solver.check(), z3::SatResult::Sat)
    }

    /// Checks if an expression is constant for all input values.
    ///
    /// This determines if the expression always produces the same value
    /// regardless of the symbolic variable's value. Useful for detecting
    /// expressions that have been simplified to constants by the obfuscator.
    ///
    /// # Arguments
    ///
    /// * `expr` - The expression to check.
    /// * `var_name` - The name of the symbolic variable.
    ///
    /// # Returns
    ///
    /// `Some(value)` if the expression is constant, `None` if it varies.
    #[must_use]
    pub fn is_constant_expression(
        &self,
        expr: &SymbolicExpr,
        var_name: &str,
        ptr_size: PointerSize,
    ) -> Option<i64> {
        // Check if there are at least two different outputs for different inputs
        let solver = z3::Solver::new();

        let var1 = z3::ast::BV::new_const(format!("{var_name}_1"), 32);
        let var2 = z3::ast::BV::new_const(format!("{var_name}_2"), 32);

        let mut var_map1: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map1.insert(var_name.to_string(), var1.clone());

        let mut var_map2: HashMap<String, z3::ast::BV> = HashMap::new();
        var_map2.insert(var_name.to_string(), var2.clone());

        let z3_expr1 = self.translate_to_z3(expr, &var_map1);
        let z3_expr2 = self.translate_to_z3(expr, &var_map2);

        // Assert that the two inputs produce different outputs
        solver.assert(z3_expr1.eq(&z3_expr2).not());

        match solver.check() {
            z3::SatResult::Sat => None, // Expression can produce different values
            z3::SatResult::Unsat => {
                // Expression is constant - find the value
                // Evaluate with any input (e.g., 0)
                if let Some(c) = expr.substitute_named(var_name, 0, ptr_size).as_i64() {
                    Some(c)
                } else {
                    // Try Z3 to find the constant value
                    let solver2 = z3::Solver::new();
                    let var = z3::ast::BV::new_const(var_name, 32);
                    let mut vm: HashMap<String, z3::ast::BV> = HashMap::new();
                    vm.insert(var_name.to_string(), var);
                    let e = self.translate_to_z3(expr, &vm);

                    // Just check satisfiability and get the expression value
                    if let z3::SatResult::Sat = solver2.check() {
                        if let Some(model) = solver2.get_model() {
                            if let Some(val) = model.eval(&e, true) {
                                return val.as_i64();
                            }
                        }
                    }
                    None
                }
            }
            z3::SatResult::Unknown => None, // Can't determine
        }
    }

    /// Translates a symbolic expression to Z3's bitvector AST.
    ///
    /// Recursively converts our [`SymbolicExpr`] IR to Z3's internal representation.
    /// All values are represented as 32-bit bitvectors to match CIL semantics.
    ///
    /// # Arguments
    ///
    /// * `expr` - The symbolic expression to translate.
    /// * `var_map` - Map from variable names to their Z3 bitvector representations.
    ///
    /// # Returns
    ///
    /// The Z3 bitvector AST representing the expression.
    #[allow(
        clippy::self_only_used_in_recursion,
        clippy::trivially_copy_pass_by_ref
    )] // Recursive helper method - &self maintains method organization
    fn translate_to_z3(
        &self,
        expr: &SymbolicExpr,
        var_map: &HashMap<String, z3::ast::BV>,
    ) -> z3::ast::BV {
        match expr {
            SymbolicExpr::Constant(v) => {
                // Extract i64 value from ConstValue for Z3
                let val = v.as_i64().unwrap_or(0);
                z3::ast::BV::from_i64(val, 32)
            }

            SymbolicExpr::Variable(var_id) => {
                // Create a unique name for SSA variables
                let name = format!("ssa_{}", var_id.index());
                z3::ast::BV::new_const(name, 32)
            }

            SymbolicExpr::NamedVar(name) => {
                if let Some(var) = var_map.get(name) {
                    var.clone()
                } else {
                    // Create new variable if not in map
                    z3::ast::BV::new_const(name.as_str(), 32)
                }
            }

            SymbolicExpr::Unary { op, operand } => {
                let operand_z3 = self.translate_to_z3(operand, var_map);
                match op {
                    SymbolicOp::Neg => operand_z3.bvneg(),
                    SymbolicOp::Not => operand_z3.bvnot(),
                    _ => operand_z3, // Shouldn't happen for valid unary ops
                }
            }

            SymbolicExpr::Binary { op, left, right } => {
                let left_z3 = self.translate_to_z3(left, var_map);
                let right_z3 = self.translate_to_z3(right, var_map);

                match op {
                    SymbolicOp::Add => left_z3.bvadd(&right_z3),
                    SymbolicOp::Sub => left_z3.bvsub(&right_z3),
                    SymbolicOp::Mul => left_z3.bvmul(&right_z3),
                    SymbolicOp::DivS => left_z3.bvsdiv(&right_z3),
                    SymbolicOp::DivU => left_z3.bvudiv(&right_z3),
                    SymbolicOp::RemS => left_z3.bvsrem(&right_z3),
                    SymbolicOp::RemU => left_z3.bvurem(&right_z3),
                    SymbolicOp::And => left_z3.bvand(&right_z3),
                    SymbolicOp::Or => left_z3.bvor(&right_z3),
                    SymbolicOp::Xor => left_z3.bvxor(&right_z3),
                    SymbolicOp::Shl => left_z3.bvshl(&right_z3),
                    SymbolicOp::ShrS => left_z3.bvashr(&right_z3),
                    SymbolicOp::ShrU => left_z3.bvlshr(&right_z3),
                    // Comparisons return 1 or 0
                    SymbolicOp::Eq => left_z3
                        .eq(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::Ne => left_z3
                        .eq(&right_z3)
                        .not()
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::LtS => left_z3
                        .bvslt(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::LtU => left_z3
                        .bvult(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::GtS => left_z3
                        .bvsgt(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::GtU => left_z3
                        .bvugt(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::LeS => left_z3
                        .bvsle(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::LeU => left_z3
                        .bvule(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::GeS => left_z3
                        .bvsge(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    SymbolicOp::GeU => left_z3
                        .bvuge(&right_z3)
                        .ite(&z3::ast::BV::from_i64(1, 32), &z3::ast::BV::from_i64(0, 32)),
                    // Unary ops shouldn't appear in binary context
                    SymbolicOp::Neg | SymbolicOp::Not => left_z3,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::ssa::symbolic::{expr::SymbolicExpr, ops::SymbolicOp, solver::Z3Solver},
        metadata::typesystem::PointerSize,
    };

    #[test]
    fn test_z3_simple_solve() {
        let solver = Z3Solver::new();

        // Solve: state + 5 = 10  =>  state = 5
        let expr = SymbolicExpr::binary(
            SymbolicOp::Add,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(5),
        );

        let solutions = solver.solve_for_value(&expr, "state", 10, 10);
        assert!(!solutions.is_empty());
        assert!(solutions.contains(&5));
    }

    #[test]
    fn test_z3_xor_solve() {
        let solver = Z3Solver::new();

        // Solve: state XOR 0x1234 = 0x5678
        let expr = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(0x1234),
        );

        let solutions = solver.solve_for_value(&expr, "state", 0x5678, 10);
        assert!(!solutions.is_empty());

        // Verify: state XOR 0x1234 should equal 0x5678
        let state = solutions[0];
        assert_eq!((state as i32) ^ 0x1234, 0x5678);
    }

    #[test]
    fn test_z3_xor_modulo_solve() {
        let solver = Z3Solver::new();

        // Solve: (state XOR 0x12345678) % 13 = 5
        let xored = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(0x12345678),
        );
        let expr = SymbolicExpr::binary(SymbolicOp::RemU, xored, SymbolicExpr::constant_i32(13));

        let solutions = solver.solve_for_value(&expr, "state", 5, 10);
        assert!(!solutions.is_empty());

        // Verify all solutions
        for &sol in &solutions {
            let xor_result = (sol as u32) ^ 0x12345678u32;
            assert_eq!(xor_result % 13, 5);
        }
    }

    #[test]
    fn test_z3_build_case_mapping() {
        let solver = Z3Solver::new();

        // Build mapping for: state % 5
        let expr = SymbolicExpr::binary(
            SymbolicOp::RemU,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(5),
        );

        let mapping = solver.build_case_mapping(&expr, "state", 5, 3);

        // Should have solutions for cases 0-4
        assert_eq!(mapping.len(), 5);
        for case_idx in 0..5 {
            assert!(mapping.contains_key(&case_idx));
        }
    }

    #[test]
    fn test_z3_is_satisfiable() {
        let solver = Z3Solver::new();

        // state % 5 = 3 should be satisfiable
        let expr = SymbolicExpr::binary(
            SymbolicOp::RemU,
            SymbolicExpr::named("state"),
            SymbolicExpr::constant_i32(5),
        );
        assert!(solver.is_satisfiable(&expr, "state", 3));

        // state % 5 = 7 should NOT be satisfiable (7 > 5)
        assert!(!solver.is_satisfiable(&expr, "state", 7));
    }

    #[test]
    fn test_opaque_predicate_always_true() {
        let solver = Z3Solver::new();

        // x * x >= 0 is always true for signed 32-bit (squared values are non-negative)
        // Actually this is false due to overflow. Let's use a simpler case:
        // (x | ~x) == -1 is always true (all bits set)
        let x = SymbolicExpr::named("x");
        let not_x = SymbolicExpr::unary(SymbolicOp::Not, x.clone());
        let or_expr = SymbolicExpr::binary(SymbolicOp::Or, x, not_x);
        let cmp = SymbolicExpr::binary(SymbolicOp::Eq, or_expr, SymbolicExpr::constant_i32(-1));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(true), "(x | ~x) == -1 should always be true");
    }

    #[test]
    fn test_opaque_predicate_always_false() {
        let solver = Z3Solver::new();

        // (x & ~x) != 0 is always false (x & ~x is always 0)
        let x = SymbolicExpr::named("x");
        let not_x = SymbolicExpr::unary(SymbolicOp::Not, x.clone());
        let and_expr = SymbolicExpr::binary(SymbolicOp::And, x, not_x);
        let cmp = SymbolicExpr::binary(SymbolicOp::Ne, and_expr, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(false), "(x & ~x) != 0 should always be false");
    }

    #[test]
    fn test_opaque_predicate_not_opaque() {
        let solver = Z3Solver::new();

        // x > 0 is NOT an opaque predicate (can be true or false)
        let expr = SymbolicExpr::binary(
            SymbolicOp::GtS,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(0),
        );

        let result = solver.check_opaque_predicate(&expr, &["x"]);
        assert_eq!(result, None, "x > 0 should not be opaque");
    }

    #[test]
    fn test_opaque_predicate_complex_always_true() {
        let solver = Z3Solver::new();

        // (x - x) == 0 is always true
        let x = SymbolicExpr::named("x");
        let sub = SymbolicExpr::binary(SymbolicOp::Sub, x.clone(), x);
        let cmp = SymbolicExpr::binary(SymbolicOp::Eq, sub, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(true), "(x - x) == 0 should always be true");
    }

    #[test]
    fn test_opaque_predicate_xor_self() {
        let solver = Z3Solver::new();

        // (x ^ x) == 0 is always true
        let x = SymbolicExpr::named("x");
        let xor = SymbolicExpr::binary(SymbolicOp::Xor, x.clone(), x);
        let cmp = SymbolicExpr::binary(SymbolicOp::Eq, xor, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x"]);
        assert_eq!(result, Some(true), "(x ^ x) == 0 should always be true");
    }

    #[test]
    fn test_opaque_predicate_multiple_variables() {
        let solver = Z3Solver::new();

        // (x + y) - (y + x) == 0 is always true (commutativity of addition)
        let x = SymbolicExpr::named("x");
        let y = SymbolicExpr::named("y");
        let sum1 = SymbolicExpr::binary(SymbolicOp::Add, x.clone(), y.clone());
        let sum2 = SymbolicExpr::binary(SymbolicOp::Add, y, x);
        let diff = SymbolicExpr::binary(SymbolicOp::Sub, sum1, sum2);
        let cmp = SymbolicExpr::binary(SymbolicOp::Eq, diff, SymbolicExpr::constant_i32(0));

        let result = solver.check_opaque_predicate(&cmp, &["x", "y"]);
        assert_eq!(
            result,
            Some(true),
            "(x + y) - (y + x) == 0 should always be true"
        );
    }

    #[test]
    fn test_is_satisfiable_bool_true() {
        let solver = Z3Solver::new();

        // x > 5 can be true (e.g., x = 10)
        let expr = SymbolicExpr::binary(
            SymbolicOp::GtS,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(5),
        );

        assert!(solver.is_satisfiable_bool(&expr, &["x"], true));
    }

    #[test]
    fn test_is_satisfiable_bool_false() {
        let solver = Z3Solver::new();

        // x > 5 can be false (e.g., x = 0)
        let expr = SymbolicExpr::binary(
            SymbolicOp::GtS,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(5),
        );

        assert!(solver.is_satisfiable_bool(&expr, &["x"], false));
    }

    #[test]
    fn test_is_constant_expression_constant() {
        let solver = Z3Solver::new();

        // 5 + 3 is always 8
        let expr = SymbolicExpr::binary(
            SymbolicOp::Add,
            SymbolicExpr::constant_i32(5),
            SymbolicExpr::constant_i32(3),
        );

        let result = solver.is_constant_expression(&expr, "x", PointerSize::Bit64);
        assert_eq!(result, Some(8), "5 + 3 should be constant 8");
    }

    #[test]
    fn test_is_constant_expression_not_constant() {
        let solver = Z3Solver::new();

        // x + 3 varies with x
        let expr = SymbolicExpr::binary(
            SymbolicOp::Add,
            SymbolicExpr::named("x"),
            SymbolicExpr::constant_i32(3),
        );

        let result = solver.is_constant_expression(&expr, "x", PointerSize::Bit64);
        assert_eq!(result, None, "x + 3 should not be constant");
    }
}
