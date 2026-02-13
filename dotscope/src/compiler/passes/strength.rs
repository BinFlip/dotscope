//! Strength reduction pass.
//!
//! This pass transforms expensive operations into cheaper equivalents:
//!
//! - **Multiplication by power of 2**: `x * 2^n` → `x << n`
//! - **Unsigned division by power of 2**: `x / 2^n` → `x >> n` (unsigned only)
//! - **Unsigned modulo by power of 2**: `x % 2^n` → `x & (2^n - 1)` (unsigned only)
//!
//! # Safety
//!
//! Signed division and modulo are NOT transformed because:
//! - Signed division rounds toward zero, shifts round toward negative infinity
//! - `-5 / 2 = -2` but `-5 >> 1 = -3`
//! - The transformation is only safe when the value is provably non-negative
//!
//! # Implementation Strategy
//!
//! The pass works by:
//! 1. Finding constant definitions and tracking their use counts
//! 2. Identifying reducible operations (mul/div/rem with power-of-2 constant)
//! 3. For single-use constants: modify the constant value in-place and transform the op
//! 4. For multi-use constants: skip (would require inserting new instructions)
//!
//! # Example
//!
//! Before:
//! ```text
//! v1 = const 8
//! v2 = mul v0, v1
//! ```
//!
//! After:
//! ```text
//! v1 = const 3
//! v2 = shl v0, v1
//! ```

use std::{collections::HashSet, sync::Arc};

use crate::{
    analysis::{ConstValue, DefUseIndex, SsaFunction, SsaOp, SsaVarId, ValueRange},
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::token::Token,
    utils::is_power_of_two,
    CilObject, Result,
};

/// Strength reduction pass that transforms expensive operations to cheaper equivalents.
///
/// This pass identifies multiplication, division, and modulo operations where one
/// operand is a power of two, and transforms them to equivalent shift/mask operations.
pub struct StrengthReductionPass;

impl Default for StrengthReductionPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Location of an instruction in SSA form.
#[derive(Debug, Clone, Copy)]
struct InstrLocation {
    /// Block index containing the instruction
    block_idx: usize,
    /// Instruction index within the block
    instr_idx: usize,
}

/// Helper for checking strength reduction candidates.
///
/// Bundles the def-use index and used constants tracking to avoid
/// passing them through every reduction check function.
struct ReductionChecker<'a> {
    /// Def-use index for the SSA function
    index: &'a DefUseIndex,
    /// Constants already used in other reductions (to avoid double-transform)
    used_constants: &'a HashSet<SsaVarId>,
}

impl<'a> ReductionChecker<'a> {
    /// Creates a new reduction checker.
    fn new(index: &'a DefUseIndex, used_constants: &'a HashSet<SsaVarId>) -> Self {
        Self {
            index,
            used_constants,
        }
    }

    /// Tries to create a multiplication reduction candidate: `x * 2^n` → `x << n`
    fn try_mul_reduction(
        &self,
        dest: SsaVarId,
        value_var: SsaVarId,
        const_var: SsaVarId,
        location: InstrLocation,
    ) -> Option<ReductionCandidate> {
        // Check if const_var is a constant using DefUseIndex
        let (const_block, const_instr, const_op) = self.index.full_definition(const_var)?;
        let SsaOp::Const {
            value: const_value, ..
        } = const_op
        else {
            return None;
        };

        // Check if it's a power of two
        let value = const_value.as_i64()?;
        let exponent = is_power_of_two(value)?;

        // Check if constant is single-use (or we skip this reduction)
        let uses = self.index.use_count(const_var);
        if uses != 1 || self.used_constants.contains(&const_var) {
            return None;
        }

        Some(ReductionCandidate {
            location,
            const_var,
            const_block,
            const_instr,
            new_const_value: ConstValue::I32(i32::from(exponent)),
            new_op: SsaOp::Shl {
                dest,
                value: value_var,
                amount: const_var,
            },
            description: format!("mul x, {value} → shl x, {exponent}"),
        })
    }

    /// Tries to create a division reduction candidate: `x / 2^n` → `x >> n`
    fn try_div_reduction(
        &self,
        dest: SsaVarId,
        dividend: SsaVarId,
        divisor_var: SsaVarId,
        unsigned: bool,
        location: InstrLocation,
    ) -> Option<ReductionCandidate> {
        let (const_block, const_instr, const_op) = self.index.full_definition(divisor_var)?;
        let SsaOp::Const {
            value: const_value, ..
        } = const_op
        else {
            return None;
        };
        let value = const_value.as_i64()?;
        let exponent = is_power_of_two(value)?;

        let uses = self.index.use_count(divisor_var);
        if uses != 1 || self.used_constants.contains(&divisor_var) {
            return None;
        }

        let desc = if unsigned {
            format!("div.un x, {value} → shr.un x, {exponent}")
        } else {
            format!("div x, {value} → shr x, {exponent} (x >= 0)")
        };

        Some(ReductionCandidate {
            location,
            const_var: divisor_var,
            const_block,
            const_instr,
            new_const_value: ConstValue::I32(i32::from(exponent)),
            new_op: SsaOp::Shr {
                dest,
                value: dividend,
                amount: divisor_var,
                unsigned,
            },
            description: desc,
        })
    }

    /// Tries to create a remainder reduction candidate: `x % 2^n` → `x & (2^n - 1)`
    #[allow(clippy::cast_possible_truncation)] // mask fits in i32 for typical divisors
    fn try_rem_reduction(
        &self,
        dest: SsaVarId,
        dividend: SsaVarId,
        divisor_var: SsaVarId,
        unsigned: bool,
        location: InstrLocation,
    ) -> Option<ReductionCandidate> {
        let (const_block, const_instr, const_op) = self.index.full_definition(divisor_var)?;
        let SsaOp::Const {
            value: const_value, ..
        } = const_op
        else {
            return None;
        };
        let value = const_value.as_i64()?;
        let _exponent = is_power_of_two(value)?;
        let mask = value - 1; // 2^n - 1

        let uses = self.index.use_count(divisor_var);
        if uses != 1 || self.used_constants.contains(&divisor_var) {
            return None;
        }

        let desc = if unsigned {
            format!("rem.un x, {value} → and x, {mask}")
        } else {
            format!("rem x, {value} → and x, {mask} (x >= 0)")
        };

        Some(ReductionCandidate {
            location,
            const_var: divisor_var,
            const_block,
            const_instr,
            new_const_value: ConstValue::I32(mask as i32),
            new_op: SsaOp::And {
                dest,
                left: dividend,
                right: divisor_var,
            },
            description: desc,
        })
    }
}

/// Information about a potential reduction.
#[derive(Debug)]
struct ReductionCandidate {
    /// Location of the operation to reduce
    location: InstrLocation,
    /// The constant variable (power of 2)
    const_var: SsaVarId,
    /// Block where the constant is defined
    const_block: usize,
    /// Instruction index where the constant is defined
    const_instr: usize,
    /// The new constant value (shift amount or mask)
    new_const_value: ConstValue,
    /// The new operation to replace with
    new_op: SsaOp,
    /// Description for logging
    description: String,
}

impl StrengthReductionPass {
    /// Creates a new strength reduction pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Identifies reduction candidates in the SSA function.
    fn find_candidates(
        ssa: &SsaFunction,
        index: &DefUseIndex,
        ctx: &CompilerContext,
        method_token: Token,
    ) -> Vec<ReductionCandidate> {
        let mut candidates = Vec::new();

        // Set of constant variables that are already being transformed
        // (to avoid transforming the same constant twice if used in multiple reductions)
        let mut used_constants: HashSet<SsaVarId> = HashSet::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            let checker = ReductionChecker::new(index, &used_constants);
            let location = InstrLocation {
                block_idx,
                instr_idx,
            };
            if let Some(candidate) =
                Self::check_reduction(instr.op(), location, &checker, ctx, method_token)
            {
                used_constants.insert(candidate.const_var);
                candidates.push(candidate);
            }
        }

        candidates
    }

    /// Checks if an operation can be strength-reduced.
    fn check_reduction(
        op: &SsaOp,
        location: InstrLocation,
        checker: &ReductionChecker<'_>,
        ctx: &CompilerContext,
        method_token: Token,
    ) -> Option<ReductionCandidate> {
        match op {
            // Multiplication: x * 2^n → x << n
            SsaOp::Mul { dest, left, right } => {
                // Try right operand first (more common: x * 8)
                if let Some(candidate) = checker.try_mul_reduction(*dest, *left, *right, location) {
                    return Some(candidate);
                }
                // Try left operand (less common: 8 * x)
                checker.try_mul_reduction(*dest, *right, *left, location)
            }

            // Unsigned division: x / 2^n → x >> n (unsigned only)
            SsaOp::Div {
                dest,
                left,
                right,
                unsigned: true,
            } => checker.try_div_reduction(*dest, *left, *right, true, location),

            // Signed division: only when dividend is provably non-negative
            SsaOp::Div {
                dest,
                left,
                right,
                unsigned: false,
            } => {
                // Check if left operand is provably non-negative
                if Self::is_provably_non_negative(*left, ctx, method_token) {
                    checker.try_div_reduction(*dest, *left, *right, false, location)
                } else {
                    None
                }
            }

            // Unsigned modulo: x % 2^n → x & (2^n - 1)
            SsaOp::Rem {
                dest,
                left,
                right,
                unsigned: true,
            } => checker.try_rem_reduction(*dest, *left, *right, true, location),

            // Signed modulo: only when dividend is provably non-negative
            SsaOp::Rem {
                dest,
                left,
                right,
                unsigned: false,
            } => {
                if Self::is_provably_non_negative(*left, ctx, method_token) {
                    checker.try_rem_reduction(*dest, *left, *right, false, location)
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    /// Checks if a variable is provably non-negative via range analysis.
    fn is_provably_non_negative(var: SsaVarId, ctx: &CompilerContext, method_token: Token) -> bool {
        ctx.with_known_range(method_token, var, ValueRange::is_always_non_negative)
            .unwrap_or(false)
    }

    /// Applies the reduction candidates to the SSA function.
    fn apply_reductions(
        ssa: &mut SsaFunction,
        candidates: Vec<ReductionCandidate>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        for candidate in candidates {
            // First, update the constant definition
            if let Some(block) = ssa.block_mut(candidate.const_block) {
                let const_instr = &mut block.instructions_mut()[candidate.const_instr];
                const_instr.set_op(SsaOp::Const {
                    dest: candidate.const_var,
                    value: candidate.new_const_value,
                });
            }

            // Then, update the operation
            if let Some(block) = ssa.block_mut(candidate.location.block_idx) {
                let instr = &mut block.instructions_mut()[candidate.location.instr_idx];
                instr.set_op(candidate.new_op);
                changes
                    .record(EventKind::StrengthReduced)
                    .at(method_token, candidate.location.instr_idx)
                    .message(&candidate.description);
            }
        }
    }
}

impl SsaPass for StrengthReductionPass {
    fn name(&self) -> &'static str {
        "strength-reduction"
    }

    fn description(&self) -> &'static str {
        "Transform expensive operations (mul/div/rem) to cheaper equivalents (shl/shr/and)"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();
        // Build DefUseIndex for definition and use tracking
        let index = DefUseIndex::build_with_ops(ssa);

        let candidates = Self::find_candidates(ssa, &index, ctx, method_token);

        // Apply reductions
        Self::apply_reductions(ssa, candidates, method_token, &mut changes);

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}
