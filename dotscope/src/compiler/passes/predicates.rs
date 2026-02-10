//! Opaque predicate detection and removal pass.
//!
//! Opaque predicates are conditional expressions that always evaluate to the same
//! value at runtime, but appear complex to static analysis. Obfuscators use them
//! to confuse decompilers and analysis tools.
//!
//! # Detection Strategies
//!
//! ## Basic Patterns
//! - **Self-comparison**: `x == x`, `x != x`, `x < x`, `x > x`
//! - **Identity operations**: `x ^ x == 0`, `x - x == 0`
//! - **Zero operations**: `x * 0`, `x & 0`, `x % 1`
//!
//! ## Number-Theoretic Predicates
//! - **Consecutive integers**: `(x * (x + 1)) % 2 == 0` (always true)
//! - **Square properties**: `x² >= 0` (always true for integers)
//! - **Modular arithmetic**: `(x² - x) % 2 == 0` (always true)
//!
//! ## Type-Based Predicates
//! - **Null checks**: `obj != null` after `newobj` (always true)
//! - **Array length**: `arr.Length >= 0` (always true)
//!
//! ## Range-Based Predicates
//! - **Unsigned bounds**: `unsigned_x >= 0` (always true)
//! - **Correlated conditions**: `if (x > 5) { if (x < 3) { dead } }`
//!
//! # Example
//!
//! Before:
//! ```text
//! v0 = 5
//! v1 = ceq v0, v0    // Always true
//! branch v1, B1, B2  // Always goes to B1
//! ```
//!
//! After:
//! ```text
//! v0 = 5
//! v1 = true
//! jump B1
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    analysis::{
        ConstValue, DefUseIndex, SsaEvaluator, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        ValueRange,
    },
    compiler::{pass::SsaPass, CompilerContext, EventKind, EventLog},
    metadata::{token::Token, typesystem::PointerSize},
    CilObject, Result,
};

/// Result of analyzing a potential opaque predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateResult {
    /// The predicate always evaluates to true.
    AlwaysTrue,
    /// The predicate always evaluates to false.
    AlwaysFalse,
    /// Cannot determine the predicate's value.
    Unknown,
}

impl PredicateResult {
    /// Converts to an optional boolean.
    #[must_use]
    pub fn as_bool(self) -> Option<bool> {
        match self {
            Self::AlwaysTrue => Some(true),
            Self::AlwaysFalse => Some(false),
            Self::Unknown => None,
        }
    }

    /// Negates the predicate result.
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Self::AlwaysTrue => Self::AlwaysFalse,
            Self::AlwaysFalse => Self::AlwaysTrue,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// Result of analyzing a comparison for algebraic simplification.
///
/// Unlike `PredicateResult` which determines if a comparison is always true/false,
/// this enum represents transformations that simplify comparisons while preserving
/// their runtime behavior.
#[derive(Debug, Clone)]
enum ComparisonSimplification {
    /// Replace with a simpler comparison operation.
    SimplerOp { new_op: SsaOp, reason: &'static str },
    /// Replace with a copy of another variable (e.g., `(cmp) == 1` → `cmp`).
    Copy {
        dest: SsaVarId,
        src: SsaVarId,
        reason: &'static str,
    },
}

/// Cached definition information for efficient lookup.
///
/// Uses `DefUseIndex` for basic definition lookups, with additional
/// tracking for phi nodes, non-null variables, and value ranges.
struct DefinitionCache {
    /// Index for definition lookups (block, instruction, operation).
    index: DefUseIndex,
    /// Variables defined by phi nodes.
    phi_defs: HashSet<SsaVarId>,
    /// Variables that are known to be non-null (after newobj, etc.).
    non_null_vars: HashSet<SsaVarId>,
    /// Variables that come from array length operations.
    array_length_vars: HashSet<SsaVarId>,
    /// Computed value ranges for variables.
    ranges: HashMap<SsaVarId, ValueRange>,
}

impl DefinitionCache {
    /// Builds the definition cache from an SSA function.
    fn build(ssa: &SsaFunction) -> Self {
        // Use DefUseIndex for basic definition tracking
        let index = DefUseIndex::build_with_ops(ssa);

        let mut phi_defs = HashSet::new();
        let mut non_null_vars = HashSet::new();
        let mut array_length_vars = HashSet::new();
        let mut ranges = HashMap::new();

        for (_block_idx, block) in ssa.iter_blocks() {
            // Process phi nodes (not covered by DefUseIndex)
            for phi in block.phi_nodes() {
                phi_defs.insert(phi.result());
            }

            // Process instructions for specialized tracking
            for instr in block.instructions() {
                let op = instr.op();
                if let Some(dest) = op.dest() {
                    // Track non-null producing operations and value ranges
                    match op {
                        SsaOp::NewObj { .. }
                        | SsaOp::NewArr { .. }
                        | SsaOp::Box { .. }
                        | SsaOp::LoadToken { .. } => {
                            // Non-null tracked separately (not a numeric range)
                            non_null_vars.insert(dest);
                        }
                        SsaOp::ArrayLength { .. } => {
                            array_length_vars.insert(dest);
                            ranges.insert(dest, ValueRange::non_negative());
                        }
                        SsaOp::Const { value, .. } => {
                            if let Some(v) = value.as_i64() {
                                ranges.insert(dest, ValueRange::constant(v));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Self {
            index,
            phi_defs,
            non_null_vars,
            array_length_vars,
            ranges,
        }
    }

    /// Gets the defining operation for a variable.
    fn get_definition(&self, var: SsaVarId) -> Option<&SsaOp> {
        self.index.def_op(var)
    }

    /// Checks if a variable is defined by a phi node.
    fn is_phi_defined(&self, var: SsaVarId) -> bool {
        self.phi_defs.contains(&var)
    }

    /// Checks if a variable is known to be non-null.
    fn is_non_null(&self, var: SsaVarId) -> bool {
        self.non_null_vars.contains(&var)
    }

    /// Gets the value range for a variable.
    fn get_range(&self, var: SsaVarId) -> Option<&ValueRange> {
        self.ranges.get(&var)
    }
}

/// Opaque predicate detection and removal pass.
pub struct OpaquePredicatePass;

impl Default for OpaquePredicatePass {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaquePredicatePass {
    /// Creates a new opaque predicate pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Analyzes a predicate operation with full context.
    fn analyze_predicate_with_cache(
        op: &SsaOp,
        cache: &DefinitionCache,
        depth: usize,
    ) -> PredicateResult {
        // Prevent infinite recursion
        if depth > 10 {
            return PredicateResult::Unknown;
        }

        match op {
            // Self-comparison patterns
            SsaOp::Ceq { left, right, .. } => {
                if left == right {
                    return PredicateResult::AlwaysTrue;
                }
                Self::analyze_equality(*left, *right, cache, depth)
            }

            SsaOp::Clt {
                left,
                right,
                unsigned,
                ..
            } => {
                if left == right {
                    return PredicateResult::AlwaysFalse;
                }
                Self::analyze_less_than(*left, *right, *unsigned, cache, depth)
            }

            SsaOp::Cgt {
                left,
                right,
                unsigned,
                ..
            } => {
                if left == right {
                    return PredicateResult::AlwaysFalse;
                }
                Self::analyze_greater_than(*left, *right, *unsigned, cache, depth)
            }

            // Operations that produce zero
            SsaOp::Xor { left, right, .. } if left == right => {
                // x ^ x = 0, handled when used in comparison
                PredicateResult::Unknown
            }

            SsaOp::Sub { left, right, .. } if left == right => {
                // x - x = 0, handled when used in comparison
                PredicateResult::Unknown
            }

            SsaOp::Rem { left, right, .. } => Self::analyze_remainder(*left, *right, cache, depth),

            SsaOp::Mul { left, right, .. } => {
                Self::analyze_multiplication(*left, *right, cache, depth)
            }

            SsaOp::And { left, right, .. } => Self::analyze_and(*left, *right, cache, depth),

            _ => PredicateResult::Unknown,
        }
    }

    /// Analyzes an equality comparison.
    fn analyze_equality(
        left: SsaVarId,
        right: SsaVarId,
        cache: &DefinitionCache,
        depth: usize,
    ) -> PredicateResult {
        let left_def = cache.get_definition(left);
        let right_def = cache.get_definition(right);

        // Check for (x ^ x) == 0 pattern
        if let Some(SsaOp::Xor {
            left: xl,
            right: xr,
            ..
        }) = left_def
        {
            if xl == xr {
                if let Some(r) = right_def {
                    if Self::is_zero_constant(r) {
                        return PredicateResult::AlwaysTrue;
                    }
                }
            }
        }

        // Symmetric check
        if let Some(SsaOp::Xor {
            left: xl,
            right: xr,
            ..
        }) = right_def
        {
            if xl == xr {
                if let Some(l) = left_def {
                    if Self::is_zero_constant(l) {
                        return PredicateResult::AlwaysTrue;
                    }
                }
            }
        }

        // Check for (x - x) == 0 pattern
        if let Some(SsaOp::Sub {
            left: sl,
            right: sr,
            ..
        }) = left_def
        {
            if sl == sr {
                if let Some(r) = right_def {
                    if Self::is_zero_constant(r) {
                        return PredicateResult::AlwaysTrue;
                    }
                }
            }
        }

        // Symmetric check
        if let Some(SsaOp::Sub {
            left: sl,
            right: sr,
            ..
        }) = right_def
        {
            if sl == sr {
                if let Some(l) = left_def {
                    if Self::is_zero_constant(l) {
                        return PredicateResult::AlwaysTrue;
                    }
                }
            }
        }

        // Check for (x * 0) == 0 pattern
        if Self::is_zero_producing_mul(left_def, cache) {
            if let Some(r) = right_def {
                if Self::is_zero_constant(r) {
                    return PredicateResult::AlwaysTrue;
                }
            }
        }

        // Symmetric check
        if Self::is_zero_producing_mul(right_def, cache) {
            if let Some(l) = left_def {
                if Self::is_zero_constant(l) {
                    return PredicateResult::AlwaysTrue;
                }
            }
        }

        // Check for (x & 0) == 0 pattern
        if Self::is_zero_producing_and(left_def, cache) {
            if let Some(r) = right_def {
                if Self::is_zero_constant(r) {
                    return PredicateResult::AlwaysTrue;
                }
            }
        }

        // Symmetric check
        if Self::is_zero_producing_and(right_def, cache) {
            if let Some(l) = left_def {
                if Self::is_zero_constant(l) {
                    return PredicateResult::AlwaysTrue;
                }
            }
        }

        // Check for number-theoretic predicates: (x * (x + 1)) % 2 == 0
        if Self::is_consecutive_product_mod2(left_def, cache) {
            if let Some(r) = right_def {
                if Self::is_zero_constant(r) {
                    return PredicateResult::AlwaysTrue;
                }
            }
        }

        // Check constant equality
        if let (Some(SsaOp::Const { value: lval, .. }), Some(SsaOp::Const { value: rval, .. })) =
            (left_def, right_def)
        {
            if let (Some(l), Some(r)) = (lval.as_i64(), rval.as_i64()) {
                return if l == r {
                    PredicateResult::AlwaysTrue
                } else {
                    PredicateResult::AlwaysFalse
                };
            }
        }

        // Check non-null equality with null
        if cache.is_non_null(left) {
            if let Some(r) = right_def {
                if Self::is_null_constant(r) {
                    return PredicateResult::AlwaysFalse;
                }
            }
        }

        if cache.is_non_null(right) {
            if let Some(l) = left_def {
                if Self::is_null_constant(l) {
                    return PredicateResult::AlwaysFalse;
                }
            }
        }

        // Nested analysis
        if let Some(left_op) = left_def {
            let left_result = Self::analyze_predicate_with_cache(left_op, cache, depth + 1);
            if left_result != PredicateResult::Unknown {
                if let Some(r) = right_def {
                    if Self::is_one_constant(r) {
                        return left_result;
                    }
                    if Self::is_zero_constant(r) {
                        return left_result.negate();
                    }
                }
            }
        }

        PredicateResult::Unknown
    }

    /// Analyzes a less-than comparison.
    fn analyze_less_than(
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        cache: &DefinitionCache,
        _depth: usize,
    ) -> PredicateResult {
        let left_def = cache.get_definition(left);
        let right_def = cache.get_definition(right);

        // Constant comparison
        if let (Some(SsaOp::Const { value: lval, .. }), Some(SsaOp::Const { value: rval, .. })) =
            (left_def, right_def)
        {
            if unsigned {
                if let (Some(l), Some(r)) = (lval.as_u64(), rval.as_u64()) {
                    return if l < r {
                        PredicateResult::AlwaysTrue
                    } else {
                        PredicateResult::AlwaysFalse
                    };
                }
            } else if let (Some(l), Some(r)) = (lval.as_i64(), rval.as_i64()) {
                return if l < r {
                    PredicateResult::AlwaysTrue
                } else {
                    PredicateResult::AlwaysFalse
                };
            }
        }

        // Range-based analysis
        if let Some(left_range) = cache.get_range(left) {
            if let Some(right_range) = cache.get_range(right) {
                // left.max < right.min => always true
                if let (Some(l_max), Some(r_min)) = (left_range.max(), right_range.min()) {
                    if l_max < r_min {
                        return PredicateResult::AlwaysTrue;
                    }
                }
                // left.min >= right.max => always false
                if let (Some(l_min), Some(r_max)) = (left_range.min(), right_range.max()) {
                    if l_min >= r_max {
                        return PredicateResult::AlwaysFalse;
                    }
                }
            }

            // Check if left < constant
            if let Some(SsaOp::Const { value: rval, .. }) = right_def {
                if let Some(r) = rval.as_i64() {
                    if let Some(result) = left_range.always_less_than(r) {
                        return if result {
                            PredicateResult::AlwaysTrue
                        } else {
                            PredicateResult::AlwaysFalse
                        };
                    }
                }
            }
        }

        // Unsigned comparison: x < 0 is always false
        if unsigned {
            if let Some(SsaOp::Const { value: rval, .. }) = right_def {
                if rval.as_u64() == Some(0) {
                    return PredicateResult::AlwaysFalse;
                }
            }
        }

        // Non-negative < 0 is always false
        if let Some(left_range) = cache.get_range(left) {
            if left_range.is_always_non_negative() {
                if let Some(SsaOp::Const { value: rval, .. }) = right_def {
                    if rval.as_i64() == Some(0) {
                        return PredicateResult::AlwaysFalse;
                    }
                }
            }
        }

        PredicateResult::Unknown
    }

    /// Analyzes a greater-than comparison.
    fn analyze_greater_than(
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        cache: &DefinitionCache,
        _depth: usize,
    ) -> PredicateResult {
        let left_def = cache.get_definition(left);
        let right_def = cache.get_definition(right);

        // Constant comparison
        if let (Some(SsaOp::Const { value: lval, .. }), Some(SsaOp::Const { value: rval, .. })) =
            (left_def, right_def)
        {
            if unsigned {
                if let (Some(l), Some(r)) = (lval.as_u64(), rval.as_u64()) {
                    return if l > r {
                        PredicateResult::AlwaysTrue
                    } else {
                        PredicateResult::AlwaysFalse
                    };
                }
            } else if let (Some(l), Some(r)) = (lval.as_i64(), rval.as_i64()) {
                return if l > r {
                    PredicateResult::AlwaysTrue
                } else {
                    PredicateResult::AlwaysFalse
                };
            }
        }

        // Range-based analysis
        if let Some(left_range) = cache.get_range(left) {
            if let Some(right_range) = cache.get_range(right) {
                // left.min > right.max => always true
                if let (Some(l_min), Some(r_max)) = (left_range.min(), right_range.max()) {
                    if l_min > r_max {
                        return PredicateResult::AlwaysTrue;
                    }
                }
                // left.max <= right.min => always false
                if let (Some(l_max), Some(r_min)) = (left_range.max(), right_range.min()) {
                    if l_max <= r_min {
                        return PredicateResult::AlwaysFalse;
                    }
                }
            }

            // Check if left > constant
            if let Some(SsaOp::Const { value: rval, .. }) = right_def {
                if let Some(r) = rval.as_i64() {
                    if let Some(result) = left_range.always_greater_than(r) {
                        return if result {
                            PredicateResult::AlwaysTrue
                        } else {
                            PredicateResult::AlwaysFalse
                        };
                    }
                }
            }
        }

        // Unsigned: 0 > x is always false
        if unsigned {
            if let Some(SsaOp::Const { value: lval, .. }) = left_def {
                if lval.as_u64() == Some(0) {
                    return PredicateResult::AlwaysFalse;
                }
            }
        }

        // Non-negative value >= 0 is always true (x > -1 equivalent)
        if let Some(left_range) = cache.get_range(left) {
            if left_range.is_always_non_negative() {
                if let Some(SsaOp::Const { value: rval, .. }) = right_def {
                    if rval.as_i64().is_some_and(|r| r < 0) {
                        return PredicateResult::AlwaysTrue;
                    }
                }
            }
        }

        PredicateResult::Unknown
    }

    /// Analyzes a remainder operation.
    fn analyze_remainder(
        _left: SsaVarId,
        right: SsaVarId,
        cache: &DefinitionCache,
        _depth: usize,
    ) -> PredicateResult {
        // x % 1 == 0 is always true
        if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(right) {
            if rval.as_i64() == Some(1) {
                // Result is always 0
                return PredicateResult::Unknown; // Handled when compared to 0
            }
        }
        PredicateResult::Unknown
    }

    /// Analyzes a multiplication for zero-producing patterns.
    fn analyze_multiplication(
        left: SsaVarId,
        right: SsaVarId,
        cache: &DefinitionCache,
        _depth: usize,
    ) -> PredicateResult {
        // x * 0 = 0
        if let Some(SsaOp::Const { value: lval, .. }) = cache.get_definition(left) {
            if lval.is_zero() {
                return PredicateResult::Unknown; // Result is 0
            }
        }
        if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(right) {
            if rval.is_zero() {
                return PredicateResult::Unknown; // Result is 0
            }
        }
        PredicateResult::Unknown
    }

    /// Analyzes a bitwise AND for zero-producing patterns.
    fn analyze_and(
        left: SsaVarId,
        right: SsaVarId,
        cache: &DefinitionCache,
        _depth: usize,
    ) -> PredicateResult {
        // x & 0 = 0
        if let Some(SsaOp::Const { value: lval, .. }) = cache.get_definition(left) {
            if lval.is_zero() {
                return PredicateResult::Unknown;
            }
        }
        if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(right) {
            if rval.is_zero() {
                return PredicateResult::Unknown;
            }
        }
        PredicateResult::Unknown
    }

    /// Checks if an operation produces a constant zero.
    fn is_zero_constant(op: &SsaOp) -> bool {
        matches!(op, SsaOp::Const { value, .. } if value.is_zero())
    }

    /// Checks if an operation produces a constant one.
    fn is_one_constant(op: &SsaOp) -> bool {
        matches!(op, SsaOp::Const { value, .. } if value.is_one())
    }

    /// Checks if an operation produces a null constant.
    fn is_null_constant(op: &SsaOp) -> bool {
        matches!(op, SsaOp::Const { value, .. } if value.is_null())
    }

    /// Checks if an operation produces a constant -1.
    fn is_minus_one_constant(op: &SsaOp) -> bool {
        matches!(op, SsaOp::Const { value, .. } if value.is_minus_one())
    }

    /// Checks if a multiplication produces zero.
    fn is_zero_producing_mul(op: Option<&SsaOp>, cache: &DefinitionCache) -> bool {
        if let Some(SsaOp::Mul { left, right, .. }) = op {
            if let Some(l) = cache.get_definition(*left) {
                if Self::is_zero_constant(l) {
                    return true;
                }
            }
            if let Some(r) = cache.get_definition(*right) {
                if Self::is_zero_constant(r) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if an AND produces zero.
    fn is_zero_producing_and(op: Option<&SsaOp>, cache: &DefinitionCache) -> bool {
        if let Some(SsaOp::And { left, right, .. }) = op {
            if let Some(l) = cache.get_definition(*left) {
                if Self::is_zero_constant(l) {
                    return true;
                }
            }
            if let Some(r) = cache.get_definition(*right) {
                if Self::is_zero_constant(r) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if an operation is (x * (x + 1)) % 2, which is always 0.
    /// This detects the classic number-theoretic opaque predicate.
    fn is_consecutive_product_mod2(op: Option<&SsaOp>, cache: &DefinitionCache) -> bool {
        // Look for: (something) % 2 where something is x * (x + 1)
        if let Some(SsaOp::Rem {
            left: rem_left,
            right: rem_right,
            ..
        }) = op
        {
            // Check if divisor is 2
            if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(*rem_right) {
                if rval.as_i64() != Some(2) {
                    return false;
                }
            } else {
                return false;
            }

            // Check if dividend is a multiplication
            if let Some(SsaOp::Mul {
                left: mul_left,
                right: mul_right,
                ..
            }) = cache.get_definition(*rem_left)
            {
                return Self::is_consecutive_pair(*mul_left, *mul_right, cache);
            }
        }
        false
    }

    /// Checks if two values form a consecutive pair (x and x+1 or x-1 and x).
    fn is_consecutive_pair(a: SsaVarId, b: SsaVarId, cache: &DefinitionCache) -> bool {
        // Check if b = a + 1
        if let Some(SsaOp::Add {
            left: add_left,
            right: add_right,
            ..
        }) = cache.get_definition(b)
        {
            if *add_left == a {
                if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(*add_right) {
                    if rval.as_i64() == Some(1) {
                        return true;
                    }
                }
            }
            if *add_right == a {
                if let Some(SsaOp::Const { value: lval, .. }) = cache.get_definition(*add_left) {
                    if lval.as_i64() == Some(1) {
                        return true;
                    }
                }
            }
        }

        // Check if a = b + 1 (symmetric)
        if let Some(SsaOp::Add {
            left: add_left,
            right: add_right,
            ..
        }) = cache.get_definition(a)
        {
            if *add_left == b {
                if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(*add_right) {
                    if rval.as_i64() == Some(1) {
                        return true;
                    }
                }
            }
            if *add_right == b {
                if let Some(SsaOp::Const { value: lval, .. }) = cache.get_definition(*add_left) {
                    if lval.as_i64() == Some(1) {
                        return true;
                    }
                }
            }
        }

        // Check if b = a - (-1) which is also a + 1
        if let Some(SsaOp::Sub {
            left: sub_left,
            right: sub_right,
            ..
        }) = cache.get_definition(b)
        {
            if *sub_left == a {
                if let Some(SsaOp::Const { value: rval, .. }) = cache.get_definition(*sub_right) {
                    if rval.as_i64() == Some(-1) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Analyzes a branch condition.
    fn analyze_branch(condition: SsaVarId, cache: &DefinitionCache) -> PredicateResult {
        // Follow Copy chain iteratively with cycle detection to prevent infinite recursion.
        // This is needed because SSA can have Copy cycles (e.g., from phi nodes or
        // obfuscated control flow patterns).
        let mut current = condition;
        let mut visited = HashSet::new();

        loop {
            // Cycle detection: if we've seen this variable before, bail out
            if !visited.insert(current) {
                return PredicateResult::Unknown;
            }

            let Some(cond_op) = cache.get_definition(current) else {
                // Check if it's a phi node - analyze all operands
                if cache.is_phi_defined(current) {
                    // For phi nodes, we'd need to check if all operands lead to the same result
                    // This is complex, so we return Unknown for now unless we have range info
                    if let Some(range) = cache.get_range(current) {
                        if let Some(result) = range.always_equal_to(0) {
                            return if result {
                                PredicateResult::AlwaysFalse
                            } else {
                                PredicateResult::AlwaysTrue
                            };
                        }
                    }
                }
                return PredicateResult::Unknown;
            };

            // First, check if it's a direct comparison predicate
            let predicate_result = Self::analyze_predicate_with_cache(cond_op, cache, 0);
            if predicate_result != PredicateResult::Unknown {
                return predicate_result;
            }

            // Check if the condition is a Copy - trace through to the source iteratively
            if let SsaOp::Copy { src, .. } = cond_op {
                current = *src;
                continue;
            }

            // Not a Copy, break out and analyze the operation
            return Self::analyze_branch_op(cond_op, cache);
        }
    }

    /// Analyzes a branch condition operation (after Copy chain has been resolved).
    fn analyze_branch_op(cond_op: &SsaOp, cache: &DefinitionCache) -> PredicateResult {
        // Check operations that produce known zero values
        match cond_op {
            // x ^ x = 0, so brtrue on this result never jumps
            SsaOp::Xor { left, right, .. } if left == right => PredicateResult::AlwaysFalse,

            // x - x = 0, so brtrue on this result never jumps
            SsaOp::Sub { left, right, .. } if left == right => PredicateResult::AlwaysFalse,

            // x & 0 = 0, x * 0 = 0
            SsaOp::And { left, right, .. } | SsaOp::Mul { left, right, .. } => {
                let is_left_zero = cache
                    .get_definition(*left)
                    .is_some_and(Self::is_zero_constant);
                let is_right_zero = cache
                    .get_definition(*right)
                    .is_some_and(Self::is_zero_constant);

                if is_left_zero || is_right_zero {
                    PredicateResult::AlwaysFalse
                } else {
                    PredicateResult::Unknown
                }
            }

            // x | -1 = -1 (all bits set), so brtrue always jumps
            SsaOp::Or { left, right, .. } => {
                let is_left_minus_one = cache
                    .get_definition(*left)
                    .is_some_and(Self::is_minus_one_constant);
                let is_right_minus_one = cache
                    .get_definition(*right)
                    .is_some_and(Self::is_minus_one_constant);

                if is_left_minus_one || is_right_minus_one {
                    PredicateResult::AlwaysTrue
                } else {
                    PredicateResult::Unknown
                }
            }

            // Constant values: 0/null/false is always false, non-zero is always true
            SsaOp::Const { value, .. } => {
                if value.is_zero() || value.is_null() {
                    PredicateResult::AlwaysFalse
                } else if value.as_i64().is_some() || value.as_bool().is_some() {
                    // Non-zero numeric or true boolean
                    PredicateResult::AlwaysTrue
                } else {
                    PredicateResult::Unknown
                }
            }

            // All other operations have unknown truthiness
            // Note: ArrayLength is always >= 0, but we can't prove non-empty
            _ => PredicateResult::Unknown,
        }
    }

    /// Analyzes a comparison operation for algebraic simplification opportunities.
    ///
    /// This checks for patterns like:
    /// - `(x - y) == 0` → `x == y`
    /// - `(x - y) < 0` → `x < y`
    /// - `(x - y) > 0` → `x > y`
    /// - `(x ^ y) == 0` → `x == y`
    /// - `(cmp) == 1` → `cmp`
    fn analyze_comparison_simplification(
        op: &SsaOp,
        cache: &DefinitionCache,
    ) -> Option<ComparisonSimplification> {
        match op {
            SsaOp::Ceq { dest, left, right } => {
                Self::analyze_ceq_simplification(*dest, *left, *right, cache)
            }
            SsaOp::Clt {
                dest,
                left,
                right,
                unsigned,
            } => Self::analyze_clt_simplification(*dest, *left, *right, *unsigned, cache),
            SsaOp::Cgt {
                dest,
                left,
                right,
                unsigned,
            } => Self::analyze_cgt_simplification(*dest, *left, *right, *unsigned, cache),
            _ => None,
        }
    }

    /// Checks if a variable is defined as a constant zero.
    fn is_zero_var(var: SsaVarId, cache: &DefinitionCache) -> bool {
        cache
            .get_definition(var)
            .is_some_and(Self::is_zero_constant)
    }

    /// Checks if a variable is defined as a constant with value 1.
    fn is_one_var(var: SsaVarId, cache: &DefinitionCache) -> bool {
        cache.get_definition(var).is_some_and(Self::is_one_constant)
    }

    /// Analyzes a Ceq operation for simplification.
    fn analyze_ceq_simplification(
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        cache: &DefinitionCache,
    ) -> Option<ComparisonSimplification> {
        // Check if comparing to zero
        let (other_var, is_comparing_to_zero) = if Self::is_zero_var(right, cache) {
            (left, true)
        } else if Self::is_zero_var(left, cache) {
            (right, true)
        } else {
            (left, false)
        };

        if is_comparing_to_zero {
            if let Some(def_op) = cache.get_definition(other_var) {
                // Pattern: (x - y) == 0 → x == y
                if let SsaOp::Sub {
                    left: sub_left,
                    right: sub_right,
                    ..
                } = def_op
                {
                    // Skip self-subtraction - that's handled by PredicateResult (always true)
                    if sub_left != sub_right {
                        return Some(ComparisonSimplification::SimplerOp {
                            new_op: SsaOp::Ceq {
                                dest,
                                left: *sub_left,
                                right: *sub_right,
                            },
                            reason: "(x - y) == 0 simplified to x == y",
                        });
                    }
                }

                // Pattern: (x ^ y) == 0 → x == y
                if let SsaOp::Xor {
                    left: xor_left,
                    right: xor_right,
                    ..
                } = def_op
                {
                    // Skip self-XOR - that's handled by PredicateResult (always true)
                    if xor_left != xor_right {
                        return Some(ComparisonSimplification::SimplerOp {
                            new_op: SsaOp::Ceq {
                                dest,
                                left: *xor_left,
                                right: *xor_right,
                            },
                            reason: "(x ^ y) == 0 simplified to x == y",
                        });
                    }
                }
            }
        }

        // Check if comparing to one (true in CIL)
        let (other_var, is_comparing_to_one) = if Self::is_one_var(right, cache) {
            (left, true)
        } else if Self::is_one_var(left, cache) {
            (right, true)
        } else {
            (left, false)
        };

        if is_comparing_to_one {
            if let Some(def_op) = cache.get_definition(other_var) {
                // Pattern: (cmp) == 1 → copy cmp
                if matches!(
                    def_op,
                    SsaOp::Ceq { .. } | SsaOp::Clt { .. } | SsaOp::Cgt { .. }
                ) {
                    return Some(ComparisonSimplification::Copy {
                        dest,
                        src: other_var,
                        reason: "(cmp) == 1 simplified to cmp",
                    });
                }
            }
        }

        None
    }

    /// Analyzes a Clt operation for simplification.
    fn analyze_clt_simplification(
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        cache: &DefinitionCache,
    ) -> Option<ComparisonSimplification> {
        // Only handle signed comparisons for subtraction patterns
        // (unsigned subtraction has different overflow semantics)
        if unsigned {
            return None;
        }

        // Pattern: (x - y) < 0 → x < y
        if Self::is_zero_var(right, cache) {
            if let Some(SsaOp::Sub {
                left: sub_left,
                right: sub_right,
                ..
            }) = cache.get_definition(left)
            {
                // Skip self-subtraction - that's handled by PredicateResult (always false)
                if sub_left != sub_right {
                    return Some(ComparisonSimplification::SimplerOp {
                        new_op: SsaOp::Clt {
                            dest,
                            left: *sub_left,
                            right: *sub_right,
                            unsigned,
                        },
                        reason: "(x - y) < 0 simplified to x < y",
                    });
                }
            }
        }

        None
    }

    /// Analyzes a Cgt operation for simplification.
    fn analyze_cgt_simplification(
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        cache: &DefinitionCache,
    ) -> Option<ComparisonSimplification> {
        // Only handle signed comparisons for subtraction patterns
        if unsigned {
            return None;
        }

        // Pattern: (x - y) > 0 → x > y
        if Self::is_zero_var(right, cache) {
            if let Some(SsaOp::Sub {
                left: sub_left,
                right: sub_right,
                ..
            }) = cache.get_definition(left)
            {
                // Skip self-subtraction - that's handled by PredicateResult (always false)
                if sub_left != sub_right {
                    return Some(ComparisonSimplification::SimplerOp {
                        new_op: SsaOp::Cgt {
                            dest,
                            left: *sub_left,
                            right: *sub_right,
                            unsigned,
                        },
                        reason: "(x - y) > 0 simplified to x > y",
                    });
                }
            }
        }

        None
    }

    /// Attempts to evaluate a branch condition using the SsaEvaluator.
    ///
    /// This is used as a fallback when pattern matching returns Unknown.
    /// The SsaEvaluator can propagate values through operations and
    /// determine branch conditions that require dataflow analysis.
    fn evaluate_with_tracked(
        ssa: &SsaFunction,
        condition: SsaVarId,
        block_idx: usize,
        ptr_size: PointerSize,
    ) -> PredicateResult {
        let mut evaluator = SsaEvaluator::new(ssa, ptr_size);

        // Evaluate all blocks up to and including the current block.
        // We use a simple forward pass - in complex cases with loops,
        // this may not capture all values, but it handles linear flows.
        for idx in 0..=block_idx {
            // For blocks that precede our target, we can evaluate them
            // to build up the value state
            evaluator.evaluate_block(idx);
        }

        // Check if we have a concrete value for the condition
        match evaluator.get(condition) {
            Some(expr) if expr.is_constant() => {
                if expr.as_constant().is_some_and(ConstValue::is_zero) {
                    PredicateResult::AlwaysFalse
                } else {
                    PredicateResult::AlwaysTrue
                }
            }
            Some(_) | None => PredicateResult::Unknown,
        }
    }

    /// Analyzes phi nodes where all operands are the same constant.
    fn analyze_phi_constants(ssa: &SsaFunction) -> HashMap<SsaVarId, ConstValue> {
        let mut phi_constants = HashMap::new();

        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                let operands: Vec<_> = phi.operands().iter().collect();
                if operands.is_empty() {
                    continue;
                }

                // Check if all operands come from the same constant
                let first_val = operands[0].value();
                let mut all_same_const = true;
                let mut const_value = None;

                for operand in &operands {
                    let var = operand.value();
                    // Look up the definition
                    if let Some(op) = ssa.get_definition(var) {
                        if let SsaOp::Const { value, .. } = op {
                            if const_value.is_none() {
                                const_value = Some(value.clone());
                            } else if const_value.as_ref() != Some(value) {
                                all_same_const = false;
                                break;
                            }
                        } else {
                            all_same_const = false;
                            break;
                        }
                    } else if var != first_val {
                        all_same_const = false;
                        break;
                    }
                }

                if all_same_const {
                    if let Some(value) = const_value {
                        phi_constants.insert(phi.result(), value);
                    }
                }
            }
        }

        phi_constants
    }
}

impl SsaPass for OpaquePredicatePass {
    fn name(&self) -> &'static str {
        "opaque-predicate-removal"
    }

    fn description(&self) -> &'static str {
        "Detects and removes opaque predicates (always-true/false conditions)"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let changes = EventLog::new();

        // Build definition cache for efficient lookup
        let cache = DefinitionCache::build(ssa);

        // Analyze phi nodes for constant values
        let phi_constants = Self::analyze_phi_constants(ssa);

        // Collect branches to simplify
        let mut branch_simplifications: Vec<(usize, usize, bool)> = Vec::new();

        // Collect comparison replacements (opaque predicates that become constant true/false)
        let mut comparison_replacements: Vec<(usize, usize, SsaVarId, bool)> = Vec::new();

        // Collect comparison simplifications (algebraic simplifications like (x-y)==0 → x==y)
        let mut comparison_simplifications: Vec<(usize, usize, ComparisonSimplification)> =
            Vec::new();

        // Collect phi replacements
        let mut phi_replacements: Vec<(usize, usize, SsaVarId, ConstValue)> = Vec::new();

        // Analyze each block
        for (block_idx, block) in ssa.iter_blocks() {
            // Analyze branch terminators
            if let Some(SsaOp::Branch {
                condition,
                true_target,
                false_target,
            }) = block.terminator_op()
            {
                // Check phi constants first
                if let Some(const_val) = phi_constants.get(condition) {
                    let is_true = const_val.as_bool().unwrap_or(false)
                        || const_val.as_i64().is_some_and(|v| v != 0);
                    if is_true {
                        branch_simplifications.push((block_idx, *true_target, true));
                    } else {
                        branch_simplifications.push((block_idx, *false_target, false));
                    }
                    // Can't use continue with iter_blocks in a for loop, collect the data
                } else {
                    let mut result = Self::analyze_branch(*condition, &cache);

                    // If pattern matching couldn't determine the result,
                    // try using SsaEvaluator for dataflow-based analysis
                    if result == PredicateResult::Unknown {
                        let ptr_size = PointerSize::from_pe(assembly.file().pe().is_64bit);
                        result = Self::evaluate_with_tracked(ssa, *condition, block_idx, ptr_size);
                    }

                    match result {
                        PredicateResult::AlwaysTrue => {
                            branch_simplifications.push((block_idx, *true_target, true));
                        }
                        PredicateResult::AlwaysFalse => {
                            branch_simplifications.push((block_idx, *false_target, false));
                        }
                        PredicateResult::Unknown => {}
                    }
                }
            }

            // Analyze comparison instructions
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let op = instr.op();
                // First check for opaque predicates (constant true/false)
                let result = Self::analyze_predicate_with_cache(op, &cache, 0);
                if let Some(value) = result.as_bool() {
                    if let Some(dest) = op.dest() {
                        comparison_replacements.push((block_idx, instr_idx, dest, value));
                        continue; // Don't also check for simplification
                    }
                }

                // Then check for algebraic simplifications
                if let Some(simplification) = Self::analyze_comparison_simplification(op, &cache) {
                    comparison_simplifications.push((block_idx, instr_idx, simplification));
                }
            }

            // Check for phi nodes that can be replaced with constants
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                if let Some(const_val) = phi_constants.get(&phi.result()) {
                    phi_replacements.push((block_idx, phi_idx, phi.result(), const_val.clone()));
                }
            }
        }

        // Apply branch simplifications
        for (block_idx, target, is_true) in branch_simplifications {
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(last_instr) = block.instructions_mut().last_mut() {
                    last_instr.set_op(SsaOp::Jump { target });
                    changes
                        .record(EventKind::OpaquePredicateRemoved)
                        .at(method_token, block_idx)
                        .message(format!(
                            "removed opaque predicate (always {})",
                            if is_true { "true" } else { "false" }
                        ));
                    changes
                        .record(EventKind::BranchSimplified)
                        .at(method_token, block_idx)
                        .message(format!("simplified to unconditional branch to {target}"));
                }
            }
        }

        // Apply comparison replacements (opaque predicates → constant true/false)
        for (block_idx, instr_idx, dest, value) in comparison_replacements {
            if let Some(block) = ssa.block_mut(block_idx) {
                let const_value = if value {
                    ConstValue::True
                } else {
                    ConstValue::False
                };
                block.instructions_mut()[instr_idx].set_op(SsaOp::Const {
                    dest,
                    value: const_value,
                });
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, instr_idx)
                    .message(format!("opaque predicate → {value}"));
            }
        }

        // Apply comparison simplifications (algebraic transformations)
        for (block_idx, instr_idx, simplification) in comparison_simplifications {
            if let Some(block) = ssa.block_mut(block_idx) {
                match simplification {
                    ComparisonSimplification::SimplerOp { new_op, reason } => {
                        block.instructions_mut()[instr_idx].set_op(new_op);
                        changes
                            .record(EventKind::ConstantFolded)
                            .at(method_token, instr_idx)
                            .message(reason);
                    }
                    ComparisonSimplification::Copy { dest, src, reason } => {
                        block.instructions_mut()[instr_idx].set_op(SsaOp::Copy { dest, src });
                        changes
                            .record(EventKind::ConstantFolded)
                            .at(method_token, instr_idx)
                            .message(reason);
                    }
                }
            }
        }

        // Apply phi replacements: PHIs where all operands are the same constant
        // We replace the PHI with a constant instruction and remove the PHI.
        // Process in reverse order to handle phi_idx correctly when removing.
        let mut phi_removals: Vec<(usize, usize)> = Vec::new();
        for (block_idx, phi_idx, phi_result, const_value) in phi_replacements {
            // Create a constant instruction with the same destination as the PHI
            let const_instr = SsaInstruction::synthetic(SsaOp::Const {
                dest: phi_result,
                value: const_value.clone(),
            });

            // Insert at the beginning of the block's instructions
            if let Some(block) = ssa.block_mut(block_idx) {
                block.instructions_mut().insert(0, const_instr);
            }

            // Mark this phi for removal
            phi_removals.push((block_idx, phi_idx));

            changes
                .record(EventKind::ConstantFolded)
                .at(method_token, block_idx)
                .message(format!("phi with constant operands → {const_value:?}"));
        }

        // Remove the PHIs (in reverse order to maintain correct indices)
        phi_removals.sort_by(|a, b| b.cmp(a)); // Sort descending by (block_idx, phi_idx)
        for (block_idx, phi_idx) in phi_removals {
            if let Some(block) = ssa.block_mut(block_idx) {
                if phi_idx < block.phi_nodes().len() {
                    block.phi_nodes_mut().remove(phi_idx);
                }
            }
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::{MethodRef, SsaFunctionBuilder};

    use super::*;

    #[test]
    fn test_predicate_result() {
        assert_eq!(PredicateResult::AlwaysTrue.as_bool(), Some(true));
        assert_eq!(PredicateResult::AlwaysFalse.as_bool(), Some(false));
        assert_eq!(PredicateResult::Unknown.as_bool(), None);

        assert_eq!(
            PredicateResult::AlwaysTrue.negate(),
            PredicateResult::AlwaysFalse
        );
        assert_eq!(
            PredicateResult::AlwaysFalse.negate(),
            PredicateResult::AlwaysTrue
        );
        assert_eq!(PredicateResult::Unknown.negate(), PredicateResult::Unknown);
    }

    #[test]
    fn test_self_equality() {
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v = b.const_i32(42);
                    v0_out = v;
                    v1_out = b.ceq(v, v); // v1 = ceq v0, v0 (always true)
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out)
        };

        let cache = DefinitionCache::build(&ssa);
        let op = SsaOp::Ceq {
            dest: v1,
            left: v0,
            right: v0,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysTrue
        );
    }

    #[test]
    fn test_self_less_than() {
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v = b.const_i32(42);
                    v0_out = v;
                    v1_out = b.clt(v, v);
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out)
        };

        let cache = DefinitionCache::build(&ssa);

        // x < x is always false
        let op = SsaOp::Clt {
            dest: v1,
            left: v0,
            right: v0,
            unsigned: false,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysFalse
        );
    }

    #[test]
    fn test_xor_self_equals_zero() {
        let (ssa, v1, v2, v3) = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let mut v3_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let v1 = b.xor(v0, v0); // v1 = v0 ^ v0 (always 0)
                    v1_out = v1;
                    let v2 = b.const_i32(0);
                    v2_out = v2;
                    v3_out = b.ceq(v1, v2); // v3 = ceq v1, v2 (always true)
                    b.ret();
                });
            });
            (ssa, v1_out, v2_out, v3_out)
        };

        let cache = DefinitionCache::build(&ssa);
        let op = SsaOp::Ceq {
            dest: v3,
            left: v1,
            right: v2,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysTrue
        );
    }

    #[test]
    fn test_constant_comparison() {
        let (ssa, v0, v1, v2) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(5);
                    v0_out = v0;
                    let v1 = b.const_i32(10);
                    v1_out = v1;
                    v2_out = b.clt(v0, v1);
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out, v2_out)
        };

        let cache = DefinitionCache::build(&ssa);

        // 5 < 10 is always true
        let op = SsaOp::Clt {
            dest: v2,
            left: v0,
            right: v1,
            unsigned: false,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysTrue
        );

        // 5 > 10 is always false
        let op = SsaOp::Cgt {
            dest: v2,
            left: v0,
            right: v1,
            unsigned: false,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysFalse
        );
    }

    #[test]
    fn test_unsigned_comparison() {
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_val(ConstValue::U32(5));
                    v0_out = v0;
                    let v1 = b.const_val(ConstValue::U32(0));
                    v1_out = v1;
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out)
        };

        let cache = DefinitionCache::build(&ssa);

        // unsigned x < 0 is always false
        let dest = SsaVarId::new();
        let op = SsaOp::Clt {
            dest,
            left: v0,
            right: v1,
            unsigned: true,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysFalse
        );
    }

    #[test]
    fn test_newobj_non_null() {
        let (ssa, v0, v1) = {
            let mut v0_out = SsaVarId::new();
            let mut v1_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    // v0 = newobj (always non-null)
                    let v0 = b.newobj(MethodRef::new(Token::new(0x06000001)), &[]);
                    v0_out = v0;
                    // v1 = null
                    let v1 = b.const_null();
                    v1_out = v1;
                    b.ret();
                });
            });
            (ssa, v0_out, v1_out)
        };

        let cache = DefinitionCache::build(&ssa);

        // newobj result == null is always false
        let dest = SsaVarId::new();
        let op = SsaOp::Ceq {
            dest,
            left: v0,
            right: v1,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysFalse
        );
    }

    #[test]
    fn test_array_length_non_negative() {
        let (ssa, v1, v2) = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    // v0 = some array (placeholder)
                    let v0 = b.const_null();
                    // v1 = array.Length (always >= 0)
                    let v1 = b.array_length(v0);
                    v1_out = v1;
                    // v2 = 0
                    let v2 = b.const_i32(0);
                    v2_out = v2;
                    b.ret();
                });
            });
            (ssa, v1_out, v2_out)
        };

        let cache = DefinitionCache::build(&ssa);

        // array.Length < 0 is always false
        let dest = SsaVarId::new();
        let op = SsaOp::Clt {
            dest,
            left: v1,
            right: v2,
            unsigned: false,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysFalse
        );
    }

    #[test]
    fn test_multiply_by_zero() {
        let (ssa, v1, v2) = {
            let mut v1_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    let v1 = b.const_i32(0);
                    v1_out = v1;
                    let v2 = b.mul(v0, v1); // v2 = v0 * v1 (always 0)
                    v2_out = v2;
                    let _ = b.ceq(v2, v1); // v3 = ceq v2, v1 (always true)
                    b.ret();
                });
            });
            (ssa, v1_out, v2_out)
        };

        let cache = DefinitionCache::build(&ssa);
        let dest = SsaVarId::new();
        let op = SsaOp::Ceq {
            dest,
            left: v2,
            right: v1,
        };

        assert_eq!(
            OpaquePredicatePass::analyze_predicate_with_cache(&op, &cache, 0),
            PredicateResult::AlwaysTrue
        );
    }

    #[test]
    fn test_value_range() {
        let range = ValueRange::constant(5);
        assert_eq!(range.always_less_than(10), Some(true));
        assert_eq!(range.always_less_than(5), Some(false));
        assert_eq!(range.always_less_than(3), Some(false));

        assert_eq!(range.always_greater_than(3), Some(true));
        assert_eq!(range.always_greater_than(5), Some(false));
        assert_eq!(range.always_greater_than(10), Some(false));

        assert_eq!(range.always_equal_to(5), Some(true));
        assert_eq!(range.always_equal_to(3), Some(false));

        let non_neg = ValueRange::non_negative();
        assert!(non_neg.is_always_non_negative());
        assert_eq!(non_neg.always_less_than(0), Some(false));
    }

    #[test]
    fn test_consecutive_pair_detection() {
        let (ssa, v0, v2) = {
            let mut v0_out = SsaVarId::new();
            let mut v2_out = SsaVarId::new();
            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(5);
                    v0_out = v0;
                    let v1 = b.const_i32(1);
                    let v2 = b.add(v0, v1); // v2 = v0 + v1 (x + 1)
                    v2_out = v2;
                    b.ret();
                });
            });
            (ssa, v0_out, v2_out)
        };

        let cache = DefinitionCache::build(&ssa);

        // v0 and v2 should be detected as consecutive pair (x and x+1)
        assert!(OpaquePredicatePass::is_consecutive_pair(v0, v2, &cache));
    }

    #[test]
    fn test_phi_constant_analysis() {
        let (ssa, phi_var) = {
            let mut c0_out = SsaVarId::new();
            let mut c1_out = SsaVarId::new();
            let mut phi_out = SsaVarId::new();

            let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
                f.block(0, |b| {
                    c0_out = b.const_i32(42);
                    b.jump(2);
                });
                f.block(1, |b| {
                    c1_out = b.const_i32(42); // Same constant
                    b.jump(2);
                });
                f.block(2, |b| {
                    phi_out = b.phi(&[(0, c0_out), (1, c1_out)]);
                });
            });

            (ssa, phi_out)
        };

        let phi_constants = OpaquePredicatePass::analyze_phi_constants(&ssa);

        // The phi should be recognized as constant since both operands are 42
        assert!(phi_constants.contains_key(&phi_var));
        assert_eq!(phi_constants.get(&phi_var), Some(&ConstValue::I32(42)));
    }
}
