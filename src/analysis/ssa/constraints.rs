//! Constraint types for SSA path analysis.
//!
//! This module provides constraint types used during path-aware SSA evaluation.
//! These constraints represent facts learned from branch conditions while
//! traversing specific paths through the control flow graph.
//!
//! # Constraint Types
//!
//! - [`Constraint`]: A constraint on a single value (e.g., `x == 5`, `x > 10`)
//! - [`PathConstraint`]: Associates a constraint with a specific SSA variable
//!
//! # Usage with SsaEvaluator
//!
//! The [`SsaEvaluator`](super::SsaEvaluator) tracks path constraints during evaluation.
//! When taking a branch, the evaluator records constraints that must hold on that path.
//!
//! For example, after taking the true branch of `if (x == 5)`:
//! - We know `x == 5` on this path
//! - This is recorded as `PathConstraint { variable: x, constraint: Constraint::Equal(ConstValue::I32(5)) }`
//!
//! # Use Cases
//!
//! - Constraint solving with Z3
//! - Value range analysis
//! - Dead code detection
//! - Path-sensitive constant propagation

use crate::analysis::ssa::{ConstValue, SsaVarId};

/// A constraint on a variable's value derived from branch conditions.
///
/// When following a specific branch path, we can derive facts about variable values.
/// For example, after taking the true branch of `if (x == 5)`, we know `x == 5`.
#[derive(Debug, Clone, PartialEq)]
pub enum Constraint {
    /// Variable equals a concrete value: `x == value`
    Equal(ConstValue),
    /// Variable does not equal a concrete value: `x != value`
    NotEqual(ConstValue),
    /// Variable is greater than a value (signed): `x > value`
    GreaterThan(ConstValue),
    /// Variable is less than a value (signed): `x < value`
    LessThan(ConstValue),
    /// Variable is greater than or equal (signed): `x >= value`
    GreaterOrEqual(ConstValue),
    /// Variable is less than or equal (signed): `x <= value`
    LessOrEqual(ConstValue),
    /// Variable is greater than (unsigned): `(uint)x > value`
    GreaterThanUnsigned(ConstValue),
    /// Variable is less than (unsigned): `(uint)x < value`
    LessThanUnsigned(ConstValue),
}

impl Constraint {
    /// Checks if a concrete value satisfies this constraint.
    ///
    /// Uses typed comparison methods from `ConstValue`.
    #[must_use]
    pub fn is_satisfied_by(&self, value: &ConstValue) -> bool {
        match self {
            Self::Equal(v) => value.ceq(v).is_some_and(|r| !r.is_zero()),
            Self::NotEqual(v) => value.ceq(v).is_some_and(|r| r.is_zero()),
            Self::GreaterThan(v) => value.cgt(v).is_some_and(|r| !r.is_zero()),
            Self::LessThan(v) => value.clt(v).is_some_and(|r| !r.is_zero()),
            Self::GreaterOrEqual(v) => value.clt(v).is_some_and(|r| r.is_zero()),
            Self::LessOrEqual(v) => value.cgt(v).is_some_and(|r| r.is_zero()),
            Self::GreaterThanUnsigned(v) => value.cgt_un(v).is_some_and(|r| !r.is_zero()),
            Self::LessThanUnsigned(v) => value.clt_un(v).is_some_and(|r| !r.is_zero()),
        }
    }

    /// Returns the concrete value if this is an equality constraint.
    #[must_use]
    pub fn as_equal(&self) -> Option<&ConstValue> {
        match self {
            Self::Equal(v) => Some(v),
            _ => None,
        }
    }

    /// Checks if this constraint conflicts with another (both can't be true).
    #[must_use]
    pub fn conflicts_with(&self, other: &Constraint) -> bool {
        match (self, other) {
            // x == a conflicts with x == b (if a != b)
            (Self::Equal(a), Self::Equal(b)) => a != b,
            // x == a conflicts with x != a
            (Self::Equal(a), Self::NotEqual(b)) | (Self::NotEqual(b), Self::Equal(a)) => a == b,
            // x == a conflicts with x > b when a <= b (i.e., a is not greater than b)
            (Self::Equal(a), Self::GreaterThan(b)) | (Self::GreaterThan(b), Self::Equal(a)) => {
                // a <= b means a is not strictly greater than b
                a.cgt(b).is_none_or(|r| r.is_zero())
            }
            // x == a conflicts with x < b when a >= b (i.e., a is not less than b)
            (Self::Equal(a), Self::LessThan(b)) | (Self::LessThan(b), Self::Equal(a)) => {
                // a >= b means a is not strictly less than b
                a.clt(b).is_none_or(|r| r.is_zero())
            }
            // x > a conflicts with x < b if ranges don't overlap
            (Self::GreaterThan(a), Self::LessThan(b))
            | (Self::LessThan(b), Self::GreaterThan(a)) => {
                // x > a AND x < b requires b > a + 1 (there must be room for at least one integer)
                // Conflicts when b <= a + 1
                let one = ConstValue::I32(1);
                a.add(&one)
                    .and_then(|a_plus_1| b.cgt(&a_plus_1))
                    .is_none_or(|r| r.is_zero())
            }
            _ => false,
        }
    }
}

/// A constraint on a path derived from branch conditions.
///
/// Associates a [`Constraint`] with a specific SSA variable. These constraints
/// are accumulated during path evaluation and can be used for constraint
/// solving with Z3.
#[derive(Debug, Clone, PartialEq)]
pub struct PathConstraint {
    /// The variable this constraint applies to.
    pub variable: SsaVarId,
    /// The constraint on the variable's value.
    pub constraint: Constraint,
}

impl PathConstraint {
    /// Creates a new equality constraint.
    #[must_use]
    pub fn equal(variable: SsaVarId, value: ConstValue) -> Self {
        Self {
            variable,
            constraint: Constraint::Equal(value),
        }
    }

    /// Creates a new inequality constraint.
    #[must_use]
    pub fn not_equal(variable: SsaVarId, value: ConstValue) -> Self {
        Self {
            variable,
            constraint: Constraint::NotEqual(value),
        }
    }

    /// Creates a new less-than constraint.
    #[must_use]
    pub fn less_than(variable: SsaVarId, value: ConstValue) -> Self {
        Self {
            variable,
            constraint: Constraint::LessThan(value),
        }
    }

    /// Creates a new greater-than constraint.
    #[must_use]
    pub fn greater_than(variable: SsaVarId, value: ConstValue) -> Self {
        Self {
            variable,
            constraint: Constraint::GreaterThan(value),
        }
    }

    /// Checks if a concrete value satisfies this constraint.
    #[must_use]
    pub fn is_satisfied_by(&self, value: &ConstValue) -> bool {
        self.constraint.is_satisfied_by(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_satisfied() {
        let c = Constraint::Equal(ConstValue::I32(5));
        assert!(c.is_satisfied_by(&ConstValue::I32(5)));
        assert!(!c.is_satisfied_by(&ConstValue::I32(6)));

        let c = Constraint::NotEqual(ConstValue::I32(5));
        assert!(!c.is_satisfied_by(&ConstValue::I32(5)));
        assert!(c.is_satisfied_by(&ConstValue::I32(6)));

        let c = Constraint::GreaterThan(ConstValue::I32(5));
        assert!(c.is_satisfied_by(&ConstValue::I32(10)));
        assert!(!c.is_satisfied_by(&ConstValue::I32(5)));

        let c = Constraint::LessThan(ConstValue::I32(10));
        assert!(c.is_satisfied_by(&ConstValue::I32(5)));
        assert!(!c.is_satisfied_by(&ConstValue::I32(10)));
    }

    #[test]
    fn test_constraint_conflicts() {
        let c1 = Constraint::Equal(ConstValue::I32(5));
        let c2 = Constraint::Equal(ConstValue::I32(10));
        assert!(c1.conflicts_with(&c2));

        let c3 = Constraint::NotEqual(ConstValue::I32(5));
        assert!(c1.conflicts_with(&c3));

        let c4 = Constraint::GreaterThan(ConstValue::I32(5));
        assert!(c1.conflicts_with(&c4)); // 5 is not > 5

        let c5 = Constraint::GreaterThan(ConstValue::I32(4));
        assert!(!c1.conflicts_with(&c5)); // 5 > 4 is ok
    }

    #[test]
    fn test_path_constraint_satisfied() {
        let var = SsaVarId::new();

        let eq = PathConstraint::equal(var, ConstValue::I32(5));
        assert!(eq.is_satisfied_by(&ConstValue::I32(5)));
        assert!(!eq.is_satisfied_by(&ConstValue::I32(6)));

        let ne = PathConstraint::not_equal(var, ConstValue::I32(5));
        assert!(!ne.is_satisfied_by(&ConstValue::I32(5)));
        assert!(ne.is_satisfied_by(&ConstValue::I32(6)));
    }

    #[test]
    fn test_path_constraint_kinds() {
        let var = SsaVarId::new();

        assert!(PathConstraint::less_than(var, ConstValue::I32(10))
            .is_satisfied_by(&ConstValue::I32(5)));
        assert!(!PathConstraint::less_than(var, ConstValue::I32(10))
            .is_satisfied_by(&ConstValue::I32(10)));

        assert!(PathConstraint::greater_than(var, ConstValue::I32(5))
            .is_satisfied_by(&ConstValue::I32(10)));
        assert!(!PathConstraint::greater_than(var, ConstValue::I32(5))
            .is_satisfied_by(&ConstValue::I32(5)));
    }
}
