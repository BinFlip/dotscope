//! Symbolic expression tree representation.
//!
//! This module defines [`SymbolicExpr`], an intermediate representation for
//! symbolic values that can contain variables, constants, and operations.
//! Expressions map directly to SSA operations and can be translated to Z3
//! for constraint solving.

use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::{
    analysis::ssa::{symbolic::ops::SymbolicOp, ConstValue, SsaVarId},
    metadata::typesystem::PointerSize,
};

/// A symbolic expression that can contain variables, constants, and operations.
///
/// This is our intermediate representation for symbolic values. It maps directly
/// to SSA operations and can be translated to Z3 for constraint solving.
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolicExpr {
    /// A typed constant value preserving CIL type information.
    Constant(ConstValue),

    /// A symbolic variable (identified by SSA variable ID).
    Variable(SsaVarId),

    /// A named symbolic variable (for external inputs like "state").
    NamedVar(String),

    /// A unary operation.
    Unary {
        /// The operation to perform.
        op: SymbolicOp,
        /// The operand.
        operand: Box<SymbolicExpr>,
    },

    /// A binary operation.
    Binary {
        /// The operation to perform.
        op: SymbolicOp,
        /// The left operand.
        left: Box<SymbolicExpr>,
        /// The right operand.
        right: Box<SymbolicExpr>,
    },
}

impl SymbolicExpr {
    /// Creates a constant expression from a typed `ConstValue`.
    ///
    /// This is the preferred constructor as it preserves type information.
    ///
    /// # Arguments
    ///
    /// * `value` - The typed constant value.
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::Constant`] containing the value.
    #[must_use]
    pub fn constant(value: ConstValue) -> Self {
        Self::Constant(value)
    }

    /// Creates a constant expression from an i64 value.
    ///
    /// The value is stored as `ConstValue::I64`. For type-preserving operations,
    /// use [`constant`](Self::constant) with an explicit `ConstValue` instead.
    ///
    /// # Arguments
    ///
    /// * `value` - The integer value.
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::Constant`] containing the value as I64.
    #[must_use]
    pub fn constant_i64(value: i64) -> Self {
        Self::Constant(ConstValue::I64(value))
    }

    /// Creates a constant expression from an i32 value.
    ///
    /// # Arguments
    ///
    /// * `value` - The integer value.
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::Constant`] containing the value as I32.
    #[must_use]
    pub fn constant_i32(value: i32) -> Self {
        Self::Constant(ConstValue::I32(value))
    }

    /// Creates a variable expression from an SSA variable ID.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable identifier.
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::Variable`] referencing the given variable.
    #[must_use]
    pub const fn variable(var: SsaVarId) -> Self {
        Self::Variable(var)
    }

    /// Creates a named variable expression.
    ///
    /// Named variables are used for external inputs like "state" that aren't
    /// tied to a specific SSA variable ID.
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name (e.g., "state").
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::NamedVar`] with the given name.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::NamedVar(name.into())
    }

    /// Creates a unary operation expression.
    ///
    /// # Arguments
    ///
    /// * `op` - The unary operation (Neg or Not).
    /// * `operand` - The operand expression.
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::Unary`] applying the operation to the operand.
    #[must_use]
    pub fn unary(op: SymbolicOp, operand: Self) -> Self {
        Self::Unary {
            op,
            operand: Box::new(operand),
        }
    }

    /// Creates a binary operation expression.
    ///
    /// # Arguments
    ///
    /// * `op` - The binary operation (Add, Sub, Mul, etc.).
    /// * `left` - The left operand expression.
    /// * `right` - The right operand expression.
    ///
    /// # Returns
    ///
    /// A new [`SymbolicExpr::Binary`] applying the operation to the operands.
    #[must_use]
    pub fn binary(op: SymbolicOp, left: Self, right: Self) -> Self {
        Self::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Checks if this expression is a constant.
    ///
    /// # Returns
    ///
    /// `true` if this is a [`SymbolicExpr::Constant`].
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(_))
    }

    /// Checks if this expression is a variable.
    ///
    /// # Returns
    ///
    /// `true` if this is a [`SymbolicExpr::Variable`] or [`SymbolicExpr::NamedVar`].
    #[must_use]
    pub const fn is_variable(&self) -> bool {
        matches!(self, Self::Variable(_) | Self::NamedVar(_))
    }

    /// Returns the typed constant value if this is a constant expression.
    ///
    /// # Returns
    ///
    /// `Some(&ConstValue)` if this is a constant, `None` otherwise.
    #[must_use]
    pub const fn as_constant(&self) -> Option<&ConstValue> {
        match self {
            Self::Constant(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the constant as i64 if this is a constant expression.
    ///
    /// This extracts the raw i64 value regardless of the underlying type.
    /// For type-preserving operations, use [`as_constant`](Self::as_constant) instead.
    ///
    /// # Returns
    ///
    /// `Some(i64)` if this is a constant with an integer value, `None` otherwise.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Constant(v) => v.as_i64(),
            _ => None,
        }
    }

    /// Returns the SSA variable ID if this is a variable expression.
    ///
    /// # Returns
    ///
    /// `Some(var_id)` if this is a [`SymbolicExpr::Variable`], `None` otherwise.
    /// Note: Returns `None` for [`SymbolicExpr::NamedVar`].
    #[must_use]
    pub const fn as_variable(&self) -> Option<SsaVarId> {
        match self {
            Self::Variable(v) => Some(*v),
            _ => None,
        }
    }

    /// Collects all SSA variables referenced in this expression.
    ///
    /// Recursively traverses the expression tree to find all variable references.
    ///
    /// # Returns
    ///
    /// A set of all [`SsaVarId`]s referenced in this expression.
    #[must_use]
    pub fn variables(&self) -> HashSet<SsaVarId> {
        match self {
            Self::Constant(_) | Self::NamedVar(_) => HashSet::new(),
            Self::Variable(v) => {
                let mut vars = HashSet::new();
                vars.insert(*v);
                vars
            }
            Self::Unary { operand, .. } => operand.variables(),
            Self::Binary { left, right, .. } => {
                let mut vars = left.variables();
                vars.extend(right.variables());
                vars
            }
        }
    }

    /// Collects all named variables referenced in this expression.
    ///
    /// Recursively traverses the expression tree to find all named variable references.
    ///
    /// # Returns
    ///
    /// A set of all variable names referenced in this expression.
    #[must_use]
    pub fn named_variables(&self) -> HashSet<String> {
        let mut vars = HashSet::new();
        self.collect_named_variables(&mut vars);
        vars
    }

    /// Recursively collects named variables into the provided set.
    ///
    /// # Arguments
    ///
    /// * `vars` - The set to collect variable names into.
    fn collect_named_variables(&self, vars: &mut HashSet<String>) {
        match self {
            Self::Constant(_) | Self::Variable(_) => {}
            Self::NamedVar(name) => {
                vars.insert(name.clone());
            }
            Self::Unary { operand, .. } => operand.collect_named_variables(vars),
            Self::Binary { left, right, .. } => {
                left.collect_named_variables(vars);
                right.collect_named_variables(vars);
            }
        }
    }

    /// Evaluates the expression with the given SSA variable bindings.
    ///
    /// Recursively evaluates the expression tree, substituting bound variables
    /// with their values and computing operations. Returns the result as a
    /// typed `ConstValue`.
    ///
    /// # Arguments
    ///
    /// * `bindings` - Map from SSA variable IDs to their concrete values.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    ///
    /// # Returns
    ///
    /// `Some(ConstValue)` if evaluation succeeds, `None` if any variable is unbound,
    /// a named variable is encountered, or division by zero occurs.
    #[must_use]
    pub fn evaluate(
        &self,
        bindings: &HashMap<SsaVarId, ConstValue>,
        ptr_size: PointerSize,
    ) -> Option<ConstValue> {
        match self {
            Self::Constant(v) => Some(v.clone()),
            Self::Variable(var) => bindings.get(var).cloned(),
            Self::NamedVar(_) => None,
            Self::Unary { op, operand } => {
                let v = operand.evaluate(bindings, ptr_size)?;
                evaluate_unary_typed(*op, v, ptr_size)
            }
            Self::Binary { op, left, right } => {
                let l = left.evaluate(bindings, ptr_size)?;
                let r = right.evaluate(bindings, ptr_size)?;
                evaluate_binary_typed(*op, l, r, ptr_size)
            }
        }
    }

    /// Evaluates the expression with named variable bindings.
    ///
    /// Similar to [`evaluate`](Self::evaluate), but uses string names instead
    /// of SSA variable IDs. Useful for evaluating expressions with external inputs.
    ///
    /// # Arguments
    ///
    /// * `bindings` - Map from variable names to their concrete values.
    /// * `ptr_size` - Target pointer size for native int/uint masking.
    ///
    /// # Returns
    ///
    /// `Some(ConstValue)` if evaluation succeeds, `None` if any named variable is
    /// unbound, an SSA variable is encountered, or division by zero occurs.
    #[must_use]
    pub fn evaluate_named(
        &self,
        bindings: &HashMap<&str, ConstValue>,
        ptr_size: PointerSize,
    ) -> Option<ConstValue> {
        match self {
            Self::Constant(v) => Some(v.clone()),
            Self::Variable(_) => None,
            Self::NamedVar(name) => bindings.get(name.as_str()).cloned(),
            Self::Unary { op, operand } => {
                let v = operand.evaluate_named(bindings, ptr_size)?;
                evaluate_unary_typed(*op, v, ptr_size)
            }
            Self::Binary { op, left, right } => {
                let l = left.evaluate_named(bindings, ptr_size)?;
                let r = right.evaluate_named(bindings, ptr_size)?;
                evaluate_binary_typed(*op, l, r, ptr_size)
            }
        }
    }

    /// Substitutes an SSA variable with a replacement expression.
    ///
    /// Creates a new expression tree where all occurrences of `var` are
    /// replaced with `replacement`.
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable ID to replace.
    /// * `replacement` - The expression to substitute in place of the variable.
    ///
    /// # Returns
    ///
    /// A new expression with the substitution applied.
    #[must_use]
    pub fn substitute(&self, var: SsaVarId, replacement: &Self) -> Self {
        match self {
            Self::Constant(v) => Self::Constant(v.clone()),
            Self::Variable(v) if *v == var => replacement.clone(),
            Self::Variable(v) => Self::Variable(*v),
            Self::NamedVar(name) => Self::NamedVar(name.clone()),
            Self::Unary { op, operand } => Self::Unary {
                op: *op,
                operand: Box::new(operand.substitute(var, replacement)),
            },
            Self::Binary { op, left, right } => Self::Binary {
                op: *op,
                left: Box::new(left.substitute(var, replacement)),
                right: Box::new(right.substitute(var, replacement)),
            },
        }
    }

    /// Substitutes a named variable with a constant value.
    ///
    /// Creates a new expression tree where all occurrences of the named
    /// variable are replaced with the constant value, then simplifies.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the variable to replace (e.g., "state").
    /// * `value` - The constant value to substitute.
    ///
    /// # Returns
    ///
    /// A simplified expression with the substitution applied.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let expr = SymbolicExpr::binary(
    ///     SymbolicOp::Xor,
    ///     SymbolicExpr::named("state"),
    ///     SymbolicExpr::constant_i64(0x12345678),
    /// );
    /// let result = expr.substitute_named("state", 100);
    /// assert_eq!(result.as_i64(), Some(100 ^ 0x12345678));
    /// ```
    #[must_use]
    pub fn substitute_named(&self, name: &str, value: i64, ptr_size: PointerSize) -> Self {
        self.substitute_named_expr(name, &Self::Constant(ConstValue::I64(value)))
            .simplify(ptr_size)
    }

    /// Substitutes a named variable with a replacement expression.
    ///
    /// Creates a new expression tree where all occurrences of the named
    /// variable are replaced with the replacement expression.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the variable to replace.
    /// * `replacement` - The expression to substitute.
    ///
    /// # Returns
    ///
    /// A new expression with the substitution applied.
    #[must_use]
    pub fn substitute_named_expr(&self, name: &str, replacement: &Self) -> Self {
        match self {
            Self::Constant(v) => Self::Constant(v.clone()),
            Self::Variable(v) => Self::Variable(*v),
            Self::NamedVar(n) if n == name => replacement.clone(),
            Self::NamedVar(n) => Self::NamedVar(n.clone()),
            Self::Unary { op, operand } => Self::Unary {
                op: *op,
                operand: Box::new(operand.substitute_named_expr(name, replacement)),
            },
            Self::Binary { op, left, right } => Self::Binary {
                op: *op,
                left: Box::new(left.substitute_named_expr(name, replacement)),
                right: Box::new(right.substitute_named_expr(name, replacement)),
            },
        }
    }

    /// Simplifies the expression by evaluating constant subexpressions.
    ///
    /// Performs constant folding and applies algebraic identities:
    /// - Folds constant operations (e.g., `5 + 3` → `8`)
    /// - Removes identity operations (e.g., `x + 0` → `x`, `x * 1` → `x`)
    /// - Simplifies zero multiplications (e.g., `x * 0` → `0`)
    /// - Self-cancellation patterns (e.g., `x ^ x = 0`, `x - x = 0`)
    /// - Double operation cancellation (e.g., `--x = x`, `~~x = x`)
    /// - XOR constant cancellation (e.g., `(x ^ c) ^ c = x`)
    ///
    /// # Returns
    ///
    /// A simplified expression that is semantically equivalent to this one.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Documents distinct algebraic identities: x*0=0 vs x&0=0
    pub fn simplify(&self, ptr_size: PointerSize) -> Self {
        match self {
            Self::Constant(_) | Self::Variable(_) | Self::NamedVar(_) => self.clone(),
            Self::Unary { op, operand } => {
                let simplified = operand.simplify(ptr_size);

                // Constant folding using typed operations
                if let Self::Constant(v) = &simplified {
                    if let Some(result) = evaluate_unary_typed(*op, v.clone(), ptr_size) {
                        return Self::Constant(result);
                    }
                }

                // Double operation cancellation: --x = x, ~~x = x
                if let Self::Unary {
                    op: inner_op,
                    operand: inner_operand,
                } = &simplified
                {
                    if op == inner_op {
                        match op {
                            // --x = x (double negation)
                            SymbolicOp::Neg => return (**inner_operand).clone(),
                            // ~~x = x (double NOT)
                            SymbolicOp::Not => return (**inner_operand).clone(),
                            _ => {}
                        }
                    }
                }

                Self::Unary {
                    op: *op,
                    operand: Box::new(simplified),
                }
            }
            Self::Binary { op, left, right } => {
                let left_simp = left.simplify(ptr_size);
                let right_simp = right.simplify(ptr_size);

                // Both constants - evaluate using typed operations
                if let (Self::Constant(l), Self::Constant(r)) = (&left_simp, &right_simp) {
                    if let Some(result) = evaluate_binary_typed(*op, l.clone(), r.clone(), ptr_size)
                    {
                        return Self::Constant(result);
                    }
                }

                // Self-cancellation patterns (when left == right)
                if left_simp == right_simp {
                    match op {
                        // x ^ x = 0
                        SymbolicOp::Xor => return Self::Constant(ConstValue::I32(0)),
                        // x - x = 0
                        SymbolicOp::Sub => return Self::Constant(ConstValue::I32(0)),
                        // x | x = x
                        SymbolicOp::Or => return left_simp,
                        // x & x = x
                        SymbolicOp::And => return left_simp,
                        _ => {}
                    }
                }

                // XOR constant cancellation: (x ^ c) ^ c = x
                // This is critical for deobfuscation - many obfuscators use XOR with same constant
                if *op == SymbolicOp::Xor {
                    if let Self::Constant(c1) = &right_simp {
                        if let Self::Binary {
                            op: SymbolicOp::Xor,
                            left: inner_left,
                            right: inner_right,
                        } = &left_simp
                        {
                            // (x ^ c1) ^ c1 = x
                            if let Self::Constant(c2) = inner_right.as_ref() {
                                if c1 == c2 {
                                    return (**inner_left).clone();
                                }
                            }
                            // (c1 ^ x) ^ c1 = x
                            if let Self::Constant(c2) = inner_left.as_ref() {
                                if c1 == c2 {
                                    return (**inner_right).clone();
                                }
                            }
                        }
                    }
                    // Also handle c ^ (x ^ c) = x
                    if let Self::Constant(c1) = &left_simp {
                        if let Self::Binary {
                            op: SymbolicOp::Xor,
                            left: inner_left,
                            right: inner_right,
                        } = &right_simp
                        {
                            // c1 ^ (x ^ c1) = x
                            if let Self::Constant(c2) = inner_right.as_ref() {
                                if c1 == c2 {
                                    return (**inner_left).clone();
                                }
                            }
                            // c1 ^ (c1 ^ x) = x
                            if let Self::Constant(c2) = inner_left.as_ref() {
                                if c1 == c2 {
                                    return (**inner_right).clone();
                                }
                            }
                        }
                    }
                }

                // Identity simplifications - check if constant is zero/one
                if let Self::Constant(r) = &right_simp {
                    if r.is_zero() {
                        match op {
                            // x + 0 = x, x - 0 = x
                            SymbolicOp::Add | SymbolicOp::Sub => return left_simp,
                            // x * 0 = 0
                            SymbolicOp::Mul => return Self::Constant(ConstValue::I32(0)),
                            // x ^ 0 = x, x | 0 = x
                            SymbolicOp::Xor | SymbolicOp::Or => return left_simp,
                            // x & 0 = 0
                            SymbolicOp::And => return Self::Constant(ConstValue::I32(0)),
                            _ => {}
                        }
                    } else if r.is_one() {
                        match op {
                            // x * 1 = x, x / 1 = x
                            SymbolicOp::Mul | SymbolicOp::DivS | SymbolicOp::DivU => {
                                return left_simp
                            }
                            _ => {}
                        }
                    } else if r.is_all_ones() {
                        match op {
                            // x & -1 = x
                            SymbolicOp::And => return left_simp,
                            // x | -1 = -1
                            SymbolicOp::Or => return Self::Constant(r.clone()),
                            // x ^ -1 = ~x
                            SymbolicOp::Xor => {
                                return Self::Unary {
                                    op: SymbolicOp::Not,
                                    operand: Box::new(left_simp),
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if let Self::Constant(l) = &left_simp {
                    if l.is_zero() {
                        match op {
                            // 0 + x = x
                            SymbolicOp::Add => return right_simp,
                            // 0 - x = -x
                            SymbolicOp::Sub => {
                                return Self::Unary {
                                    op: SymbolicOp::Neg,
                                    operand: Box::new(right_simp),
                                }
                            }
                            // 0 * x = 0
                            SymbolicOp::Mul => return Self::Constant(ConstValue::I32(0)),
                            // 0 ^ x = x, 0 | x = x
                            SymbolicOp::Xor | SymbolicOp::Or => return right_simp,
                            // 0 & x = 0
                            SymbolicOp::And => return Self::Constant(ConstValue::I32(0)),
                            _ => {}
                        }
                    } else if l.is_one() {
                        // 1 * x = x
                        if *op == SymbolicOp::Mul {
                            return right_simp;
                        }
                    } else if l.is_all_ones() {
                        match op {
                            // -1 & x = x
                            SymbolicOp::And => return right_simp,
                            // -1 | x = -1
                            SymbolicOp::Or => return Self::Constant(l.clone()),
                            // -1 ^ x = ~x
                            SymbolicOp::Xor => {
                                return Self::Unary {
                                    op: SymbolicOp::Not,
                                    operand: Box::new(right_simp),
                                }
                            }
                            _ => {}
                        }
                    }
                }

                Self::Binary {
                    op: *op,
                    left: Box::new(left_simp),
                    right: Box::new(right_simp),
                }
            }
        }
    }

    /// Returns the depth of the expression tree.
    ///
    /// The depth is the length of the longest path from the root to a leaf.
    /// Constants and variables have depth 0.
    ///
    /// # Returns
    ///
    /// The maximum nesting depth of operations in this expression.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Constant(_) | Self::Variable(_) | Self::NamedVar(_) => 0,
            Self::Unary { operand, .. } => 1 + operand.depth(),
            Self::Binary { left, right, .. } => 1 + left.depth().max(right.depth()),
        }
    }
}

impl fmt::Display for SymbolicExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Constant(v) => write!(f, "{v}"),
            Self::Variable(var) => write!(f, "v{}", var.index()),
            Self::NamedVar(name) => write!(f, "{name}"),
            Self::Unary { op, operand } => write!(f, "({op}{operand})"),
            Self::Binary { op, left, right } => write!(f, "({left} {op} {right})"),
        }
    }
}

impl From<ConstValue> for SymbolicExpr {
    fn from(value: ConstValue) -> Self {
        Self::Constant(value)
    }
}

impl From<i32> for SymbolicExpr {
    fn from(value: i32) -> Self {
        Self::Constant(ConstValue::I32(value))
    }
}

impl From<i64> for SymbolicExpr {
    fn from(value: i64) -> Self {
        Self::Constant(ConstValue::I64(value))
    }
}

/// Evaluates a unary operation on a typed constant value.
///
/// Uses the type-preserving operations on `ConstValue`.
///
/// # Arguments
///
/// * `op` - The unary operation to perform (Neg or Not).
/// * `value` - The typed operand value.
///
/// # Returns
///
/// The result of the operation as a `ConstValue`, or `None` if the operation fails.
pub fn evaluate_unary_typed(
    op: SymbolicOp,
    value: ConstValue,
    ptr_size: PointerSize,
) -> Option<ConstValue> {
    match op {
        SymbolicOp::Neg => value.negate(ptr_size),
        SymbolicOp::Not => value.bitwise_not(ptr_size),
        _ => None,
    }
}

/// Evaluates a binary operation on typed constant values.
///
/// Uses the type-preserving operations on `ConstValue`.
///
/// # Arguments
///
/// * `op` - The binary operation to perform.
/// * `left` - The typed left operand value.
/// * `right` - The typed right operand value.
///
/// # Returns
///
/// The result of the operation as a `ConstValue`, or `None` if the operation
/// fails (e.g., division by zero, type mismatch).
pub fn evaluate_binary_typed(
    op: SymbolicOp,
    left: ConstValue,
    right: ConstValue,
    ptr_size: PointerSize,
) -> Option<ConstValue> {
    match op {
        SymbolicOp::Add => left.add(&right, ptr_size),
        SymbolicOp::Sub => left.sub(&right, ptr_size),
        SymbolicOp::Mul => left.mul(&right, ptr_size),
        // div/rem handle signedness based on ConstValue's underlying type
        SymbolicOp::DivS | SymbolicOp::DivU => left.div(&right, ptr_size),
        SymbolicOp::RemS | SymbolicOp::RemU => left.rem(&right, ptr_size),
        SymbolicOp::And => left.bitwise_and(&right, ptr_size),
        SymbolicOp::Or => left.bitwise_or(&right, ptr_size),
        SymbolicOp::Xor => left.bitwise_xor(&right, ptr_size),
        SymbolicOp::Shl => left.shl(&right, ptr_size),
        SymbolicOp::ShrS => left.shr(&right, false, ptr_size),
        SymbolicOp::ShrU => left.shr(&right, true, ptr_size),
        SymbolicOp::Eq => left.ceq(&right),
        SymbolicOp::Ne => left.ceq(&right).map(|v| {
            // Negate the equality result
            if v.is_zero() {
                ConstValue::I32(1)
            } else {
                ConstValue::I32(0)
            }
        }),
        SymbolicOp::LtS => left.clt(&right),
        SymbolicOp::LtU => left.clt_un(&right),
        SymbolicOp::GtS => left.cgt(&right),
        SymbolicOp::GtU => left.cgt_un(&right),
        SymbolicOp::LeS => {
            // x <= y is !(x > y)
            left.cgt(&right).map(|v| {
                if v.is_zero() {
                    ConstValue::I32(1)
                } else {
                    ConstValue::I32(0)
                }
            })
        }
        SymbolicOp::LeU => {
            // x <=u y is !(x >u y)
            left.cgt_un(&right).map(|v| {
                if v.is_zero() {
                    ConstValue::I32(1)
                } else {
                    ConstValue::I32(0)
                }
            })
        }
        SymbolicOp::GeS => {
            // x >= y is !(x < y)
            left.clt(&right).map(|v| {
                if v.is_zero() {
                    ConstValue::I32(1)
                } else {
                    ConstValue::I32(0)
                }
            })
        }
        SymbolicOp::GeU => {
            // x >=u y is !(x <u y)
            left.clt_un(&right).map(|v| {
                if v.is_zero() {
                    ConstValue::I32(1)
                } else {
                    ConstValue::I32(0)
                }
            })
        }
        SymbolicOp::Neg | SymbolicOp::Not => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        analysis::ssa::{
            symbolic::{expr::SymbolicExpr, ops::SymbolicOp},
            ConstValue, SsaVarId,
        },
        metadata::typesystem::PointerSize,
    };

    #[test]
    fn test_constant_expression() {
        let expr = SymbolicExpr::constant_i32(42);
        assert!(expr.is_constant());
        assert_eq!(expr.as_constant(), Some(&ConstValue::I32(42)));
        assert_eq!(
            expr.evaluate(&HashMap::new(), PointerSize::Bit64),
            Some(ConstValue::I32(42))
        );
    }

    #[test]
    fn test_variable_expression() {
        let var = SsaVarId::new();
        let expr = SymbolicExpr::variable(var);
        assert!(expr.is_variable());
        assert_eq!(expr.as_variable(), Some(var));

        let mut bindings = HashMap::new();
        assert_eq!(expr.evaluate(&bindings, PointerSize::Bit64), None);

        bindings.insert(var, ConstValue::I32(100));
        assert_eq!(
            expr.evaluate(&bindings, PointerSize::Bit64),
            Some(ConstValue::I32(100))
        );
    }

    #[test]
    fn test_simplify_constant_fold() {
        let expr = SymbolicExpr::binary(
            SymbolicOp::Add,
            SymbolicExpr::constant_i32(10),
            SymbolicExpr::constant_i32(20),
        );
        let simplified = expr.simplify(PointerSize::Bit64);
        assert_eq!(simplified, SymbolicExpr::constant(ConstValue::I32(30)));
    }

    #[test]
    fn test_simplify_identity() {
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::Add,
            SymbolicExpr::variable(var),
            SymbolicExpr::constant_i32(0),
        );
        let simplified = expr.simplify(PointerSize::Bit64);
        assert_eq!(simplified, SymbolicExpr::variable(var));
    }

    #[test]
    fn test_expression_display() {
        let expr = SymbolicExpr::binary(
            SymbolicOp::RemU,
            SymbolicExpr::binary(
                SymbolicOp::Xor,
                SymbolicExpr::named("state"),
                SymbolicExpr::constant_i32(0x1234),
            ),
            SymbolicExpr::constant_i32(13),
        );

        let display = format!("{}", expr);
        assert!(display.contains("state"));
        assert!(display.contains("^"));
        assert!(display.contains("%u"));
    }

    #[test]
    fn test_simplify_xor_self_cancellation() {
        // x ^ x = 0
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::variable(var),
            SymbolicExpr::variable(var),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_simplify_sub_self_cancellation() {
        // x - x = 0
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::Sub,
            SymbolicExpr::variable(var),
            SymbolicExpr::variable(var),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::constant(ConstValue::I32(0))
        );
    }

    #[test]
    fn test_simplify_or_self_idempotent() {
        // x | x = x
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::Or,
            SymbolicExpr::variable(var),
            SymbolicExpr::variable(var),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_and_self_idempotent() {
        // x & x = x
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::And,
            SymbolicExpr::variable(var),
            SymbolicExpr::variable(var),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_double_negation() {
        // --x = x
        let var = SsaVarId::new();
        let expr = SymbolicExpr::unary(
            SymbolicOp::Neg,
            SymbolicExpr::unary(SymbolicOp::Neg, SymbolicExpr::variable(var)),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_double_not() {
        // ~~x = x
        let var = SsaVarId::new();
        let expr = SymbolicExpr::unary(
            SymbolicOp::Not,
            SymbolicExpr::unary(SymbolicOp::Not, SymbolicExpr::variable(var)),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_xor_constant_cancellation() {
        // (x ^ c) ^ c = x
        let var = SsaVarId::new();
        let const_val = ConstValue::I32(0x12345678_u32 as i32);
        let expr = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::binary(
                SymbolicOp::Xor,
                SymbolicExpr::variable(var),
                SymbolicExpr::constant(const_val.clone()),
            ),
            SymbolicExpr::constant(const_val),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_xor_constant_cancellation_reversed() {
        // c ^ (x ^ c) = x
        let var = SsaVarId::new();
        let const_val = ConstValue::I64(0xDEADBEEF_u32 as i64);
        let expr = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::constant(const_val.clone()),
            SymbolicExpr::binary(
                SymbolicOp::Xor,
                SymbolicExpr::variable(var),
                SymbolicExpr::constant(const_val),
            ),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_and_all_ones() {
        // x & -1 = x
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::And,
            SymbolicExpr::variable(var),
            SymbolicExpr::constant_i32(-1),
        );
        assert_eq!(
            expr.simplify(PointerSize::Bit64),
            SymbolicExpr::variable(var)
        );
    }

    #[test]
    fn test_simplify_or_all_ones() {
        // x | -1 = -1
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::Or,
            SymbolicExpr::variable(var),
            SymbolicExpr::constant_i32(-1),
        );
        // Result should have all ones
        let simplified = expr.simplify(PointerSize::Bit64);
        if let SymbolicExpr::Constant(v) = simplified {
            assert!(v.is_all_ones());
        } else {
            panic!("Expected constant result");
        }
    }

    #[test]
    fn test_simplify_xor_all_ones() {
        // x ^ -1 = ~x
        let var = SsaVarId::new();
        let expr = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::variable(var),
            SymbolicExpr::constant_i32(-1),
        );
        let simplified = expr.simplify(PointerSize::Bit64);
        // Should be ~x (NOT operation)
        assert!(matches!(
            simplified,
            SymbolicExpr::Unary {
                op: SymbolicOp::Not,
                ..
            }
        ));
    }

    #[test]
    fn test_simplify_confuserex_state_pattern() {
        // ConfuserEx uses: ((state * mul) ^ xor_key) % mod_val
        // After XOR cancellation: (state * mul) % mod_val
        // This tests that XOR with same constant cancels out
        let state = SymbolicExpr::named("state");
        let mul_const = ConstValue::I32(0x1234);
        let xor_key = ConstValue::I32(0xABCD_u32 as i32);

        // Build: ((state * mul) ^ xor) ^ xor
        let expr = SymbolicExpr::binary(
            SymbolicOp::Xor,
            SymbolicExpr::binary(
                SymbolicOp::Xor,
                SymbolicExpr::binary(
                    SymbolicOp::Mul,
                    state.clone(),
                    SymbolicExpr::constant(mul_const),
                ),
                SymbolicExpr::constant(xor_key.clone()),
            ),
            SymbolicExpr::constant(xor_key),
        );

        let simplified = expr.simplify(PointerSize::Bit64);

        // Should simplify to: state * mul
        assert!(matches!(
            simplified,
            SymbolicExpr::Binary {
                op: SymbolicOp::Mul,
                ..
            }
        ));
    }
}
