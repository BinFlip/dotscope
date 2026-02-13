//! Decomposed SSA operations.
//!
//! This module defines `SsaOp`, the decomposed operation representation that
//! converts complex CIL instructions into simple `result = op(operands)` form.
//!
//! # Design Goals
//!
//! - **Single assignment**: Each operation produces at most one result
//! - **Explicit operands**: All data dependencies are explicit SSA variables
//! - **Pattern matching**: Enum variants enable easy pattern matching for analysis
//! - **Type safety**: Operations are typed where possible
//!
//! # Operation Categories
//!
//! - **Constants**: Load constant values
//! - **Arithmetic**: Binary and unary math operations
//! - **Bitwise**: And, or, xor, shifts
//! - **Comparison**: Equality and relational comparisons
//! - **Conversion**: Type conversions
//! - **Control flow**: Branches, jumps, returns
//! - **Memory**: Field, array, and indirect access
//! - **Objects**: Allocation, casting, boxing
//! - **Calls**: Method invocations
//!
//! # Field Documentation
//!
//! The struct fields in this module follow a consistent naming convention:
//! - `dest`: The destination SSA variable for the operation result
//! - `left`, `right`: Binary operands (left and right hand side)
//! - `operand`: Unary operand
//! - `value`: A value being stored or used
//! - `object`: The object instance for field/method operations
//! - `array`, `index`: Array and index for element operations
//! - `addr`: Address for indirect memory operations
//! - `target`, `true_target`, `false_target`: Branch targets (block indices)
//! - `unsigned`: Whether the operation treats values as unsigned
//! - `overflow_check`: Whether the operation checks for overflow

#![allow(missing_docs)]

use std::fmt;

use crate::{
    analysis::ssa::{
        types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef},
        value::ConstValue,
        SsaVarId,
    },
    metadata::token::Token,
};

/// Comparison kind for `BranchCmp` operations.
///
/// Represents the comparison operator used in combined compare-and-branch
/// operations like `blt`, `beq`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmpKind {
    /// Equal: `left == right`
    Eq,
    /// Not equal: `left != right`
    Ne,
    /// Less than: `left < right`
    Lt,
    /// Less than or equal: `left <= right`
    Le,
    /// Greater than: `left > right`
    Gt,
    /// Greater than or equal: `left >= right`
    Ge,
}

impl fmt::Display for CmpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
        }
    }
}

/// Kind of binary operation for extracted binary op info.
///
/// This enum categorizes all binary operations in `SsaOp` for uniform
/// handling in optimization passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOpKind {
    /// Addition: `left + right`
    Add,
    /// Addition with overflow check
    AddOvf,
    /// Subtraction: `left - right`
    Sub,
    /// Subtraction with overflow check
    SubOvf,
    /// Multiplication: `left * right`
    Mul,
    /// Multiplication with overflow check
    MulOvf,
    /// Division: `left / right`
    Div,
    /// Remainder: `left % right`
    Rem,
    /// Bitwise AND: `left & right`
    And,
    /// Bitwise OR: `left | right`
    Or,
    /// Bitwise XOR: `left ^ right`
    Xor,
    /// Shift left: `value << amount`
    Shl,
    /// Shift right: `value >> amount`
    Shr,
    /// Compare equal: `left == right`
    Ceq,
    /// Compare less than: `left < right`
    Clt,
    /// Compare greater than: `left > right`
    Cgt,
}

impl fmt::Display for BinaryOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::AddOvf => write!(f, "add.ovf"),
            Self::Sub => write!(f, "sub"),
            Self::SubOvf => write!(f, "sub.ovf"),
            Self::Mul => write!(f, "mul"),
            Self::MulOvf => write!(f, "mul.ovf"),
            Self::Div => write!(f, "div"),
            Self::Rem => write!(f, "rem"),
            Self::And => write!(f, "and"),
            Self::Or => write!(f, "or"),
            Self::Xor => write!(f, "xor"),
            Self::Shl => write!(f, "shl"),
            Self::Shr => write!(f, "shr"),
            Self::Ceq => write!(f, "ceq"),
            Self::Clt => write!(f, "clt"),
            Self::Cgt => write!(f, "cgt"),
        }
    }
}

impl BinaryOpKind {
    /// Returns `true` if this operation is commutative (`a op b == b op a`).
    ///
    /// Commutative operations can have their operands swapped without changing
    /// the result. This is useful for normalization in optimizations like GVN.
    ///
    /// # Commutative Operations
    ///
    /// - Arithmetic: `Add`, `AddOvf`, `Mul`, `MulOvf`
    /// - Bitwise: `And`, `Or`, `Xor`
    /// - Comparison: `Ceq` (equality is symmetric)
    #[must_use]
    pub const fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::AddOvf
                | Self::Mul
                | Self::MulOvf
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Ceq
        )
    }

    /// Returns `true` if this is a comparison operation.
    ///
    /// Comparison operations produce a boolean result (0 or 1) based on
    /// comparing two operands.
    #[must_use]
    pub const fn is_comparison(self) -> bool {
        matches!(self, Self::Ceq | Self::Clt | Self::Cgt)
    }

    /// Returns the operation with swapped operand semantics, if applicable.
    ///
    /// For comparison operations:
    /// - `Clt` (less than) becomes `Cgt` (greater than) when operands swap
    /// - `Cgt` (greater than) becomes `Clt` (less than) when operands swap
    /// - `Ceq` (equal) stays the same (symmetric)
    ///
    /// For non-comparison operations, returns `self` unchanged.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // a < b is equivalent to b > a
    /// assert_eq!(BinaryOpKind::Clt.swapped(), BinaryOpKind::Cgt);
    /// ```
    #[must_use]
    pub const fn swapped(self) -> Self {
        match self {
            Self::Clt => Self::Cgt,
            Self::Cgt => Self::Clt,
            other => other,
        }
    }

    /// Returns `true` if signedness affects the operation's semantics.
    ///
    /// Operations where the `unsigned` flag changes behavior:
    /// - `Div`, `Rem`: Signed vs unsigned division/remainder
    /// - `Shr`: Arithmetic (signed) vs logical (unsigned) shift
    /// - `Clt`, `Cgt`: Signed vs unsigned comparison
    ///
    /// For other operations, the unsigned flag has no effect.
    #[must_use]
    pub const fn is_signedness_sensitive(self) -> bool {
        matches!(
            self,
            Self::Div | Self::Rem | Self::Shr | Self::Clt | Self::Cgt
        )
    }
}

/// Information about a binary operation extracted from an `SsaOp`.
///
/// This provides a uniform view of binary operations for optimization passes,
/// allowing them to handle all binary ops generically without matching on
/// each variant individually.
///
/// # Example
///
/// ```ignore
/// if let Some(info) = op.as_binary_op() {
///     // Handle all binary ops uniformly
///     println!("{} = {} {} {}", info.dest, info.left, info.kind, info.right);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BinaryOpInfo {
    /// The kind of binary operation.
    pub kind: BinaryOpKind,
    /// Destination variable for the result.
    pub dest: SsaVarId,
    /// Left operand.
    pub left: SsaVarId,
    /// Right operand.
    pub right: SsaVarId,
    /// Whether the operation treats operands as unsigned.
    pub unsigned: bool,
}

impl BinaryOpInfo {
    /// Returns a normalized version of this operation for value numbering.
    ///
    /// For commutative operations, this ensures operands are in a canonical
    /// order (smaller variable index first). For non-commutative comparisons
    /// like `Clt` and `Cgt`, swapping operands also swaps the operation kind.
    ///
    /// This is useful for Global Value Numbering (GVN) where `a + b` and `b + a`
    /// should hash to the same value.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = BinaryOpInfo { kind: BinaryOpKind::Add, left: v5, right: v2, ... };
    /// let normalized = info.normalized();
    /// // normalized.left = v2, normalized.right = v5 (swapped for canonical order)
    /// ```
    #[must_use]
    pub fn normalized(self) -> Self {
        // Only normalize if right operand should come first
        if self.right.index() < self.left.index() {
            if self.kind.is_commutative() {
                // Commutative: just swap operands
                Self {
                    left: self.right,
                    right: self.left,
                    ..self
                }
            } else if self.kind.is_comparison() {
                // Non-commutative comparison: swap operands AND operation
                Self {
                    kind: self.kind.swapped(),
                    left: self.right,
                    right: self.left,
                    ..self
                }
            } else {
                // Non-commutative, non-comparison: don't normalize
                self
            }
        } else {
            self
        }
    }

    /// Returns a tuple suitable for use as a hash key in value numbering.
    ///
    /// The tuple includes all semantically relevant fields:
    /// - Operation kind
    /// - Unsigned flag (only if the operation is signedness-sensitive)
    /// - Left and right operands
    ///
    /// For operations where signedness doesn't matter, the unsigned field
    /// is normalized to `false` to ensure consistent hashing.
    #[must_use]
    pub fn value_key(self) -> (BinaryOpKind, bool, SsaVarId, SsaVarId) {
        let unsigned = if self.kind.is_signedness_sensitive() {
            self.unsigned
        } else {
            false // Normalize for consistent hashing
        };
        (self.kind, unsigned, self.left, self.right)
    }
}

/// Kind of unary operation for extracted unary op info.
///
/// This enum categorizes all unary operations in `SsaOp` for uniform
/// handling in optimization passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOpKind {
    /// Negation: `-operand`
    Neg,
    /// Bitwise NOT: `~operand`
    Not,
    /// Check finite (throws if NaN or infinity)
    Ckfinite,
}

impl fmt::Display for UnaryOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neg => write!(f, "neg"),
            Self::Not => write!(f, "not"),
            Self::Ckfinite => write!(f, "ckfinite"),
        }
    }
}

/// Information about a unary operation extracted from an `SsaOp`.
///
/// This provides a uniform view of unary operations for optimization passes,
/// allowing them to handle all unary ops generically without matching on
/// each variant individually.
///
/// # Example
///
/// ```ignore
/// if let Some(info) = op.as_unary_op() {
///     // Handle all unary ops uniformly
///     println!("{} = {} {}", info.dest, info.kind, info.operand);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnaryOpInfo {
    /// The kind of unary operation.
    pub kind: UnaryOpKind,
    /// Destination variable for the result.
    pub dest: SsaVarId,
    /// The operand.
    pub operand: SsaVarId,
}

/// A decomposed SSA operation.
///
/// Each variant represents a single operation with explicit inputs and outputs.
/// This enables clean pattern matching for optimization and analysis passes.
///
/// # Conventions
///
/// - For operations that produce a result, the first `SsaVarId` is the destination
/// - Operands follow in the order they appear on the CIL stack (first pushed = first operand)
/// - Optional results use `Option<SsaVarId>` (e.g., calls that may not return a value)
#[derive(Debug, Clone, PartialEq)]
pub enum SsaOp {
    /// Load a constant value.
    ///
    /// `dest = const value`
    Const { dest: SsaVarId, value: ConstValue },

    /// Addition: `dest = left + right`
    Add {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Addition with overflow check: `dest = left + right` (throws on overflow)
    AddOvf {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Subtraction: `dest = left - right`
    Sub {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Subtraction with overflow check: `dest = left - right`
    SubOvf {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Multiplication: `dest = left * right`
    Mul {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Multiplication with overflow check: `dest = left * right`
    MulOvf {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Division: `dest = left / right`
    Div {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Remainder: `dest = left % right`
    Rem {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Negation: `dest = -operand`
    Neg { dest: SsaVarId, operand: SsaVarId },

    /// Bitwise AND: `dest = left & right`
    And {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Bitwise OR: `dest = left | right`
    Or {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Bitwise XOR: `dest = left ^ right`
    Xor {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Bitwise NOT: `dest = ~operand`
    Not { dest: SsaVarId, operand: SsaVarId },

    /// Shift left: `dest = value << amount`
    Shl {
        dest: SsaVarId,
        value: SsaVarId,
        amount: SsaVarId,
    },

    /// Shift right: `dest = value >> amount`
    Shr {
        dest: SsaVarId,
        value: SsaVarId,
        amount: SsaVarId,
        unsigned: bool,
    },

    /// Compare equal: `dest = (left == right) ? 1 : 0`
    Ceq {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
    },

    /// Compare less than: `dest = (left < right) ? 1 : 0`
    Clt {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Compare greater than: `dest = (left > right) ? 1 : 0`
    Cgt {
        dest: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
    },

    /// Type conversion: `dest = (target_type)operand`
    Conv {
        dest: SsaVarId,
        operand: SsaVarId,
        target: SsaType,
        overflow_check: bool,
        unsigned: bool,
    },

    /// Unconditional jump to a block.
    Jump { target: usize },

    /// Conditional branch: if condition is true, go to true_target, else false_target.
    Branch {
        condition: SsaVarId,
        true_target: usize,
        false_target: usize,
    },

    /// Compare and branch: if (left cmp right) goto true_target else false_target.
    ///
    /// This represents CIL comparison branch instructions like `beq`, `blt`, `bgt`, etc.
    /// These are combined compare-and-branch operations that don't produce an intermediate
    /// comparison result.
    BranchCmp {
        left: SsaVarId,
        right: SsaVarId,
        cmp: CmpKind,
        unsigned: bool,
        true_target: usize,
        false_target: usize,
    },

    /// Switch statement: jump to `targets[value]` or default if out of range.
    Switch {
        value: SsaVarId,
        targets: Vec<usize>,
        default: usize,
    },

    /// Return from method with optional value.
    Return { value: Option<SsaVarId> },

    /// Load instance field: `dest = object.field`
    LoadField {
        dest: SsaVarId,
        object: SsaVarId,
        field: FieldRef,
    },

    /// Store instance field: `object.field = value`
    StoreField {
        object: SsaVarId,
        field: FieldRef,
        value: SsaVarId,
    },

    /// Load static field: `dest = ClassName.field`
    LoadStaticField { dest: SsaVarId, field: FieldRef },

    /// Store static field: `ClassName.field = value`
    StoreStaticField { field: FieldRef, value: SsaVarId },

    /// Load field address: `dest = &object.field`
    LoadFieldAddr {
        dest: SsaVarId,
        object: SsaVarId,
        field: FieldRef,
    },

    /// Load static field address: `dest = &ClassName.field`
    LoadStaticFieldAddr { dest: SsaVarId, field: FieldRef },

    /// Load array element: `dest = array[index]`
    LoadElement {
        dest: SsaVarId,
        array: SsaVarId,
        index: SsaVarId,
        elem_type: SsaType,
    },

    /// Store array element: `array[index] = value`
    StoreElement {
        array: SsaVarId,
        index: SsaVarId,
        value: SsaVarId,
        elem_type: SsaType,
    },

    /// Load array element address: `dest = &array[index]`
    LoadElementAddr {
        dest: SsaVarId,
        array: SsaVarId,
        index: SsaVarId,
        elem_type: TypeRef,
    },

    /// Get array length: `dest = array.Length`
    ArrayLength { dest: SsaVarId, array: SsaVarId },

    /// Load through pointer: `dest = *ptr`
    LoadIndirect {
        dest: SsaVarId,
        addr: SsaVarId,
        value_type: SsaType,
    },

    /// Store through pointer: `*ptr = value`
    StoreIndirect {
        addr: SsaVarId,
        value: SsaVarId,
        value_type: SsaType,
    },

    /// Create new object: `dest = new Type(args...)`
    NewObj {
        dest: SsaVarId,
        ctor: MethodRef,
        args: Vec<SsaVarId>,
    },

    /// Create new array: `dest = new Type[length]`
    NewArr {
        dest: SsaVarId,
        elem_type: TypeRef,
        length: SsaVarId,
    },

    /// Cast object to type (throws if invalid): `dest = (Type)obj`
    CastClass {
        dest: SsaVarId,
        object: SsaVarId,
        target_type: TypeRef,
    },

    /// Type check (returns null if invalid): `dest = obj as Type`
    IsInst {
        dest: SsaVarId,
        object: SsaVarId,
        target_type: TypeRef,
    },

    /// Box value type: `dest = (object)value`
    Box {
        dest: SsaVarId,
        value: SsaVarId,
        value_type: TypeRef,
    },

    /// Unbox to pointer: `dest = &((ValueType)obj)`
    Unbox {
        dest: SsaVarId,
        object: SsaVarId,
        value_type: TypeRef,
    },

    /// Unbox and copy: `dest = (ValueType)obj`
    UnboxAny {
        dest: SsaVarId,
        object: SsaVarId,
        value_type: TypeRef,
    },

    /// Get size of value type: `dest = sizeof(Type)`
    SizeOf { dest: SsaVarId, value_type: TypeRef },

    /// Load runtime type token: `dest = typeof(Type).TypeHandle`
    LoadToken { dest: SsaVarId, token: TypeRef },

    /// Direct method call: `dest = method(args...)`
    Call {
        dest: Option<SsaVarId>,
        method: MethodRef,
        args: Vec<SsaVarId>,
    },

    /// Virtual method call: `dest = obj.method(args...)`
    CallVirt {
        dest: Option<SsaVarId>,
        method: MethodRef,
        args: Vec<SsaVarId>,
    },

    /// Indirect call through function pointer: `dest = fptr(args...)`
    CallIndirect {
        dest: Option<SsaVarId>,
        fptr: SsaVarId,
        signature: SigRef,
        args: Vec<SsaVarId>,
    },

    /// Load function pointer: `dest = &method`
    LoadFunctionPtr { dest: SsaVarId, method: MethodRef },

    /// Load virtual function pointer: `dest = &obj.method`
    LoadVirtFunctionPtr {
        dest: SsaVarId,
        object: SsaVarId,
        method: MethodRef,
    },

    /// Load argument value: `dest = argN`
    LoadArg { dest: SsaVarId, arg_index: u16 },

    /// Load local value: `dest = localN`
    LoadLocal { dest: SsaVarId, local_index: u16 },

    /// Load argument address: `dest = &argN`
    LoadArgAddr { dest: SsaVarId, arg_index: u16 },

    /// Load local address: `dest = &localN`
    LoadLocalAddr { dest: SsaVarId, local_index: u16 },

    /// Copy value (from dup): `dest = src`
    Copy { dest: SsaVarId, src: SsaVarId },

    /// Pop value from stack (value is discarded, but we track the use)
    Pop { value: SsaVarId },

    /// Throw exception: `throw obj`
    Throw { exception: SsaVarId },

    /// Rethrow current exception (in catch handler)
    Rethrow,

    /// End finally block
    EndFinally,

    /// End filter block with result
    EndFilter { result: SsaVarId },

    /// Leave protected region
    Leave { target: usize },

    /// Initialize block of memory to zero
    InitBlk {
        dest_addr: SsaVarId,
        value: SsaVarId,
        size: SsaVarId,
    },

    /// Copy block of memory
    CopyBlk {
        dest_addr: SsaVarId,
        src_addr: SsaVarId,
        size: SsaVarId,
    },

    /// Initialize object (for value types): `*dest = default(T)`
    InitObj {
        dest_addr: SsaVarId,
        value_type: TypeRef,
    },

    /// Copy object (for value types): `*dest = *src`
    CopyObj {
        dest_addr: SsaVarId,
        src_addr: SsaVarId,
        value_type: TypeRef,
    },

    /// Load object (value type copy): `dest = *src`
    LoadObj {
        dest: SsaVarId,
        src_addr: SsaVarId,
        value_type: TypeRef,
    },

    /// Store object (value type copy): `*dest = value`
    StoreObj {
        dest_addr: SsaVarId,
        value: SsaVarId,
        value_type: TypeRef,
    },

    /// No operation (for nop instructions)
    Nop,

    /// Duplicate value (SSA form: just a copy)
    /// Breakpoint trap
    Break,

    /// Check for finite floating point: throws if not finite
    Ckfinite { dest: SsaVarId, operand: SsaVarId },

    /// Localloc: allocate stack space
    LocalAlloc { dest: SsaVarId, size: SsaVarId },

    /// Constrained virtual call prefix (affects next callvirt)
    Constrained { constraint_type: TypeRef },

    /// Phi node: merges values from different predecessors.
    ///
    /// This is placed at the beginning of blocks with multiple predecessors.
    Phi {
        dest: SsaVarId,
        operands: Vec<(usize, SsaVarId)>,
    },
}

impl SsaOp {
    /// Returns the destination variable if this operation produces one.
    #[must_use]
    pub fn dest(&self) -> Option<SsaVarId> {
        match self {
            Self::Const { dest, .. }
            | Self::Add { dest, .. }
            | Self::AddOvf { dest, .. }
            | Self::Sub { dest, .. }
            | Self::SubOvf { dest, .. }
            | Self::Mul { dest, .. }
            | Self::MulOvf { dest, .. }
            | Self::Div { dest, .. }
            | Self::Rem { dest, .. }
            | Self::Neg { dest, .. }
            | Self::And { dest, .. }
            | Self::Or { dest, .. }
            | Self::Xor { dest, .. }
            | Self::Not { dest, .. }
            | Self::Shl { dest, .. }
            | Self::Shr { dest, .. }
            | Self::Ceq { dest, .. }
            | Self::Clt { dest, .. }
            | Self::Cgt { dest, .. }
            | Self::Conv { dest, .. }
            | Self::LoadField { dest, .. }
            | Self::LoadStaticField { dest, .. }
            | Self::LoadFieldAddr { dest, .. }
            | Self::LoadStaticFieldAddr { dest, .. }
            | Self::LoadElement { dest, .. }
            | Self::LoadElementAddr { dest, .. }
            | Self::ArrayLength { dest, .. }
            | Self::LoadIndirect { dest, .. }
            | Self::NewObj { dest, .. }
            | Self::NewArr { dest, .. }
            | Self::CastClass { dest, .. }
            | Self::IsInst { dest, .. }
            | Self::Box { dest, .. }
            | Self::Unbox { dest, .. }
            | Self::UnboxAny { dest, .. }
            | Self::SizeOf { dest, .. }
            | Self::LoadToken { dest, .. }
            | Self::LoadFunctionPtr { dest, .. }
            | Self::LoadVirtFunctionPtr { dest, .. }
            | Self::LoadArg { dest, .. }
            | Self::LoadLocal { dest, .. }
            | Self::LoadArgAddr { dest, .. }
            | Self::LoadLocalAddr { dest, .. }
            | Self::Copy { dest, .. }
            | Self::Ckfinite { dest, .. }
            | Self::LocalAlloc { dest, .. }
            | Self::LoadObj { dest, .. }
            | Self::Phi { dest, .. } => Some(*dest),

            Self::Call { dest, .. }
            | Self::CallVirt { dest, .. }
            | Self::CallIndirect { dest, .. } => *dest,

            // Operations that don't produce a result
            Self::StoreField { .. }
            | Self::StoreStaticField { .. }
            | Self::StoreElement { .. }
            | Self::StoreIndirect { .. }
            | Self::Jump { .. }
            | Self::Branch { .. }
            | Self::BranchCmp { .. }
            | Self::Switch { .. }
            | Self::Return { .. }
            | Self::Pop { .. }
            | Self::Throw { .. }
            | Self::Rethrow
            | Self::EndFinally
            | Self::EndFilter { .. }
            | Self::Leave { .. }
            | Self::InitBlk { .. }
            | Self::CopyBlk { .. }
            | Self::InitObj { .. }
            | Self::CopyObj { .. }
            | Self::StoreObj { .. }
            | Self::Nop
            | Self::Break
            | Self::Constrained { .. } => None,
        }
    }

    /// Sets the destination variable for operations that produce a result.
    ///
    /// This is used during SSA renaming to update the dest after assigning
    /// new SSA variable IDs. Returns `true` if the dest was updated.
    ///
    /// # Arguments
    ///
    /// * `new_dest` - The new destination variable ID
    pub fn set_dest(&mut self, new_dest: SsaVarId) -> bool {
        match self {
            Self::Const { dest, .. }
            | Self::Add { dest, .. }
            | Self::AddOvf { dest, .. }
            | Self::Sub { dest, .. }
            | Self::SubOvf { dest, .. }
            | Self::Mul { dest, .. }
            | Self::MulOvf { dest, .. }
            | Self::Div { dest, .. }
            | Self::Rem { dest, .. }
            | Self::Neg { dest, .. }
            | Self::And { dest, .. }
            | Self::Or { dest, .. }
            | Self::Xor { dest, .. }
            | Self::Not { dest, .. }
            | Self::Shl { dest, .. }
            | Self::Shr { dest, .. }
            | Self::Ceq { dest, .. }
            | Self::Clt { dest, .. }
            | Self::Cgt { dest, .. }
            | Self::Conv { dest, .. }
            | Self::LoadField { dest, .. }
            | Self::LoadStaticField { dest, .. }
            | Self::LoadFieldAddr { dest, .. }
            | Self::LoadStaticFieldAddr { dest, .. }
            | Self::LoadElement { dest, .. }
            | Self::LoadElementAddr { dest, .. }
            | Self::ArrayLength { dest, .. }
            | Self::LoadIndirect { dest, .. }
            | Self::NewObj { dest, .. }
            | Self::NewArr { dest, .. }
            | Self::CastClass { dest, .. }
            | Self::IsInst { dest, .. }
            | Self::Box { dest, .. }
            | Self::Unbox { dest, .. }
            | Self::UnboxAny { dest, .. }
            | Self::SizeOf { dest, .. }
            | Self::LoadToken { dest, .. }
            | Self::LoadFunctionPtr { dest, .. }
            | Self::LoadVirtFunctionPtr { dest, .. }
            | Self::LoadArg { dest, .. }
            | Self::LoadLocal { dest, .. }
            | Self::LoadArgAddr { dest, .. }
            | Self::LoadLocalAddr { dest, .. }
            | Self::Copy { dest, .. }
            | Self::Ckfinite { dest, .. }
            | Self::LocalAlloc { dest, .. }
            | Self::LoadObj { dest, .. }
            | Self::Phi { dest, .. } => {
                *dest = new_dest;
                true
            }

            Self::Call { dest, .. }
            | Self::CallVirt { dest, .. }
            | Self::CallIndirect { dest, .. } => {
                *dest = Some(new_dest);
                true
            }

            // Operations that don't produce a result - cannot set dest
            Self::StoreField { .. }
            | Self::StoreStaticField { .. }
            | Self::StoreElement { .. }
            | Self::StoreIndirect { .. }
            | Self::Jump { .. }
            | Self::Branch { .. }
            | Self::BranchCmp { .. }
            | Self::Switch { .. }
            | Self::Return { .. }
            | Self::Pop { .. }
            | Self::Throw { .. }
            | Self::Rethrow
            | Self::EndFinally
            | Self::EndFilter { .. }
            | Self::Leave { .. }
            | Self::InitBlk { .. }
            | Self::CopyBlk { .. }
            | Self::InitObj { .. }
            | Self::CopyObj { .. }
            | Self::StoreObj { .. }
            | Self::Nop
            | Self::Break
            | Self::Constrained { .. } => false,
        }
    }

    /// Returns all variables used by this operation.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Kept separate for clarity by operation category
    pub fn uses(&self) -> Vec<SsaVarId> {
        match self {
            Self::Const { .. } => vec![],

            Self::Add { left, right, .. }
            | Self::AddOvf { left, right, .. }
            | Self::Sub { left, right, .. }
            | Self::SubOvf { left, right, .. }
            | Self::Mul { left, right, .. }
            | Self::MulOvf { left, right, .. }
            | Self::Div { left, right, .. }
            | Self::Rem { left, right, .. }
            | Self::And { left, right, .. }
            | Self::Or { left, right, .. }
            | Self::Xor { left, right, .. }
            | Self::Ceq { left, right, .. }
            | Self::Clt { left, right, .. }
            | Self::Cgt { left, right, .. } => vec![*left, *right],

            Self::Shl { value, amount, .. } | Self::Shr { value, amount, .. } => {
                vec![*value, *amount]
            }

            Self::Neg { operand, .. }
            | Self::Not { operand, .. }
            | Self::Conv { operand, .. }
            | Self::Ckfinite { operand, .. } => vec![*operand],

            Self::Branch { condition, .. } => vec![*condition],
            Self::BranchCmp { left, right, .. } => vec![*left, *right],
            Self::Switch { value, .. } => vec![*value],
            Self::Return { value } => value.iter().copied().collect(),

            Self::LoadField { object, .. } => vec![*object],
            Self::StoreField { object, value, .. } => vec![*object, *value],
            Self::LoadStaticField { .. } => vec![],
            Self::StoreStaticField { value, .. } => vec![*value],
            Self::LoadFieldAddr { object, .. } => vec![*object],
            Self::LoadStaticFieldAddr { .. } => vec![],

            Self::LoadElement { array, index, .. } | Self::LoadElementAddr { array, index, .. } => {
                vec![*array, *index]
            }
            Self::StoreElement {
                array,
                index,
                value,
                ..
            } => vec![*array, *index, *value],
            Self::ArrayLength { array, .. } => vec![*array],

            Self::LoadIndirect { addr, .. } => vec![*addr],
            Self::StoreIndirect { addr, value, .. } => vec![*addr, *value],

            Self::NewObj { args, .. } => args.clone(),
            Self::NewArr { length, .. } => vec![*length],
            Self::CastClass { object, .. }
            | Self::IsInst { object, .. }
            | Self::Unbox { object, .. }
            | Self::UnboxAny { object, .. } => vec![*object],
            Self::Box { value, .. } => vec![*value],
            Self::SizeOf { .. } | Self::LoadToken { .. } => vec![],

            Self::Call { args, .. } | Self::CallVirt { args, .. } => args.clone(),
            Self::CallIndirect { fptr, args, .. } => {
                let mut uses = vec![*fptr];
                uses.extend(args);
                uses
            }

            Self::LoadFunctionPtr { .. } => vec![],
            Self::LoadVirtFunctionPtr { object, .. } => vec![*object],

            Self::LoadArg { .. }
            | Self::LoadLocal { .. }
            | Self::LoadArgAddr { .. }
            | Self::LoadLocalAddr { .. } => vec![],

            Self::Copy { src, .. } => vec![*src],
            Self::Pop { value } => vec![*value],

            Self::Throw { exception } => vec![*exception],
            Self::EndFilter { result } => vec![*result],

            Self::InitBlk {
                dest_addr,
                value,
                size,
            }
            | Self::CopyBlk {
                dest_addr,
                src_addr: value,
                size,
            } => vec![*dest_addr, *value, *size],

            Self::InitObj { dest_addr, .. } => vec![*dest_addr],
            Self::CopyObj {
                dest_addr,
                src_addr,
                ..
            } => vec![*dest_addr, *src_addr],
            Self::LoadObj { src_addr, .. } => vec![*src_addr],
            Self::StoreObj {
                dest_addr, value, ..
            } => vec![*dest_addr, *value],

            Self::LocalAlloc { size, .. } => vec![*size],

            Self::Phi { operands, .. } => operands.iter().map(|(_, v)| *v).collect(),

            Self::Jump { .. }
            | Self::Rethrow
            | Self::EndFinally
            | Self::Leave { .. }
            | Self::Nop
            | Self::Break
            | Self::Constrained { .. } => vec![],
        }
    }

    /// Returns `true` if this operation is a terminator (ends a basic block).
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(
            self,
            Self::Jump { .. }
                | Self::Branch { .. }
                | Self::BranchCmp { .. }
                | Self::Switch { .. }
                | Self::Return { .. }
                | Self::Throw { .. }
                | Self::Rethrow
                | Self::Leave { .. }
                | Self::EndFinally
                | Self::EndFilter { .. }
        )
    }

    /// Returns `true` if this operation may throw an exception.
    #[must_use]
    pub const fn may_throw(&self) -> bool {
        matches!(
            self,
            Self::Div { .. }
                | Self::Rem { .. }
                | Self::AddOvf { .. }
                | Self::SubOvf { .. }
                | Self::MulOvf { .. }
                | Self::Conv {
                    overflow_check: true,
                    ..
                }
                | Self::LoadField { .. }
                | Self::StoreField { .. }
                | Self::LoadElement { .. }
                | Self::StoreElement { .. }
                | Self::LoadElementAddr { .. }
                | Self::LoadIndirect { .. }
                | Self::StoreIndirect { .. }
                | Self::NewObj { .. }
                | Self::NewArr { .. }
                | Self::CastClass { .. }
                | Self::Unbox { .. }
                | Self::UnboxAny { .. }
                | Self::Call { .. }
                | Self::CallVirt { .. }
                | Self::CallIndirect { .. }
                | Self::Throw { .. }
                | Self::Ckfinite { .. }
        )
    }

    /// Returns `true` if this operation is pure (has no side effects).
    ///
    /// Pure operations can be eliminated if their result is unused.
    #[must_use]
    pub const fn is_pure(&self) -> bool {
        matches!(
            self,
            Self::Const { .. }
                | Self::Add { .. }
                | Self::Sub { .. }
                | Self::Mul { .. }
                | Self::Neg { .. }
                | Self::And { .. }
                | Self::Or { .. }
                | Self::Xor { .. }
                | Self::Not { .. }
                | Self::Shl { .. }
                | Self::Shr { .. }
                | Self::Ceq { .. }
                | Self::Clt { .. }
                | Self::Cgt { .. }
                | Self::Conv {
                    overflow_check: false,
                    ..
                }
                | Self::Copy { .. }
                | Self::SizeOf { .. }
                | Self::LoadToken { .. }
                | Self::LoadArg { .. }
                | Self::LoadLocal { .. }
                | Self::LoadArgAddr { .. }
                | Self::LoadLocalAddr { .. }
                | Self::Phi { .. }
                | Self::Nop
                | Self::Pop { .. }
        )
    }

    /// Replaces all uses of `old_var` with `new_var` in this operation.
    ///
    /// This is used for copy propagation and other variable substitution transformations.
    ///
    /// # Arguments
    ///
    /// * `old_var` - The variable to replace.
    /// * `new_var` - The variable to use instead.
    ///
    /// # Returns
    ///
    /// The number of replacements made.
    pub fn replace_uses(&mut self, old_var: SsaVarId, new_var: SsaVarId) -> usize {
        let mut count = 0;

        // Helper closure to replace a variable
        let mut replace = |var: &mut SsaVarId| {
            if *var == old_var {
                *var = new_var;
                count += 1;
            }
        };

        match self {
            // Binary arithmetic and comparison branches
            Self::Add { left, right, .. }
            | Self::AddOvf { left, right, .. }
            | Self::Sub { left, right, .. }
            | Self::SubOvf { left, right, .. }
            | Self::Mul { left, right, .. }
            | Self::MulOvf { left, right, .. }
            | Self::Div { left, right, .. }
            | Self::Rem { left, right, .. }
            | Self::And { left, right, .. }
            | Self::Or { left, right, .. }
            | Self::Xor { left, right, .. }
            | Self::Ceq { left, right, .. }
            | Self::Clt { left, right, .. }
            | Self::Cgt { left, right, .. }
            | Self::BranchCmp { left, right, .. } => {
                replace(left);
                replace(right);
            }

            // Unary operations and conversion
            Self::Neg { operand, .. }
            | Self::Not { operand, .. }
            | Self::Ckfinite { operand, .. }
            | Self::Conv { operand, .. } => {
                replace(operand);
            }

            // Shift operations
            Self::Shl { value, amount, .. } | Self::Shr { value, amount, .. } => {
                replace(value);
                replace(amount);
            }

            // Copy operation
            Self::Copy { src, .. } => {
                replace(src);
            }

            // Control flow
            Self::Branch { condition, .. } => {
                replace(condition);
            }
            Self::Switch { value, .. }
            | Self::StoreStaticField { value, .. }
            | Self::Pop { value } => {
                replace(value);
            }
            Self::Return { value: Some(v) } => {
                replace(v);
            }

            // Object/field operations
            Self::LoadField { object, .. }
            | Self::LoadFieldAddr { object, .. }
            | Self::CastClass { object, .. }
            | Self::IsInst { object, .. }
            | Self::Box { value: object, .. }
            | Self::Unbox { object, .. }
            | Self::UnboxAny { object, .. }
            | Self::LoadVirtFunctionPtr { object, .. } => {
                replace(object);
            }
            Self::StoreField { object, value, .. } => {
                replace(object);
                replace(value);
            }

            // Array operations
            Self::LoadElement { array, index, .. } | Self::LoadElementAddr { array, index, .. } => {
                replace(array);
                replace(index);
            }
            Self::StoreElement {
                array,
                index,
                value,
                ..
            } => {
                replace(array);
                replace(index);
                replace(value);
            }
            Self::NewArr { length, .. } => {
                replace(length);
            }
            Self::ArrayLength { array, .. } => {
                replace(array);
            }

            // Indirect load/store
            Self::LoadIndirect { addr, .. } => {
                replace(addr);
            }
            Self::StoreIndirect { addr, value, .. } => {
                replace(addr);
                replace(value);
            }

            // Calls
            Self::Call { args, .. } | Self::CallVirt { args, .. } | Self::NewObj { args, .. } => {
                for arg in args {
                    replace(arg);
                }
            }
            Self::CallIndirect { fptr, args, .. } => {
                replace(fptr);
                for arg in args {
                    replace(arg);
                }
            }

            // Other
            Self::Throw { exception } => {
                replace(exception);
            }
            Self::EndFilter { result } => {
                replace(result);
            }
            Self::Phi { operands, .. } => {
                for (_, operand) in operands {
                    replace(operand);
                }
            }
            Self::StoreObj {
                dest_addr, value, ..
            } => {
                replace(dest_addr);
                replace(value);
            }
            Self::LoadObj { src_addr, .. } => {
                replace(src_addr);
            }
            Self::LocalAlloc { size, .. } => {
                replace(size);
            }
            Self::InitObj { dest_addr, .. } => {
                replace(dest_addr);
            }
            Self::CopyObj {
                dest_addr,
                src_addr,
                ..
            } => {
                replace(dest_addr);
                replace(src_addr);
            }
            Self::CopyBlk {
                dest_addr,
                src_addr,
                size,
            } => {
                replace(dest_addr);
                replace(src_addr);
                replace(size);
            }
            Self::InitBlk {
                dest_addr,
                value,
                size,
            } => {
                replace(dest_addr);
                replace(value);
                replace(size);
            }

            // Operations without variable uses
            Self::Const { .. }
            | Self::LoadStaticField { .. }
            | Self::LoadStaticFieldAddr { .. }
            | Self::Jump { .. }
            | Self::Return { value: None }
            | Self::Rethrow
            | Self::EndFinally
            | Self::Leave { .. }
            | Self::SizeOf { .. }
            | Self::LoadToken { .. }
            | Self::LoadArg { .. }
            | Self::LoadLocal { .. }
            | Self::LoadArgAddr { .. }
            | Self::LoadLocalAddr { .. }
            | Self::LoadFunctionPtr { .. }
            | Self::Nop
            | Self::Break
            | Self::Constrained { .. } => {}
        }

        count
    }

    /// Remaps branch target block indices using the provided mapping function.
    ///
    /// This is used to translate RVA-based targets (from CIL instructions) to
    /// sequential block indices (used by the SSA representation).
    ///
    /// # Arguments
    ///
    /// * `remap` - A function that maps old block indices to new block indices.
    ///   Returns `None` if the target should remain unchanged.
    pub fn remap_branch_targets<F>(&mut self, remap: F)
    where
        F: Fn(usize) -> Option<usize>,
    {
        match self {
            Self::Jump { target } | Self::Leave { target } => {
                if let Some(new_target) = remap(*target) {
                    *target = new_target;
                }
            }
            Self::Branch {
                true_target,
                false_target,
                ..
            }
            | Self::BranchCmp {
                true_target,
                false_target,
                ..
            } => {
                if let Some(new_target) = remap(*true_target) {
                    *true_target = new_target;
                }
                if let Some(new_target) = remap(*false_target) {
                    *false_target = new_target;
                }
            }
            Self::Switch {
                targets, default, ..
            } => {
                for target in targets.iter_mut() {
                    if let Some(new_target) = remap(*target) {
                        *target = new_target;
                    }
                }
                if let Some(new_target) = remap(*default) {
                    *default = new_target;
                }
            }
            // All other operations don't have branch targets
            _ => {}
        }
    }

    /// Returns the successor block indices for this operation.
    ///
    /// For control flow operations (terminators), this returns the indices of
    /// all possible successor blocks:
    /// - `Jump` and `Leave`: single target block
    /// - `Branch`: true and false target blocks
    /// - `Switch`: all case targets plus the default target
    ///
    /// For non-terminator operations, returns an empty vector.
    ///
    /// # Returns
    ///
    /// A vector of successor block indices. Empty for non-branching operations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let op = SsaOp::Branch {
    ///     condition: var,
    ///     true_target: 1,
    ///     false_target: 2,
    /// };
    /// assert_eq!(op.successors(), vec![1, 2]);
    /// ```
    #[must_use]
    pub fn successors(&self) -> Vec<usize> {
        match self {
            Self::Jump { target } | Self::Leave { target } => vec![*target],
            Self::Branch {
                true_target,
                false_target,
                ..
            }
            | Self::BranchCmp {
                true_target,
                false_target,
                ..
            } => vec![*true_target, *false_target],
            Self::Switch {
                targets, default, ..
            } => {
                let mut succs = targets.clone();
                succs.push(*default);
                succs
            }
            // Return, Throw, Rethrow, EndFinally, EndFilter have no successors
            _ => vec![],
        }
    }

    /// Redirects control flow targets from `old_target` to `new_target`.
    ///
    /// This method modifies branch/jump targets in-place. It handles all control
    /// flow operations: `Jump`, `Leave`, `Branch`, `BranchCmp`, and `Switch`.
    ///
    /// # Arguments
    ///
    /// * `old_target` - The block index to redirect from
    /// * `new_target` - The block index to redirect to
    ///
    /// # Returns
    ///
    /// `true` if any target was changed, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Redirect all jumps to block 2 to instead go to block 5
    /// if op.redirect_target(2, 5) {
    ///     println!("Target redirected");
    /// }
    /// ```
    pub fn redirect_target(&mut self, old_target: usize, new_target: usize) -> bool {
        if old_target == new_target {
            return false;
        }

        match self {
            Self::Jump { target } | Self::Leave { target } => {
                if *target == old_target {
                    *target = new_target;
                    true
                } else {
                    false
                }
            }
            Self::Branch {
                true_target,
                false_target,
                ..
            }
            | Self::BranchCmp {
                true_target,
                false_target,
                ..
            } => {
                let mut changed = false;
                if *true_target == old_target {
                    *true_target = new_target;
                    changed = true;
                }
                if *false_target == old_target {
                    *false_target = new_target;
                    changed = true;
                }
                changed
            }
            Self::Switch {
                targets, default, ..
            } => {
                let mut changed = false;
                if *default == old_target {
                    *default = new_target;
                    changed = true;
                }
                for target in targets.iter_mut() {
                    if *target == old_target {
                        *target = new_target;
                        changed = true;
                    }
                }
                changed
            }
            _ => false,
        }
    }

    /// Returns the metadata token referenced by this operation, if any.
    ///
    /// This extracts the token from operations that reference metadata entities
    /// such as methods, fields, or types. Used for cleanup operations to identify
    /// which SSA operations reference tokens that are being removed.
    ///
    /// # Returns
    ///
    /// - `Some(Token)` if the operation references a method, field, or type token
    /// - `None` if the operation doesn't reference any metadata token
    ///
    /// # Operations That Return Tokens
    ///
    /// - `Call`, `CallVirt`: Method token
    /// - `NewObj`: Constructor method token
    /// - `LoadField`, `StoreField`, `LoadFieldAddr`: Field token
    /// - `LoadStaticField`, `StoreStaticField`, `LoadStaticFieldAddr`: Field token
    /// - `Box`, `Unbox`, `UnboxAny`, `InitObj`, `SizeOf`: Value type token
    /// - `IsInst`, `CastClass`: Target type token
    /// - `NewArr`: Element type token
    /// - `LoadToken`: The loaded token
    #[must_use]
    pub fn referenced_token(&self) -> Option<Token> {
        match self {
            Self::Call { method, .. }
            | Self::CallVirt { method, .. }
            | Self::LoadFunctionPtr { method, .. }
            | Self::LoadVirtFunctionPtr { method, .. } => Some(method.token()),
            Self::NewObj { ctor, .. } => Some(ctor.token()),
            Self::LoadField { field, .. }
            | Self::StoreField { field, .. }
            | Self::LoadFieldAddr { field, .. }
            | Self::LoadStaticField { field, .. }
            | Self::StoreStaticField { field, .. }
            | Self::LoadStaticFieldAddr { field, .. } => Some(field.token()),
            Self::Box { value_type, .. }
            | Self::Unbox { value_type, .. }
            | Self::UnboxAny { value_type, .. }
            | Self::InitObj { value_type, .. }
            | Self::SizeOf { value_type, .. }
            | Self::CopyObj { value_type, .. }
            | Self::LoadObj { value_type, .. }
            | Self::StoreObj { value_type, .. } => Some(value_type.token()),
            Self::IsInst { target_type, .. } | Self::CastClass { target_type, .. } => {
                Some(target_type.token())
            }
            Self::NewArr { elem_type, .. } | Self::LoadElementAddr { elem_type, .. } => {
                Some(elem_type.token())
            }
            Self::LoadToken { token, .. } => Some(token.token()),
            Self::Constrained { constraint_type } => Some(constraint_type.token()),
            _ => None,
        }
    }

    /// Creates a clone of this operation with all variable IDs remapped.
    ///
    /// This is used for block duplication where all variable references
    /// (both destinations and uses) need to be updated to fresh IDs.
    ///
    /// # Arguments
    ///
    /// * `remap` - A function that maps old variable IDs to new ones.
    ///   If the function returns `None`, the original ID is kept.
    ///
    /// # Returns
    ///
    /// A new `SsaOp` with all variable IDs remapped.
    #[must_use]
    pub fn remap_variables<F>(&self, remap: F) -> Self
    where
        F: Fn(SsaVarId) -> Option<SsaVarId>,
    {
        // Helper to remap a single variable
        let r = |var: SsaVarId| remap(var).unwrap_or(var);

        match self.clone() {
            Self::Const { dest, value } => Self::Const {
                dest: r(dest),
                value,
            },

            Self::Add { dest, left, right } => Self::Add {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::AddOvf {
                dest,
                left,
                right,
                unsigned,
            } => Self::AddOvf {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },
            Self::Sub { dest, left, right } => Self::Sub {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::SubOvf {
                dest,
                left,
                right,
                unsigned,
            } => Self::SubOvf {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },
            Self::Mul { dest, left, right } => Self::Mul {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::MulOvf {
                dest,
                left,
                right,
                unsigned,
            } => Self::MulOvf {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },
            Self::Div {
                dest,
                left,
                right,
                unsigned,
            } => Self::Div {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },
            Self::Rem {
                dest,
                left,
                right,
                unsigned,
            } => Self::Rem {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },

            Self::Neg { dest, operand } => Self::Neg {
                dest: r(dest),
                operand: r(operand),
            },
            Self::And { dest, left, right } => Self::And {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::Or { dest, left, right } => Self::Or {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::Xor { dest, left, right } => Self::Xor {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::Not { dest, operand } => Self::Not {
                dest: r(dest),
                operand: r(operand),
            },

            Self::Shl {
                dest,
                value,
                amount,
            } => Self::Shl {
                dest: r(dest),
                value: r(value),
                amount: r(amount),
            },
            Self::Shr {
                dest,
                value,
                amount,
                unsigned,
            } => Self::Shr {
                dest: r(dest),
                value: r(value),
                amount: r(amount),
                unsigned,
            },

            Self::Ceq { dest, left, right } => Self::Ceq {
                dest: r(dest),
                left: r(left),
                right: r(right),
            },
            Self::Clt {
                dest,
                left,
                right,
                unsigned,
            } => Self::Clt {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },
            Self::Cgt {
                dest,
                left,
                right,
                unsigned,
            } => Self::Cgt {
                dest: r(dest),
                left: r(left),
                right: r(right),
                unsigned,
            },

            Self::Conv {
                dest,
                operand,
                target,
                overflow_check,
                unsigned,
            } => Self::Conv {
                dest: r(dest),
                operand: r(operand),
                target,
                overflow_check,
                unsigned,
            },
            Self::Ckfinite { dest, operand } => Self::Ckfinite {
                dest: r(dest),
                operand: r(operand),
            },

            // Control flow - no dests, may have uses
            Self::Jump { target } => Self::Jump { target },
            Self::Branch {
                condition,
                true_target,
                false_target,
            } => Self::Branch {
                condition: r(condition),
                true_target,
                false_target,
            },
            Self::BranchCmp {
                left,
                right,
                cmp,
                unsigned,
                true_target,
                false_target,
            } => Self::BranchCmp {
                left: r(left),
                right: r(right),
                cmp,
                unsigned,
                true_target,
                false_target,
            },
            Self::Switch {
                value,
                targets,
                default,
            } => Self::Switch {
                value: r(value),
                targets,
                default,
            },
            Self::Return { value } => Self::Return {
                value: value.map(&r),
            },
            Self::Leave { target } => Self::Leave { target },

            // Field operations
            Self::LoadField {
                dest,
                object,
                field,
            } => Self::LoadField {
                dest: r(dest),
                object: r(object),
                field,
            },
            Self::StoreField {
                object,
                field,
                value,
            } => Self::StoreField {
                object: r(object),
                field,
                value: r(value),
            },
            Self::LoadStaticField { dest, field } => Self::LoadStaticField {
                dest: r(dest),
                field,
            },
            Self::StoreStaticField { field, value } => Self::StoreStaticField {
                field,
                value: r(value),
            },
            Self::LoadFieldAddr {
                dest,
                object,
                field,
            } => Self::LoadFieldAddr {
                dest: r(dest),
                object: r(object),
                field,
            },
            Self::LoadStaticFieldAddr { dest, field } => Self::LoadStaticFieldAddr {
                dest: r(dest),
                field,
            },

            // Array operations
            Self::LoadElement {
                dest,
                array,
                index,
                elem_type,
            } => Self::LoadElement {
                dest: r(dest),
                array: r(array),
                index: r(index),
                elem_type,
            },
            Self::StoreElement {
                array,
                index,
                value,
                elem_type,
            } => Self::StoreElement {
                array: r(array),
                index: r(index),
                value: r(value),
                elem_type,
            },
            Self::LoadElementAddr {
                dest,
                array,
                index,
                elem_type,
            } => Self::LoadElementAddr {
                dest: r(dest),
                array: r(array),
                index: r(index),
                elem_type,
            },
            Self::ArrayLength { dest, array } => Self::ArrayLength {
                dest: r(dest),
                array: r(array),
            },

            // Indirect operations
            Self::LoadIndirect {
                dest,
                addr,
                value_type,
            } => Self::LoadIndirect {
                dest: r(dest),
                addr: r(addr),
                value_type,
            },
            Self::StoreIndirect {
                addr,
                value,
                value_type,
            } => Self::StoreIndirect {
                addr: r(addr),
                value: r(value),
                value_type,
            },

            // Object operations
            Self::NewObj { dest, ctor, args } => Self::NewObj {
                dest: r(dest),
                ctor,
                args: args.into_iter().map(&r).collect(),
            },
            Self::NewArr {
                dest,
                elem_type,
                length,
            } => Self::NewArr {
                dest: r(dest),
                elem_type,
                length: r(length),
            },
            Self::CastClass {
                dest,
                object,
                target_type,
            } => Self::CastClass {
                dest: r(dest),
                object: r(object),
                target_type,
            },
            Self::IsInst {
                dest,
                object,
                target_type,
            } => Self::IsInst {
                dest: r(dest),
                object: r(object),
                target_type,
            },
            Self::Box {
                dest,
                value,
                value_type,
            } => Self::Box {
                dest: r(dest),
                value: r(value),
                value_type,
            },
            Self::Unbox {
                dest,
                object,
                value_type,
            } => Self::Unbox {
                dest: r(dest),
                object: r(object),
                value_type,
            },
            Self::UnboxAny {
                dest,
                object,
                value_type,
            } => Self::UnboxAny {
                dest: r(dest),
                object: r(object),
                value_type,
            },
            Self::SizeOf { dest, value_type } => Self::SizeOf {
                dest: r(dest),
                value_type,
            },
            Self::LoadToken { dest, token } => Self::LoadToken {
                dest: r(dest),
                token,
            },

            // Call operations
            Self::Call { dest, method, args } => Self::Call {
                dest: dest.map(&r),
                method,
                args: args.into_iter().map(&r).collect(),
            },
            Self::CallVirt { dest, method, args } => Self::CallVirt {
                dest: dest.map(&r),
                method,
                args: args.into_iter().map(&r).collect(),
            },
            Self::CallIndirect {
                dest,
                fptr,
                signature,
                args,
            } => Self::CallIndirect {
                dest: dest.map(&r),
                fptr: r(fptr),
                signature,
                args: args.into_iter().map(&r).collect(),
            },

            // Function pointer operations
            Self::LoadFunctionPtr { dest, method } => Self::LoadFunctionPtr {
                dest: r(dest),
                method,
            },
            Self::LoadVirtFunctionPtr {
                dest,
                object,
                method,
            } => Self::LoadVirtFunctionPtr {
                dest: r(dest),
                object: r(object),
                method,
            },

            // Value and address loading
            Self::LoadArg { dest, arg_index } => Self::LoadArg {
                dest: r(dest),
                arg_index,
            },
            Self::LoadLocal { dest, local_index } => Self::LoadLocal {
                dest: r(dest),
                local_index,
            },
            Self::LoadArgAddr { dest, arg_index } => Self::LoadArgAddr {
                dest: r(dest),
                arg_index,
            },
            Self::LoadLocalAddr { dest, local_index } => Self::LoadLocalAddr {
                dest: r(dest),
                local_index,
            },

            // Misc operations
            Self::Copy { dest, src } => Self::Copy {
                dest: r(dest),
                src: r(src),
            },
            Self::Pop { value } => Self::Pop { value: r(value) },
            Self::Throw { exception } => Self::Throw {
                exception: r(exception),
            },
            Self::Rethrow => Self::Rethrow,
            Self::EndFilter { result } => Self::EndFilter { result: r(result) },
            Self::EndFinally => Self::EndFinally,
            Self::Nop => Self::Nop,
            Self::Break => Self::Break,

            // Memory block operations
            Self::LocalAlloc { dest, size } => Self::LocalAlloc {
                dest: r(dest),
                size: r(size),
            },
            Self::InitObj {
                dest_addr,
                value_type,
            } => Self::InitObj {
                dest_addr: r(dest_addr),
                value_type,
            },
            Self::LoadObj {
                dest,
                src_addr,
                value_type,
            } => Self::LoadObj {
                dest: r(dest),
                src_addr: r(src_addr),
                value_type,
            },
            Self::StoreObj {
                dest_addr,
                value,
                value_type,
            } => Self::StoreObj {
                dest_addr: r(dest_addr),
                value: r(value),
                value_type,
            },
            Self::CopyObj {
                dest_addr,
                src_addr,
                value_type,
            } => Self::CopyObj {
                dest_addr: r(dest_addr),
                src_addr: r(src_addr),
                value_type,
            },
            Self::CopyBlk {
                dest_addr,
                src_addr,
                size,
            } => Self::CopyBlk {
                dest_addr: r(dest_addr),
                src_addr: r(src_addr),
                size: r(size),
            },
            Self::InitBlk {
                dest_addr,
                value,
                size,
            } => Self::InitBlk {
                dest_addr: r(dest_addr),
                value: r(value),
                size: r(size),
            },

            // Phi operations
            Self::Phi { dest, operands } => Self::Phi {
                dest: r(dest),
                operands: operands.into_iter().map(|(p, v)| (p, r(v))).collect(),
            },

            Self::Constrained { constraint_type } => Self::Constrained { constraint_type },
        }
    }

    /// Extracts binary operation information if this is a binary operation.
    ///
    /// This method provides a uniform view of all binary operations (arithmetic,
    /// bitwise, comparison, shifts) for optimization passes that need to handle
    /// them generically.
    ///
    /// # Returns
    ///
    /// - `Some(BinaryOpInfo)` if this is a binary operation
    /// - `None` for all other operations
    ///
    /// # Supported Operations
    ///
    /// - Arithmetic: `Add`, `AddOvf`, `Sub`, `SubOvf`, `Mul`, `MulOvf`, `Div`, `Rem`
    /// - Bitwise: `And`, `Or`, `Xor`
    /// - Shifts: `Shl`, `Shr`
    /// - Comparisons: `Ceq`, `Clt`, `Cgt`
    ///
    /// # Example
    ///
    /// ```ignore
    /// match op.as_binary_op() {
    ///     Some(info) if info.kind == BinaryOpKind::Add => {
    ///         // Handle addition
    ///     }
    ///     Some(info) => {
    ///         // Handle other binary ops
    ///     }
    ///     None => {
    ///         // Not a binary operation
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn as_binary_op(&self) -> Option<BinaryOpInfo> {
        match *self {
            Self::Add { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Add,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::AddOvf {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::AddOvf,
                dest,
                left,
                right,
                unsigned,
            }),
            Self::Sub { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Sub,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::SubOvf {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::SubOvf,
                dest,
                left,
                right,
                unsigned,
            }),
            Self::Mul { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Mul,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::MulOvf {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::MulOvf,
                dest,
                left,
                right,
                unsigned,
            }),
            Self::Div {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Div,
                dest,
                left,
                right,
                unsigned,
            }),
            Self::Rem {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Rem,
                dest,
                left,
                right,
                unsigned,
            }),
            Self::And { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::And,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::Or { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Or,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::Xor { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Xor,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::Shl {
                dest,
                value,
                amount,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Shl,
                dest,
                left: value,
                right: amount,
                unsigned: false,
            }),
            Self::Shr {
                dest,
                value,
                amount,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Shr,
                dest,
                left: value,
                right: amount,
                unsigned,
            }),
            Self::Ceq { dest, left, right } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Ceq,
                dest,
                left,
                right,
                unsigned: false,
            }),
            Self::Clt {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Clt,
                dest,
                left,
                right,
                unsigned,
            }),
            Self::Cgt {
                dest,
                left,
                right,
                unsigned,
            } => Some(BinaryOpInfo {
                kind: BinaryOpKind::Cgt,
                dest,
                left,
                right,
                unsigned,
            }),
            _ => None,
        }
    }

    /// Extracts unary operation information if this is a unary operation.
    ///
    /// This method provides a uniform view of all unary operations for
    /// optimization passes that need to handle them generically.
    ///
    /// # Returns
    ///
    /// - `Some(UnaryOpInfo)` if this is a unary operation
    /// - `None` for all other operations
    ///
    /// # Supported Operations
    ///
    /// - `Neg`: Negation
    /// - `Not`: Bitwise NOT
    /// - `Ckfinite`: Check finite
    ///
    /// # Note
    ///
    /// `Conv` is not included because it requires additional type information
    /// that doesn't fit the simple unary pattern.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(info) = op.as_unary_op() {
    ///     println!("Unary {} on {}", info.kind, info.operand);
    /// }
    /// ```
    #[must_use]
    pub fn as_unary_op(&self) -> Option<UnaryOpInfo> {
        match *self {
            Self::Neg { dest, operand } => Some(UnaryOpInfo {
                kind: UnaryOpKind::Neg,
                dest,
                operand,
            }),
            Self::Not { dest, operand } => Some(UnaryOpInfo {
                kind: UnaryOpKind::Not,
                dest,
                operand,
            }),
            Self::Ckfinite { dest, operand } => Some(UnaryOpInfo {
                kind: UnaryOpKind::Ckfinite,
                dest,
                operand,
            }),
            _ => None,
        }
    }

    /// Returns the stack effect (pops, pushes) for this SSA operation.
    ///
    /// This represents the net effect on the evaluation stack when the operation
    /// is executed, assuming operands have already been loaded. The effect is:
    /// - pops: number of values consumed from the stack
    /// - pushes: number of values produced to the stack
    ///
    /// Note: This tracks the operation's own effect, not the loading of operands
    /// (which is tracked separately during codegen).
    #[must_use]
    pub fn stack_effect(&self) -> (u32, u32) {
        match self {
            // Binary arithmetic, comparisons, and array access - pop 2, push 1
            Self::Add { .. }
            | Self::Sub { .. }
            | Self::Mul { .. }
            | Self::Div { .. }
            | Self::Rem { .. }
            | Self::AddOvf { .. }
            | Self::SubOvf { .. }
            | Self::MulOvf { .. }
            | Self::And { .. }
            | Self::Or { .. }
            | Self::Xor { .. }
            | Self::Shl { .. }
            | Self::Shr { .. }
            | Self::Ceq { .. }
            | Self::Clt { .. }
            | Self::Cgt { .. }
            | Self::LoadElement { .. }
            | Self::LoadElementAddr { .. } => (2, 1),

            // Control flow
            Self::Return { value } => {
                if value.is_some() {
                    (1, 0) // pop return value
                } else {
                    (0, 0) // void return
                }
            }
            // No stack effect (0, 0)
            Self::Jump { .. }
            | Self::Rethrow
            | Self::Leave { .. }
            | Self::EndFinally
            | Self::Copy { .. }
            | Self::Nop
            | Self::Break
            | Self::Constrained { .. }
            | Self::Phi { .. } => (0, 0),

            // Pop 1, push 0 (1, 0)
            Self::Branch { .. }
            | Self::Switch { .. }
            | Self::Throw { .. }
            | Self::EndFilter { .. }
            | Self::Pop { .. }
            | Self::StoreStaticField { .. }
            | Self::InitObj { .. } => (1, 0),

            // Pop 2, push 0 (2, 0)
            Self::BranchCmp { .. }
            | Self::StoreField { .. }
            | Self::StoreIndirect { .. }
            | Self::StoreObj { .. }
            | Self::CopyObj { .. } => (2, 0),

            // Pop 3, push 0 (3, 0)
            Self::StoreElement { .. } | Self::InitBlk { .. } | Self::CopyBlk { .. } => (3, 0),

            // Pop 0, push 1 (0, 1)
            Self::LoadStaticField { .. }
            | Self::LoadStaticFieldAddr { .. }
            | Self::SizeOf { .. }
            | Self::LoadToken { .. }
            | Self::LoadArg { .. }
            | Self::LoadLocal { .. }
            | Self::LoadArgAddr { .. }
            | Self::LoadLocalAddr { .. }
            | Self::LoadFunctionPtr { .. }
            | Self::Const { .. } => (0, 1),

            // Pop 1, push 1 (1, 1)
            Self::Neg { .. }
            | Self::Not { .. }
            | Self::Conv { .. }
            | Self::Ckfinite { .. }
            | Self::LoadField { .. }
            | Self::LoadFieldAddr { .. }
            | Self::ArrayLength { .. }
            | Self::NewArr { .. }
            | Self::LoadIndirect { .. }
            | Self::LoadObj { .. }
            | Self::Box { .. }
            | Self::Unbox { .. }
            | Self::UnboxAny { .. }
            | Self::CastClass { .. }
            | Self::IsInst { .. }
            | Self::LoadVirtFunctionPtr { .. }
            | Self::LocalAlloc { .. } => (1, 1),

            // Call operations - stack effect depends on args and return type
            Self::Call { dest, args, .. } | Self::CallVirt { dest, args, .. } => {
                // args.len() will never exceed u32 for CIL methods
                #[allow(clippy::cast_possible_truncation)]
                let pops = args.len() as u32;
                let pushes = u32::from(dest.is_some());
                (pops, pushes)
            }
            Self::CallIndirect { dest, args, .. } => {
                // Indirect call pops args + function pointer
                // args.len() will never exceed u32 for CIL methods
                #[allow(clippy::cast_possible_truncation)]
                let pops = args.len() as u32 + 1;
                let pushes = u32::from(dest.is_some());
                (pops, pushes)
            }
            Self::NewObj { args, .. } => {
                // newobj pops constructor args, always pushes new instance
                // args.len() will never exceed u32 for CIL methods
                #[allow(clippy::cast_possible_truncation)]
                let pops = args.len() as u32;
                (pops, 1)
            }
        }
    }
}

impl fmt::Display for SsaOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const { dest, value } => write!(f, "{dest} = {value}"),
            Self::Add { dest, left, right } => write!(f, "{dest} = add {left}, {right}"),
            Self::AddOvf {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = add.ovf{suffix} {left}, {right}")
            }
            Self::Sub { dest, left, right } => write!(f, "{dest} = sub {left}, {right}"),
            Self::SubOvf {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = sub.ovf{suffix} {left}, {right}")
            }
            Self::Mul { dest, left, right } => write!(f, "{dest} = mul {left}, {right}"),
            Self::MulOvf {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = mul.ovf{suffix} {left}, {right}")
            }
            Self::Div {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = div{suffix} {left}, {right}")
            }
            Self::Rem {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = rem{suffix} {left}, {right}")
            }
            Self::Neg { dest, operand } => write!(f, "{dest} = neg {operand}"),
            Self::And { dest, left, right } => write!(f, "{dest} = and {left}, {right}"),
            Self::Or { dest, left, right } => write!(f, "{dest} = or {left}, {right}"),
            Self::Xor { dest, left, right } => write!(f, "{dest} = xor {left}, {right}"),
            Self::Not { dest, operand } => write!(f, "{dest} = not {operand}"),
            Self::Shl {
                dest,
                value,
                amount,
            } => write!(f, "{dest} = shl {value}, {amount}"),
            Self::Shr {
                dest,
                value,
                amount,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = shr{suffix} {value}, {amount}")
            }
            Self::Ceq { dest, left, right } => write!(f, "{dest} = ceq {left}, {right}"),
            Self::Clt {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = clt{suffix} {left}, {right}")
            }
            Self::Cgt {
                dest,
                left,
                right,
                unsigned,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(f, "{dest} = cgt{suffix} {left}, {right}")
            }
            Self::Conv {
                dest,
                operand,
                target,
                ..
            } => write!(f, "{dest} = conv.{target} {operand}"),
            Self::Jump { target } => write!(f, "jump B{target}"),
            Self::Branch {
                condition,
                true_target,
                false_target,
            } => write!(f, "branch {condition}, B{true_target}, B{false_target}"),
            Self::BranchCmp {
                left,
                right,
                cmp,
                unsigned,
                true_target,
                false_target,
            } => {
                let suffix = if *unsigned { ".un" } else { "" };
                write!(
                    f,
                    "branchcmp{suffix} {left} {cmp} {right}, B{true_target}, B{false_target}"
                )
            }
            Self::Switch {
                value,
                targets,
                default,
            } => {
                write!(f, "switch {value}, [")?;
                for (i, t) in targets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "B{t}")?;
                }
                write!(f, "], B{default}")
            }
            Self::Return { value: Some(v) } => write!(f, "ret {v}"),
            Self::Return { value: None } => write!(f, "ret"),
            Self::LoadField {
                dest,
                object,
                field,
            } => {
                write!(f, "{dest} = ldfld {field}, {object}")
            }
            Self::StoreField {
                object,
                field,
                value,
            } => write!(f, "stfld {field}, {object}, {value}"),
            Self::LoadStaticField { dest, field } => write!(f, "{dest} = ldsfld {field}"),
            Self::StoreStaticField { field, value } => write!(f, "stsfld {field}, {value}"),
            Self::LoadFieldAddr {
                dest,
                object,
                field,
            } => {
                write!(f, "{dest} = ldflda {field}, {object}")
            }
            Self::LoadStaticFieldAddr { dest, field } => write!(f, "{dest} = ldsflda {field}"),
            Self::LoadElement {
                dest,
                array,
                index,
                elem_type,
            } => write!(f, "{dest} = ldelem.{elem_type} {array}[{index}]"),
            Self::StoreElement {
                array,
                index,
                value,
                elem_type,
            } => write!(f, "stelem.{elem_type} {array}[{index}], {value}"),
            Self::LoadElementAddr {
                dest, array, index, ..
            } => write!(f, "{dest} = ldelema {array}[{index}]"),
            Self::ArrayLength { dest, array } => write!(f, "{dest} = ldlen {array}"),
            Self::LoadIndirect {
                dest,
                addr,
                value_type,
            } => write!(f, "{dest} = ldind.{value_type} {addr}"),
            Self::StoreIndirect {
                addr,
                value,
                value_type,
            } => write!(f, "stind.{value_type} {addr}, {value}"),
            Self::NewObj { dest, ctor, args } => {
                write!(f, "{dest} = newobj {ctor}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            Self::NewArr {
                dest,
                elem_type,
                length,
            } => write!(f, "{dest} = newarr {elem_type}[{length}]"),
            Self::CastClass {
                dest,
                object,
                target_type,
            } => write!(f, "{dest} = castclass {target_type}, {object}"),
            Self::IsInst {
                dest,
                object,
                target_type,
            } => write!(f, "{dest} = isinst {target_type}, {object}"),
            Self::Box {
                dest,
                value,
                value_type,
            } => write!(f, "{dest} = box {value_type}, {value}"),
            Self::Unbox {
                dest,
                object,
                value_type,
            } => write!(f, "{dest} = unbox {value_type}, {object}"),
            Self::UnboxAny {
                dest,
                object,
                value_type,
            } => write!(f, "{dest} = unbox.any {value_type}, {object}"),
            Self::SizeOf { dest, value_type } => write!(f, "{dest} = sizeof {value_type}"),
            Self::LoadToken { dest, token } => write!(f, "{dest} = ldtoken {token}"),
            Self::Call { dest, method, args } => {
                if let Some(d) = dest {
                    write!(f, "{d} = ")?;
                }
                write!(f, "call {method}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            Self::CallVirt { dest, method, args } => {
                if let Some(d) = dest {
                    write!(f, "{d} = ")?;
                }
                write!(f, "callvirt {method}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            Self::CallIndirect {
                dest, fptr, args, ..
            } => {
                if let Some(d) = dest {
                    write!(f, "{d} = ")?;
                }
                write!(f, "calli {fptr}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ")")
            }
            Self::LoadFunctionPtr { dest, method } => write!(f, "{dest} = ldftn {method}"),
            Self::LoadVirtFunctionPtr {
                dest,
                object,
                method,
            } => write!(f, "{dest} = ldvirtftn {method}, {object}"),
            Self::LoadArg { dest, arg_index } => write!(f, "{dest} = ldarg {arg_index}"),
            Self::LoadLocal { dest, local_index } => write!(f, "{dest} = ldloc {local_index}"),
            Self::LoadArgAddr { dest, arg_index } => write!(f, "{dest} = ldarga {arg_index}"),
            Self::LoadLocalAddr { dest, local_index } => {
                write!(f, "{dest} = ldloca {local_index}")
            }
            Self::Copy { dest, src } => write!(f, "{dest} = {src}"),
            Self::Pop { value } => write!(f, "pop {value}"),
            Self::Throw { exception } => write!(f, "throw {exception}"),
            Self::Rethrow => write!(f, "rethrow"),
            Self::EndFinally => write!(f, "endfinally"),
            Self::EndFilter { result } => write!(f, "endfilter {result}"),
            Self::Leave { target } => write!(f, "leave B{target}"),
            Self::InitBlk {
                dest_addr,
                value,
                size,
            } => write!(f, "initblk {dest_addr}, {value}, {size}"),
            Self::CopyBlk {
                dest_addr,
                src_addr,
                size,
            } => write!(f, "cpblk {dest_addr}, {src_addr}, {size}"),
            Self::InitObj {
                dest_addr,
                value_type,
            } => write!(f, "initobj {value_type}, {dest_addr}"),
            Self::CopyObj {
                dest_addr,
                src_addr,
                value_type,
            } => write!(f, "cpobj {value_type}, {dest_addr}, {src_addr}"),
            Self::LoadObj {
                dest,
                src_addr,
                value_type,
            } => write!(f, "{dest} = ldobj {value_type}, {src_addr}"),
            Self::StoreObj {
                dest_addr,
                value,
                value_type,
            } => write!(f, "stobj {value_type}, {dest_addr}, {value}"),
            Self::LocalAlloc { dest, size } => write!(f, "{dest} = localloc {size}"),
            Self::Constrained { constraint_type } => {
                write!(f, "constrained. {constraint_type}")
            }
            Self::Ckfinite { dest, operand } => write!(f, "{dest} = ckfinite {operand}"),
            Self::Nop => write!(f, "nop"),
            Self::Break => write!(f, "break"),
            Self::Phi { dest, operands } => {
                write!(f, "{dest} = phi(")?;
                for (i, (block, var)) in operands.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "B{block}: {var}")?;
                }
                write!(f, ")")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::ssa::{
            ops::{BinaryOpKind, SsaOp, UnaryOpKind},
            types::{FieldRef, MethodRef},
            value::ConstValue,
            SsaVarId,
        },
        metadata::token::Token,
    };

    #[test]
    fn test_dest_extraction() {
        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
        let op = SsaOp::Add { dest, left, right };
        assert_eq!(op.dest(), Some(dest));

        let op = SsaOp::Jump { target: 1 };
        assert_eq!(op.dest(), None);

        let call_dest = SsaVarId::new();
        let op = SsaOp::Call {
            dest: Some(call_dest),
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert_eq!(op.dest(), Some(call_dest));

        let op = SsaOp::Call {
            dest: None,
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert_eq!(op.dest(), None);
    }

    #[test]
    fn test_uses_extraction() {
        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
        let op = SsaOp::Add { dest, left, right };
        assert_eq!(op.uses(), vec![left, right]);

        let const_dest = SsaVarId::new();
        let op = SsaOp::Const {
            dest: const_dest,
            value: ConstValue::I32(42),
        };
        assert!(op.uses().is_empty());

        let phi_dest = SsaVarId::new();
        let phi_op1 = SsaVarId::new();
        let phi_op2 = SsaVarId::new();
        let op = SsaOp::Phi {
            dest: phi_dest,
            operands: vec![(0, phi_op1), (1, phi_op2)],
        };
        assert_eq!(op.uses(), vec![phi_op1, phi_op2]);
    }

    #[test]
    fn test_is_terminator() {
        let cond = SsaVarId::new();
        let exc = SsaVarId::new();
        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();

        assert!(SsaOp::Jump { target: 1 }.is_terminator());
        assert!(SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2
        }
        .is_terminator());
        assert!(SsaOp::Return { value: None }.is_terminator());
        assert!(SsaOp::Throw { exception: exc }.is_terminator());

        assert!(!SsaOp::Nop.is_terminator());
        assert!(!SsaOp::Add { dest, left, right }.is_terminator());
    }

    #[test]
    fn test_is_pure() {
        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();
        let const_dest = SsaVarId::new();
        let object = SsaVarId::new();
        let value = SsaVarId::new();

        assert!(SsaOp::Add { dest, left, right }.is_pure());
        assert!(SsaOp::Const {
            dest: const_dest,
            value: ConstValue::I32(42)
        }
        .is_pure());
        assert!(SsaOp::Nop.is_pure());

        // Not pure: has side effects
        assert!(!SsaOp::StoreField {
            object,
            field: FieldRef::new(Token::new(0x04000001)),
            value
        }
        .is_pure());
        assert!(!SsaOp::Call {
            dest: None,
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![]
        }
        .is_pure());
    }

    #[test]
    fn test_display() {
        let op = SsaOp::Add {
            dest: SsaVarId::from_index(2),
            left: SsaVarId::from_index(0),
            right: SsaVarId::from_index(1),
        };
        assert_eq!(format!("{op}"), "v2 = add v0, v1");

        let op = SsaOp::Const {
            dest: SsaVarId::from_index(0),
            value: ConstValue::I32(42),
        };
        assert_eq!(format!("{op}"), "v0 = 42");

        let op = SsaOp::Branch {
            condition: SsaVarId::from_index(0),
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(format!("{op}"), "branch v0, B1, B2");

        let op = SsaOp::Phi {
            dest: SsaVarId::from_index(3),
            operands: vec![(0, SsaVarId::from_index(1)), (1, SsaVarId::from_index(2))],
        };
        assert_eq!(format!("{op}"), "v3 = phi(B0: v1, B1: v2)");
    }

    #[test]
    fn test_successors() {
        let cond = SsaVarId::new();
        let switch_val = SsaVarId::new();
        let ret_val = SsaVarId::new();
        let exc = SsaVarId::new();
        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();

        // Jump has single successor
        let op = SsaOp::Jump { target: 5 };
        assert_eq!(op.successors(), vec![5]);

        // Leave has single successor
        let op = SsaOp::Leave { target: 3 };
        assert_eq!(op.successors(), vec![3]);

        // Branch has two successors
        let op = SsaOp::Branch {
            condition: cond,
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(op.successors(), vec![1, 2]);

        // Switch has multiple successors plus default
        let op = SsaOp::Switch {
            value: switch_val,
            targets: vec![1, 2, 3],
            default: 4,
        };
        assert_eq!(op.successors(), vec![1, 2, 3, 4]);

        // Return has no successors
        let op = SsaOp::Return { value: None };
        assert!(op.successors().is_empty());

        let op = SsaOp::Return {
            value: Some(ret_val),
        };
        assert!(op.successors().is_empty());

        // Throw has no successors
        let op = SsaOp::Throw { exception: exc };
        assert!(op.successors().is_empty());

        // Non-terminators have no successors
        let op = SsaOp::Add { dest, left, right };
        assert!(op.successors().is_empty());

        let op = SsaOp::Nop;
        assert!(op.successors().is_empty());
    }

    #[test]
    fn test_as_binary_op() {
        let dest = SsaVarId::new();
        let left = SsaVarId::new();
        let right = SsaVarId::new();

        // Add is a binary operation
        let op = SsaOp::Add { dest, left, right };
        let info = op.as_binary_op().expect("Add should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Add);
        assert_eq!(info.dest, dest);
        assert_eq!(info.left, left);
        assert_eq!(info.right, right);
        assert!(!info.unsigned);

        // Div with unsigned
        let op = SsaOp::Div {
            dest,
            left,
            right,
            unsigned: true,
        };
        let info = op.as_binary_op().expect("Div should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Div);
        assert!(info.unsigned);

        // Shl maps value/amount to left/right
        let value = SsaVarId::new();
        let amount = SsaVarId::new();
        let op = SsaOp::Shl {
            dest,
            value,
            amount,
        };
        let info = op.as_binary_op().expect("Shl should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Shl);
        assert_eq!(info.left, value);
        assert_eq!(info.right, amount);

        // Comparison operations
        let op = SsaOp::Clt {
            dest,
            left,
            right,
            unsigned: true,
        };
        let info = op.as_binary_op().expect("Clt should be binary op");
        assert_eq!(info.kind, BinaryOpKind::Clt);
        assert!(info.unsigned);

        // Non-binary operations return None
        assert!(SsaOp::Nop.as_binary_op().is_none());
        assert!(SsaOp::Jump { target: 1 }.as_binary_op().is_none());
        assert!(SsaOp::Neg {
            dest,
            operand: left
        }
        .as_binary_op()
        .is_none());
        assert!(SsaOp::Const {
            dest,
            value: ConstValue::I32(42)
        }
        .as_binary_op()
        .is_none());
    }

    #[test]
    fn test_as_unary_op() {
        let dest = SsaVarId::new();
        let operand = SsaVarId::new();

        // Neg is a unary operation
        let op = SsaOp::Neg { dest, operand };
        let info = op.as_unary_op().expect("Neg should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Neg);
        assert_eq!(info.dest, dest);
        assert_eq!(info.operand, operand);

        // Not is a unary operation
        let op = SsaOp::Not { dest, operand };
        let info = op.as_unary_op().expect("Not should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Not);

        // Ckfinite is a unary operation
        let op = SsaOp::Ckfinite { dest, operand };
        let info = op.as_unary_op().expect("Ckfinite should be unary op");
        assert_eq!(info.kind, UnaryOpKind::Ckfinite);

        // Non-unary operations return None
        assert!(SsaOp::Nop.as_unary_op().is_none());
        assert!(SsaOp::Jump { target: 1 }.as_unary_op().is_none());

        let left = SsaVarId::new();
        let right = SsaVarId::new();
        assert!(SsaOp::Add { dest, left, right }.as_unary_op().is_none());

        assert!(SsaOp::Const {
            dest,
            value: ConstValue::I32(42)
        }
        .as_unary_op()
        .is_none());
    }

    #[test]
    fn test_binary_op_kind_display() {
        assert_eq!(format!("{}", BinaryOpKind::Add), "add");
        assert_eq!(format!("{}", BinaryOpKind::AddOvf), "add.ovf");
        assert_eq!(format!("{}", BinaryOpKind::Ceq), "ceq");
        assert_eq!(format!("{}", BinaryOpKind::Shl), "shl");
    }

    #[test]
    fn test_unary_op_kind_display() {
        assert_eq!(format!("{}", UnaryOpKind::Neg), "neg");
        assert_eq!(format!("{}", UnaryOpKind::Not), "not");
        assert_eq!(format!("{}", UnaryOpKind::Ckfinite), "ckfinite");
    }
}
