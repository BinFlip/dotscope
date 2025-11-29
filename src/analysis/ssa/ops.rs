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

use super::types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef};
use super::value::ConstValue;
use super::SsaVarId;

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
    // ========================================================================
    // Constants
    // ========================================================================
    /// Load a constant value.
    ///
    /// `dest = const value`
    Const { dest: SsaVarId, value: ConstValue },

    // ========================================================================
    // Arithmetic - Binary
    // ========================================================================
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

    // ========================================================================
    // Arithmetic - Unary
    // ========================================================================
    /// Negation: `dest = -operand`
    Neg { dest: SsaVarId, operand: SsaVarId },

    // ========================================================================
    // Bitwise Operations
    // ========================================================================
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

    // ========================================================================
    // Comparison Operations
    // ========================================================================
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

    // ========================================================================
    // Conversion Operations
    // ========================================================================
    /// Type conversion: `dest = (target_type)operand`
    Conv {
        dest: SsaVarId,
        operand: SsaVarId,
        target: SsaType,
        overflow_check: bool,
        unsigned: bool,
    },

    // ========================================================================
    // Control Flow
    // ========================================================================
    /// Unconditional jump to a block.
    Jump { target: usize },

    /// Conditional branch: if condition is true, go to true_target, else false_target.
    Branch {
        condition: SsaVarId,
        true_target: usize,
        false_target: usize,
    },

    /// Switch statement: jump to targets[value] or default if out of range.
    Switch {
        value: SsaVarId,
        targets: Vec<usize>,
        default: usize,
    },

    /// Return from method with optional value.
    Return { value: Option<SsaVarId> },

    // ========================================================================
    // Field Operations
    // ========================================================================
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

    // ========================================================================
    // Array Operations
    // ========================================================================
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
        elem_type: SsaType,
    },

    /// Get array length: `dest = array.Length`
    ArrayLength { dest: SsaVarId, array: SsaVarId },

    // ========================================================================
    // Indirect Memory Access
    // ========================================================================
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

    // ========================================================================
    // Object Operations
    // ========================================================================
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

    // ========================================================================
    // Call Operations
    // ========================================================================
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

    // ========================================================================
    // Function Pointer Operations
    // ========================================================================
    /// Load function pointer: `dest = &method`
    LoadFunctionPtr { dest: SsaVarId, method: MethodRef },

    /// Load virtual function pointer: `dest = &obj.method`
    LoadVirtFunctionPtr {
        dest: SsaVarId,
        object: SsaVarId,
        method: MethodRef,
    },

    // ========================================================================
    // Address Operations
    // ========================================================================
    /// Load argument address: `dest = &argN`
    LoadArgAddr { dest: SsaVarId, arg_index: u16 },

    /// Load local address: `dest = &localN`
    LoadLocalAddr { dest: SsaVarId, local_index: u16 },

    // ========================================================================
    // Stack Operations (converted to moves)
    // ========================================================================
    /// Copy value (from dup): `dest = src`
    Copy { dest: SsaVarId, src: SsaVarId },

    /// Pop value from stack (value is discarded, but we track the use)
    Pop { value: SsaVarId },

    // ========================================================================
    // Exception Operations
    // ========================================================================
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

    // ========================================================================
    // Initialization
    // ========================================================================
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

    // ========================================================================
    // Misc
    // ========================================================================
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

            Self::LoadArgAddr { .. } | Self::LoadLocalAddr { .. } => vec![],

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
                | Self::Phi { .. }
                | Self::Nop
        )
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
    use super::*;
    use crate::metadata::token::Token;

    #[test]
    fn test_dest_extraction() {
        let op = SsaOp::Add {
            dest: SsaVarId::new(2),
            left: SsaVarId::new(0),
            right: SsaVarId::new(1),
        };
        assert_eq!(op.dest(), Some(SsaVarId::new(2)));

        let op = SsaOp::Jump { target: 1 };
        assert_eq!(op.dest(), None);

        let op = SsaOp::Call {
            dest: Some(SsaVarId::new(5)),
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert_eq!(op.dest(), Some(SsaVarId::new(5)));

        let op = SsaOp::Call {
            dest: None,
            method: MethodRef::new(Token::new(0x06000001)),
            args: vec![],
        };
        assert_eq!(op.dest(), None);
    }

    #[test]
    fn test_uses_extraction() {
        let op = SsaOp::Add {
            dest: SsaVarId::new(2),
            left: SsaVarId::new(0),
            right: SsaVarId::new(1),
        };
        assert_eq!(op.uses(), vec![SsaVarId::new(0), SsaVarId::new(1)]);

        let op = SsaOp::Const {
            dest: SsaVarId::new(0),
            value: ConstValue::I32(42),
        };
        assert!(op.uses().is_empty());

        let op = SsaOp::Phi {
            dest: SsaVarId::new(3),
            operands: vec![(0, SsaVarId::new(1)), (1, SsaVarId::new(2))],
        };
        assert_eq!(op.uses(), vec![SsaVarId::new(1), SsaVarId::new(2)]);
    }

    #[test]
    fn test_is_terminator() {
        assert!(SsaOp::Jump { target: 1 }.is_terminator());
        assert!(SsaOp::Branch {
            condition: SsaVarId::new(0),
            true_target: 1,
            false_target: 2
        }
        .is_terminator());
        assert!(SsaOp::Return { value: None }.is_terminator());
        assert!(SsaOp::Throw {
            exception: SsaVarId::new(0)
        }
        .is_terminator());

        assert!(!SsaOp::Nop.is_terminator());
        assert!(!SsaOp::Add {
            dest: SsaVarId::new(0),
            left: SsaVarId::new(1),
            right: SsaVarId::new(2)
        }
        .is_terminator());
    }

    #[test]
    fn test_is_pure() {
        assert!(SsaOp::Add {
            dest: SsaVarId::new(0),
            left: SsaVarId::new(1),
            right: SsaVarId::new(2)
        }
        .is_pure());
        assert!(SsaOp::Const {
            dest: SsaVarId::new(0),
            value: ConstValue::I32(42)
        }
        .is_pure());
        assert!(SsaOp::Nop.is_pure());

        // Not pure: has side effects
        assert!(!SsaOp::StoreField {
            object: SsaVarId::new(0),
            field: FieldRef::new(Token::new(0x04000001)),
            value: SsaVarId::new(1)
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
            dest: SsaVarId::new(2),
            left: SsaVarId::new(0),
            right: SsaVarId::new(1),
        };
        assert_eq!(format!("{op}"), "v2 = add v0, v1");

        let op = SsaOp::Const {
            dest: SsaVarId::new(0),
            value: ConstValue::I32(42),
        };
        assert_eq!(format!("{op}"), "v0 = 42");

        let op = SsaOp::Branch {
            condition: SsaVarId::new(0),
            true_target: 1,
            false_target: 2,
        };
        assert_eq!(format!("{op}"), "branch v0, B1, B2");

        let op = SsaOp::Phi {
            dest: SsaVarId::new(3),
            operands: vec![(0, SsaVarId::new(1)), (1, SsaVarId::new(2))],
        };
        assert_eq!(format!("{op}"), "v3 = phi(B0: v1, B1: v2)");
    }
}
