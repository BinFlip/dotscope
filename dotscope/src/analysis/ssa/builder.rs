//! Builder pattern for programmatic SSA construction.
//!
//! This module provides a fluent API for building SSA functions without the
//! boilerplate of manual block/variable ID management. It's useful for:
//!
//! - Writing unit tests for deobfuscation passes
//! - Programmatic SSA construction in optimization passes
//! - Creating test fixtures for SSA analysis
//!
//! # Design
//!
//! The builder uses a closure-based API where all blocks are defined within
//! a single expression, making the CFG structure visually clear:
//!
//! ```rust,ignore
//! let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
//!     let cond = f.arg(0);
//!
//!     f.block(0, |b| b.branch(cond, 1, 2));
//!     f.block(1, |b| b.jump(3));
//!     f.block(2, |b| b.jump(4));
//!     f.block(3, |b| b.ret());
//!     f.block(4, |b| b.ret());
//! });
//! ```
//!
//! # Variable Management
//!
//! Variables are automatically allocated when operations are performed.
//! Operations that produce values (like `const_i32`, `add`) return the
//! allocated `SsaVarId` which can be used in subsequent operations.

use std::collections::HashMap;

use crate::analysis::ssa::{
    ConstValue, DefSite, MethodRef, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction,
    SsaOp, SsaType, SsaVarId, SsaVariable, VariableOrigin,
};

/// Builder for constructing SSA functions programmatically.
///
/// Provides a closure-based API for building SSA functions where all
/// blocks are defined within a single expression, making the CFG
/// structure visually clear.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::SsaFunctionBuilder;
///
/// // Simple function: return arg0 + arg1
/// let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
///     let (a, b) = (f.arg(0), f.arg(1));
///     f.block(0, |blk| {
///         let sum = blk.add(a, b);
///         blk.ret_val(sum);
///     });
/// });
/// ```
#[derive(Debug)]
pub struct SsaFunctionBuilder {
    num_args: usize,
    num_locals: usize,
    /// Next stack slot number for temporaries
    next_stack_slot: u32,
    /// Pre-allocated argument variable IDs
    arg_vars: Vec<SsaVarId>,
    /// Pre-allocated local variable IDs
    local_vars: Vec<SsaVarId>,
    /// Variables created during building
    variables: Vec<SsaVariable>,
    /// Blocks indexed by ID (may have gaps)
    blocks: HashMap<usize, SsaBlock>,
    /// Highest block ID seen
    max_block_id: usize,
}

impl SsaFunctionBuilder {
    /// Creates a new builder with the specified number of arguments and locals.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    #[must_use]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        let mut builder = Self {
            num_args,
            num_locals,
            next_stack_slot: 0,
            arg_vars: Vec::with_capacity(num_args),
            local_vars: Vec::with_capacity(num_locals),
            variables: Vec::new(),
            blocks: HashMap::new(),
            max_block_id: 0,
        };

        // Pre-allocate argument variables (v0, v1, ... for each arg)
        for i in 0..num_args {
            // Argument indices are bounded by method signature limits (< 65535)
            #[allow(clippy::cast_possible_truncation)]
            let idx = i as u16;
            let id = builder.alloc_var_with_origin(VariableOrigin::Argument(idx));
            builder.arg_vars.push(id);
        }

        // Pre-allocate local variables
        for i in 0..num_locals {
            // Local indices are bounded by method body limits (< 65535)
            #[allow(clippy::cast_possible_truncation)]
            let idx = i as u16;
            let id = builder.alloc_var_with_origin(VariableOrigin::Local(idx));
            builder.local_vars.push(id);
        }

        builder
    }

    /// Allocates a fresh variable ID with the given origin.
    fn alloc_var_with_origin(&mut self, origin: VariableOrigin) -> SsaVarId {
        let var = SsaVariable::new(origin, 0, DefSite::entry());
        let id = var.id();
        self.variables.push(var);
        id
    }

    /// Allocates a fresh variable ID for a stack temporary.
    fn alloc_stack_var(&mut self) -> SsaVarId {
        let slot = self.next_stack_slot;
        self.next_stack_slot += 1;
        self.alloc_var_with_origin(VariableOrigin::Stack(slot))
    }

    /// Allocates a fresh variable ID for a stack temporary with a known type.
    fn alloc_stack_var_typed(&mut self, var_type: SsaType) -> SsaVarId {
        let id = self.alloc_stack_var();
        // Set the type on the last added variable
        if let Some(var) = self.variables.last_mut() {
            var.set_type(var_type);
        }
        id
    }

    /// Builds the SSA function using a closure that defines all blocks.
    ///
    /// This is the primary API - all blocks are defined within the closure,
    /// making the control flow structure visually apparent.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives an `SsaFunctionContext` for defining blocks
    ///
    /// # Returns
    ///
    /// The constructed `SsaFunction`.
    pub fn build_with<F>(mut self, f: F) -> SsaFunction
    where
        F: FnOnce(&mut SsaFunctionContext<'_>),
    {
        let mut ctx = SsaFunctionContext { builder: &mut self };
        f(&mut ctx);
        self.build()
    }

    /// Consumes the builder and produces the SsaFunction.
    fn build(self) -> SsaFunction {
        let mut func = SsaFunction::new(self.num_args, self.num_locals);

        // Add variables
        for var in self.variables {
            func.add_variable(var);
        }

        // Add blocks in order (filling gaps with empty blocks if needed)
        for id in 0..=self.max_block_id {
            if let Some(block) = self.blocks.get(&id) {
                func.add_block(block.clone());
            } else {
                // Fill gap with empty block
                func.add_block(SsaBlock::new(id));
            }
        }

        func
    }
}

/// Context passed to the build closure for defining blocks.
///
/// This is the main interface used within `build_with()` to define
/// the function's blocks and access pre-allocated variables.
pub struct SsaFunctionContext<'a> {
    builder: &'a mut SsaFunctionBuilder,
}

impl SsaFunctionContext<'_> {
    /// Gets the argument variable at the specified index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= num_args`.
    #[must_use]
    pub fn arg(&self, index: usize) -> SsaVarId {
        self.builder.arg_vars[index]
    }

    /// Gets the local variable at the specified index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= num_locals`.
    #[must_use]
    pub fn local(&self, index: usize) -> SsaVarId {
        self.builder.local_vars[index]
    }

    /// Allocates a fresh variable ID.
    ///
    /// Use this when you need a variable ID before defining it
    /// (e.g., for phi node placeholders that will be defined later).
    #[must_use]
    pub fn var(&mut self) -> SsaVarId {
        self.builder.alloc_stack_var()
    }

    /// Defines a block with the given ID using a closure.
    ///
    /// The closure receives an `SsaBlockBuilder` for adding instructions.
    ///
    /// # Arguments
    ///
    /// * `id` - The block ID (should be sequential starting from 0)
    /// * `f` - A closure that defines the block's contents
    pub fn block<F>(&mut self, id: usize, f: F)
    where
        F: FnOnce(&mut SsaBlockBuilder<'_>),
    {
        // Track max block ID
        if id > self.builder.max_block_id {
            self.builder.max_block_id = id;
        }

        let mut block = SsaBlock::new(id);
        let mut block_builder = SsaBlockBuilder {
            builder: self.builder,
            block: &mut block,
            block_id: id,
        };

        f(&mut block_builder);

        self.builder.blocks.insert(id, block);
    }
}

/// Builder for constructing individual SSA blocks.
///
/// Provides shorthand methods for adding instructions to a block.
/// Operations that produce values return the allocated `SsaVarId`.
pub struct SsaBlockBuilder<'a> {
    builder: &'a mut SsaFunctionBuilder,
    block: &'a mut SsaBlock,
    block_id: usize,
}

impl SsaBlockBuilder<'_> {
    /// Helper to allocate a variable and add an instruction.
    fn add_op(&mut self, op: SsaOp) -> SsaVarId {
        let dest = op.dest().unwrap_or_else(|| self.builder.alloc_stack_var());
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Helper to add an instruction without returning a var.
    fn add_op_void(&mut self, op: SsaOp) {
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: dest = const i32
    #[must_use]
    pub fn const_i32(&mut self, value: i32) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::I32(value),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = const i64
    #[must_use]
    pub fn const_i64(&mut self, value: i64) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::I64(value),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = const f32
    #[must_use]
    pub fn const_f32(&mut self, value: f32) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::F32(value),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = const f64
    #[must_use]
    pub fn const_f64(&mut self, value: f64) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::F64(value),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = null
    #[must_use]
    pub fn const_null(&mut self) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::Null,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = true (i32 value 1)
    #[must_use]
    pub fn const_true(&mut self) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::True,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = false (i32 value 0)
    #[must_use]
    pub fn const_false(&mut self) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Const {
            dest,
            value: ConstValue::False,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = const (generic ConstValue)
    #[must_use]
    pub fn const_val(&mut self, value: ConstValue) -> SsaVarId {
        let var_type = value.ssa_type();
        let dest = self.builder.alloc_stack_var_typed(var_type);
        let op = SsaOp::Const { dest, value };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left + right
    #[must_use]
    pub fn add(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Add { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left - right
    #[must_use]
    pub fn sub(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Sub { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left * right
    #[must_use]
    pub fn mul(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Mul { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left / right (signed)
    #[must_use]
    pub fn div(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Div {
            dest,
            left,
            right,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left / right (unsigned)
    #[must_use]
    pub fn div_un(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Div {
            dest,
            left,
            right,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left % right (signed)
    #[must_use]
    pub fn rem(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Rem {
            dest,
            left,
            right,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left % right (unsigned)
    #[must_use]
    pub fn rem_un(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Rem {
            dest,
            left,
            right,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left & right
    #[must_use]
    pub fn and(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::And { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left | right
    #[must_use]
    pub fn or(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Or { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = left ^ right
    #[must_use]
    pub fn xor(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Xor { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = value << amount
    #[must_use]
    pub fn shl(&mut self, value: SsaVarId, amount: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Shl {
            dest,
            value,
            amount,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = value >> amount (signed)
    #[must_use]
    pub fn shr(&mut self, value: SsaVarId, amount: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Shr {
            dest,
            value,
            amount,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = value >> amount (unsigned)
    #[must_use]
    pub fn shr_un(&mut self, value: SsaVarId, amount: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Shr {
            dest,
            value,
            amount,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = -operand
    #[must_use]
    pub fn neg(&mut self, operand: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Neg { dest, operand };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = ~operand
    #[must_use]
    pub fn not(&mut self, operand: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Not { dest, operand };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = src (copy)
    #[must_use]
    pub fn copy(&mut self, src: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Copy { dest, src };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = (left == right) ? 1 : 0
    #[must_use]
    pub fn ceq(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Ceq { dest, left, right };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = (left < right) ? 1 : 0 (signed)
    #[must_use]
    pub fn clt(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Clt {
            dest,
            left,
            right,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = (left < right) ? 1 : 0 (unsigned)
    #[must_use]
    pub fn clt_un(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Clt {
            dest,
            left,
            right,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = (left > right) ? 1 : 0 (signed)
    #[must_use]
    pub fn cgt(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Cgt {
            dest,
            left,
            right,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = (left > right) ? 1 : 0 (unsigned)
    #[must_use]
    pub fn cgt_un(&mut self, left: SsaVarId, right: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Cgt {
            dest,
            left,
            right,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = conv(operand, target) - signed conversion
    #[must_use]
    pub fn conv(&mut self, operand: SsaVarId, target: SsaType) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Conv {
            dest,
            operand,
            target,
            overflow_check: false,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = conv.un(operand, target) - unsigned conversion
    #[must_use]
    pub fn conv_un(&mut self, operand: SsaVarId, target: SsaType) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Conv {
            dest,
            operand,
            target,
            overflow_check: false,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = conv.ovf(operand, target) - with overflow checking
    #[must_use]
    pub fn conv_ovf(&mut self, operand: SsaVarId, target: SsaType) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Conv {
            dest,
            operand,
            target,
            overflow_check: true,
            unsigned: false,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: dest = conv.ovf.un(operand, target) - unsigned with overflow checking
    #[must_use]
    pub fn conv_ovf_un(&mut self, operand: SsaVarId, target: SsaType) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Conv {
            dest,
            operand,
            target,
            overflow_check: true,
            unsigned: true,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: jump target
    pub fn jump(&mut self, target: usize) {
        let op = SsaOp::Jump { target };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: branch condition, true_target, false_target
    pub fn branch(&mut self, condition: SsaVarId, true_target: usize, false_target: usize) {
        let op = SsaOp::Branch {
            condition,
            true_target,
            false_target,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: switch value, targets, default
    pub fn switch(&mut self, value: SsaVarId, targets: Vec<usize>, default: usize) {
        let op = SsaOp::Switch {
            value,
            targets,
            default,
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: return (void)
    pub fn ret(&mut self) {
        let op = SsaOp::Return { value: None };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: return value
    pub fn ret_val(&mut self, value: SsaVarId) {
        let op = SsaOp::Return { value: Some(value) };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: leave target (for exception handling)
    pub fn leave(&mut self, target: usize) {
        let op = SsaOp::Leave { target };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: throw exception
    pub fn throw(&mut self, exception: SsaVarId) {
        let op = SsaOp::Throw { exception };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: call method with return value
    ///
    /// Returns the variable holding the call result.
    #[must_use]
    pub fn call(&mut self, method: MethodRef, args: &[SsaVarId]) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::Call {
            dest: Some(dest),
            method,
            args: args.to_vec(),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: call method without return value (void)
    pub fn call_void(&mut self, method: MethodRef, args: &[SsaVarId]) {
        let op = SsaOp::Call {
            dest: None,
            method,
            args: args.to_vec(),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: callvirt method with return value
    ///
    /// Returns the variable holding the call result.
    #[must_use]
    pub fn callvirt(&mut self, method: MethodRef, args: &[SsaVarId]) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::CallVirt {
            dest: Some(dest),
            method,
            args: args.to_vec(),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: callvirt method without return value (void)
    pub fn callvirt_void(&mut self, method: MethodRef, args: &[SsaVarId]) {
        let op = SsaOp::CallVirt {
            dest: None,
            method,
            args: args.to_vec(),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds: newobj ctor(args)
    ///
    /// Returns the variable holding the new object reference.
    #[must_use]
    pub fn newobj(&mut self, ctor: MethodRef, args: &[SsaVarId]) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::NewObj {
            dest,
            ctor,
            args: args.to_vec(),
        };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds: array.Length
    ///
    /// Returns the variable holding the array length.
    #[must_use]
    pub fn array_length(&mut self, array: SsaVarId) -> SsaVarId {
        let dest = self.builder.alloc_stack_var();
        let op = SsaOp::ArrayLength { dest, array };
        self.block.add_instruction(SsaInstruction::synthetic(op));
        dest
    }

    /// Adds a phi node and returns the result variable.
    ///
    /// # Arguments
    ///
    /// * `operands` - Pairs of (predecessor_block_id, value) for each incoming edge
    #[must_use]
    pub fn phi(&mut self, operands: &[(usize, SsaVarId)]) -> SsaVarId {
        let result = self.builder.alloc_stack_var();
        // Variable indices are bounded by SSA instruction count which fits in u32
        #[allow(clippy::cast_possible_truncation)]
        let slot = result.index() as u32;
        let mut phi = PhiNode::new(result, VariableOrigin::Stack(slot));

        for &(pred, val) in operands {
            phi.add_operand(PhiOperand::new(val, pred));
        }

        self.block.add_phi(phi);
        result
    }

    /// Adds a raw SsaOp (for cases not covered by helpers).
    pub fn op(&mut self, op: SsaOp) {
        self.block.add_instruction(SsaInstruction::synthetic(op));
    }

    /// Adds a nop instruction.
    pub fn nop(&mut self) {
        self.block
            .add_instruction(SsaInstruction::synthetic(SsaOp::Nop));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            let (a, b) = (f.arg(0), f.arg(1));

            f.block(0, |blk| {
                let sum = blk.add(a, b);
                blk.ret_val(sum);
            });
        });

        assert_eq!(ssa.num_args(), 2);
        assert_eq!(ssa.num_locals(), 0);
        assert_eq!(ssa.block_count(), 1);

        let block = ssa.block(0).unwrap();
        assert_eq!(block.instruction_count(), 2); // add + ret
    }

    #[test]
    fn test_diamond_control_flow() {
        let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let cond = f.arg(0);
            let (mut v_then, mut v_else) = (SsaVarId::new(), SsaVarId::new());

            f.block(0, |b| {
                b.branch(cond, 1, 2);
            });

            f.block(1, |b| {
                v_then = b.const_i32(1);
                b.jump(3);
            });

            f.block(2, |b| {
                v_else = b.const_i32(0);
                b.jump(3);
            });

            f.block(3, |b| {
                let result = b.phi(&[(1, v_then), (2, v_else)]);
                b.ret_val(result);
            });
        });

        assert_eq!(ssa.block_count(), 4);

        // Check phi node exists in block 3
        let block3 = ssa.block(3).unwrap();
        assert_eq!(block3.phi_count(), 1);
    }

    #[test]
    fn test_jump_threading_pattern() {
        let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let cond = f.arg(0);

            f.block(0, |b| b.branch(cond, 1, 2));
            f.block(1, |b| b.jump(3));
            f.block(2, |b| b.jump(4));
            f.block(3, |b| b.ret());
            f.block(4, |b| b.ret());
        });

        assert_eq!(ssa.block_count(), 5);

        // Verify block 0 has branch
        let block0 = ssa.block(0).unwrap();
        assert!(matches!(block0.terminator_op(), Some(SsaOp::Branch { .. })));
    }

    #[test]
    fn test_constant_propagation_pattern() {
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(10);
                let v1 = b.const_i32(32);
                let sum = b.add(v0, v1);
                b.ret_val(sum);
            });
        });

        assert_eq!(ssa.block_count(), 1);

        let block = ssa.block(0).unwrap();
        assert_eq!(block.instruction_count(), 4); // const, const, add, ret
    }

    #[test]
    fn test_switch_pattern() {
        let ssa = SsaFunctionBuilder::new(1, 0).build_with(|f| {
            let val = f.arg(0);

            f.block(0, |b| b.switch(val, vec![1, 2], 3));
            f.block(1, |b| b.jump(4));
            f.block(2, |b| b.jump(4));
            f.block(3, |b| b.jump(4));
            f.block(4, |b| b.ret());
        });

        assert_eq!(ssa.block_count(), 5);

        // Verify block 0 has switch
        let block0 = ssa.block(0).unwrap();
        assert!(matches!(block0.terminator_op(), Some(SsaOp::Switch { .. })));
    }

    #[test]
    fn test_arithmetic_operations() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            let (a, b) = (f.arg(0), f.arg(1));

            f.block(0, |blk| {
                let sum = blk.add(a, b);
                let diff = blk.sub(a, b);
                let prod = blk.mul(sum, diff);
                let quot = blk.div(prod, a);
                let rem = blk.rem(quot, b);
                blk.ret_val(rem);
            });
        });

        let block = ssa.block(0).unwrap();
        assert_eq!(block.instruction_count(), 6); // 5 ops + ret
    }

    #[test]
    fn test_bitwise_operations() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            let (a, b) = (f.arg(0), f.arg(1));

            f.block(0, |blk| {
                let v_and = blk.and(a, b);
                let _v_or = blk.or(a, b);
                let _v_xor = blk.xor(a, b);
                let _v_shl = blk.shl(a, b);
                let _v_shr = blk.shr(a, b);
                let v_not = blk.not(v_and);
                blk.ret_val(v_not);
            });
        });

        let block = ssa.block(0).unwrap();
        assert_eq!(block.instruction_count(), 7);
    }

    #[test]
    fn test_comparisons() {
        let ssa = SsaFunctionBuilder::new(2, 0).build_with(|f| {
            let (a, b) = (f.arg(0), f.arg(1));

            f.block(0, |blk| {
                let eq = blk.ceq(a, b);
                let _lt = blk.clt(a, b);
                let _gt = blk.cgt(a, b);
                blk.ret_val(eq);
            });
        });

        let block = ssa.block(0).unwrap();
        assert_eq!(block.instruction_count(), 4);
    }

    #[test]
    fn test_locals() {
        let ssa = SsaFunctionBuilder::new(1, 2).build_with(|f| {
            let arg = f.arg(0);
            let _local0 = f.local(0);
            let _local1 = f.local(1);

            f.block(0, |blk| {
                blk.ret_val(arg);
            });
        });

        assert_eq!(ssa.num_locals(), 2);
    }
}
