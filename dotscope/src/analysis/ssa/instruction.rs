//! SSA-form instructions with explicit def/use information.
//!
//! This module provides the SSA representation of CIL instructions. Unlike
//! stack-based CIL where operands are implicit on the evaluation stack,
//! SSA instructions have explicit operands (uses) and results (defs).
//!
//! # Design
//!
//! Each SSA instruction contains:
//!
//! - **Original**: The original CIL instruction (for debugging/display)
//! - **Op**: The decomposed SSA operation in `result = op(operands)` form
//!
//! The `SsaOp` is the primary representation for analysis passes, while
//! the original CIL instruction is retained for debugging and to maintain
//! the connection to source locations.
//!
//! This explicit representation enables:
//! - Direct construction of def-use chains
//! - Easy identification of dead code (def with no uses)
//! - Straightforward data flow analysis
//! - Pattern matching on decomposed operations
//!
//! # Thread Safety
//!
//! All types in this module are `Send` and `Sync`.

use std::fmt;

use crate::{
    analysis::ssa::{SsaOp, SsaVarId},
    assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior},
};

/// An instruction in SSA form with explicit operands.
///
/// This contains both the original CIL instruction (for debugging) and a
/// decomposed SSA operation for analysis. The `SsaOp` provides a clean
/// `result = op(operands)` form suitable for optimization passes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::analysis::{SsaInstruction, SsaOp, SsaVarId};
/// use dotscope::assembly::Instruction;
///
/// // An add instruction: result = left + right
/// let left = SsaVarId::new();
/// let right = SsaVarId::new();
/// let result = SsaVarId::new();
/// let instr = SsaInstruction::new(
///     cil_instr,
///     SsaOp::Add { dest: result, left, right },
/// );
/// ```
#[derive(Debug, Clone)]
pub struct SsaInstruction {
    /// The original CIL instruction (retained for debugging and source mapping).
    original: Instruction,

    /// The decomposed SSA operation.
    ///
    /// This is the authoritative representation used by analysis passes. It provides
    /// a clean `result = op(operands)` form where all data dependencies are explicit.
    op: SsaOp,
}

impl SsaInstruction {
    /// Creates a new SSA instruction with a decomposed operation.
    ///
    /// # Arguments
    ///
    /// * `original` - The original CIL instruction
    /// * `op` - The decomposed SSA operation
    #[must_use]
    pub fn new(original: Instruction, op: SsaOp) -> Self {
        Self { original, op }
    }

    /// Creates an SSA instruction with only a decomposed operation (no CIL instruction).
    ///
    /// This is useful for synthetic instructions like phi nodes that don't
    /// correspond to any CIL instruction.
    #[must_use]
    pub fn synthetic(op: SsaOp) -> Self {
        // Create a dummy instruction for synthetic ops
        let dummy = Instruction {
            rva: 0,
            offset: 0,
            size: 0,
            opcode: 0,
            prefix: 0,
            mnemonic: "synthetic",
            category: InstructionCategory::Misc,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        };
        Self {
            original: dummy,
            op,
        }
    }

    /// Returns a reference to the original CIL instruction.
    #[must_use]
    pub const fn original(&self) -> &Instruction {
        &self.original
    }

    /// Returns the decomposed SSA operation.
    #[must_use]
    pub const fn op(&self) -> &SsaOp {
        &self.op
    }

    /// Returns a mutable reference to the decomposed SSA operation.
    pub fn op_mut(&mut self) -> &mut SsaOp {
        &mut self.op
    }

    /// Sets the decomposed SSA operation.
    pub fn set_op(&mut self, op: SsaOp) {
        self.op = op;
    }

    /// Returns `true` if this instruction is a terminator.
    ///
    /// Terminators are instructions that end a basic block (jumps, branches, returns, throws).
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        self.op.is_terminator()
    }

    /// Returns `true` if this instruction may throw an exception.
    #[must_use]
    pub fn may_throw(&self) -> bool {
        self.op.may_throw()
    }

    /// Returns `true` if this instruction is pure (has no side effects).
    ///
    /// Pure instructions can be eliminated if their result is unused.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        self.op.is_pure()
    }

    /// Returns the SSA variables used (read) by this instruction.
    #[must_use]
    pub fn uses(&self) -> Vec<SsaVarId> {
        self.op.uses()
    }

    /// Returns the SSA variable defined by this instruction, if any.
    #[must_use]
    pub fn def(&self) -> Option<SsaVarId> {
        self.op.dest()
    }

    /// Returns `true` if this instruction defines a value.
    #[must_use]
    pub fn has_def(&self) -> bool {
        self.op.dest().is_some()
    }

    /// Returns `true` if this instruction has no uses.
    #[must_use]
    pub fn has_no_uses(&self) -> bool {
        self.op.uses().is_empty()
    }

    /// Returns the instruction's mnemonic.
    #[must_use]
    pub fn mnemonic(&self) -> &'static str {
        self.original.mnemonic
    }

    /// Returns the instruction's RVA.
    #[must_use]
    pub const fn rva(&self) -> u64 {
        self.original.rva
    }

    /// Returns all SSA variables referenced by this instruction.
    ///
    /// This includes both uses and the def (if present).
    #[must_use]
    pub fn all_variables(&self) -> Vec<SsaVarId> {
        let mut vars = self.op.uses();
        if let Some(def) = self.op.dest() {
            vars.push(def);
        }
        vars
    }
}

impl fmt::Display for SsaInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_instruction(mnemonic: &'static str, pops: u8, pushes: u8) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x58, // add
            prefix: 0,
            mnemonic,
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops,
                pushes,
                net_effect: pushes as i8 - pops as i8,
            },
            branch_targets: vec![],
        }
    }

    #[test]
    fn test_ssa_instruction_new() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let cil = make_test_instruction("add", 2, 1);
        let op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let instr = SsaInstruction::new(cil, op);

        assert_eq!(instr.uses().len(), 2);
        assert_eq!(instr.def(), Some(v2));
        assert!(instr.has_def());
        assert!(!instr.has_no_uses());
    }

    #[test]
    fn test_ssa_instruction_uses() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let cil = make_test_instruction("add", 2, 1);
        let op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let instr = SsaInstruction::new(cil, op);

        let uses = instr.uses();
        assert_eq!(uses.len(), 2);
        assert!(uses.contains(&v0));
        assert!(uses.contains(&v1));
    }

    #[test]
    fn test_ssa_instruction_all_variables() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let cil = make_test_instruction("add", 2, 1);
        let op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let instr = SsaInstruction::new(cil, op);

        let vars = instr.all_variables();
        assert_eq!(vars.len(), 3);
        assert!(vars.contains(&v0));
        assert!(vars.contains(&v1));
        assert!(vars.contains(&v2));
    }

    #[test]
    fn test_ssa_instruction_all_variables_no_def() {
        let v = SsaVarId::new();
        let cil = make_test_instruction("pop", 1, 0);
        let op = SsaOp::Pop { value: v };
        let instr = SsaInstruction::new(cil, op);

        let vars = instr.all_variables();
        assert_eq!(vars.len(), 1);
        assert!(vars.contains(&v));
    }

    #[test]
    fn test_ssa_instruction_display() {
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let cil = make_test_instruction("add", 2, 1);
        let op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let instr = SsaInstruction::new(cil, op);

        assert_eq!(format!("{instr}"), "v2 = add v0, v1");
    }

    #[test]
    fn test_ssa_instruction_display_no_def() {
        let v = SsaVarId::from_index(5);
        let cil = make_test_instruction("pop", 1, 0);
        let op = SsaOp::Pop { value: v };
        let instr = SsaInstruction::new(cil, op);

        assert_eq!(format!("{instr}"), "pop v5");
    }

    #[test]
    fn test_ssa_instruction_display_const() {
        use crate::analysis::ssa::ConstValue;
        let v = SsaVarId::from_index(3);
        let cil = make_test_instruction("ldc.i4", 0, 1);
        let op = SsaOp::Const {
            dest: v,
            value: ConstValue::I32(42),
        };
        let instr = SsaInstruction::new(cil, op);

        assert_eq!(format!("{instr}"), "v3 = 42");
    }

    #[test]
    fn test_ssa_instruction_synthetic() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let instr = SsaInstruction::synthetic(op);

        assert_eq!(instr.uses().len(), 2);
        assert_eq!(instr.def(), Some(v2));
        assert_eq!(instr.mnemonic(), "synthetic");
    }

    #[test]
    fn test_ssa_instruction_set_op() {
        let v0 = SsaVarId::new();
        let v1 = SsaVarId::new();
        let v2 = SsaVarId::new();
        let v3 = SsaVarId::new();
        let cil = make_test_instruction("add", 2, 1);
        let op = SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
        };
        let mut instr = SsaInstruction::new(cil, op);

        // Replace with a different operation
        let new_op = SsaOp::Sub {
            dest: v3,
            left: v0,
            right: v1,
        };
        instr.set_op(new_op);

        assert_eq!(instr.def(), Some(v3));
        assert!(matches!(instr.op(), SsaOp::Sub { .. }));
    }
}
