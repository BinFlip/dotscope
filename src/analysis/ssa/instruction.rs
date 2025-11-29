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
//! - **Uses**: The SSA variables consumed by this instruction
//! - **Def**: The SSA variable produced by this instruction (if any)
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
/// use dotscope::analysis::ssa::{SsaInstruction, SsaOp, SsaVarId};
/// use dotscope::assembly::Instruction;
///
/// // An add instruction: v2 = v0 + v1
/// let instr = SsaInstruction::new(
///     cil_instr,
///     vec![SsaVarId::new(0), SsaVarId::new(1)],  // operands
///     Some(SsaVarId::new(2)),                     // result
/// );
///
/// // With decomposed operation
/// let instr = SsaInstruction::with_op(
///     cil_instr,
///     SsaOp::Add {
///         dest: SsaVarId::new(2),
///         left: SsaVarId::new(0),
///         right: SsaVarId::new(1),
///     },
/// );
/// ```
#[derive(Debug, Clone)]
pub struct SsaInstruction {
    /// The original CIL instruction (retained for debugging and source mapping).
    original: Instruction,

    /// The decomposed SSA operation.
    ///
    /// This is the primary representation used by analysis passes. It provides
    /// a clean `result = op(operands)` form where all data dependencies are explicit.
    op: Option<SsaOp>,

    /// SSA variables read by this instruction.
    ///
    /// The order matches the stack order: first element was deepest on stack.
    /// For example, `sub` pops two values; `uses[0]` was pushed first (deeper),
    /// `uses[1]` was pushed second (top of stack).
    ///
    /// Note: When `op` is set, uses can also be derived from `op.uses()`.
    /// This field is retained for backward compatibility and performance.
    uses: Vec<SsaVarId>,

    /// SSA variable defined by this instruction (if any).
    ///
    /// Most instructions that push a value onto the stack will have a def.
    /// Instructions like `pop`, `stloc`, `starg`, branches, and `ret` have no def.
    ///
    /// Note: When `op` is set, def can also be derived from `op.dest()`.
    /// This field is retained for backward compatibility and performance.
    def: Option<SsaVarId>,
}

impl SsaInstruction {
    /// Creates a new SSA instruction (legacy constructor).
    ///
    /// This constructor does not set the decomposed operation. Prefer using
    /// `with_op` when constructing new SSA instructions.
    ///
    /// # Arguments
    ///
    /// * `original` - The original CIL instruction
    /// * `uses` - SSA variables consumed by this instruction
    /// * `def` - SSA variable produced by this instruction (if any)
    #[must_use]
    pub fn new(original: Instruction, uses: Vec<SsaVarId>, def: Option<SsaVarId>) -> Self {
        Self {
            original,
            op: None,
            uses,
            def,
        }
    }

    /// Creates a new SSA instruction with a decomposed operation.
    ///
    /// This is the preferred constructor for new code. The uses and def
    /// are extracted from the operation.
    ///
    /// # Arguments
    ///
    /// * `original` - The original CIL instruction
    /// * `op` - The decomposed SSA operation
    #[must_use]
    pub fn with_op(original: Instruction, op: SsaOp) -> Self {
        let uses = op.uses();
        let def = op.dest();
        Self {
            original,
            op: Some(op),
            uses,
            def,
        }
    }

    /// Creates an SSA instruction with no operands and no result.
    ///
    /// Useful for instructions like `nop`, `break`, or unconditional branches.
    #[must_use]
    pub fn no_operands(original: Instruction) -> Self {
        Self {
            original,
            op: None,
            uses: Vec::new(),
            def: None,
        }
    }

    /// Creates an SSA instruction with only a decomposed operation (no CIL instruction).
    ///
    /// This is useful for synthetic instructions like phi nodes that don't
    /// correspond to any CIL instruction.
    #[must_use]
    pub fn synthetic(op: SsaOp) -> Self {
        let uses = op.uses();
        let def = op.dest();
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
            op: Some(op),
            uses,
            def,
        }
    }

    /// Returns a reference to the original CIL instruction.
    #[must_use]
    pub const fn original(&self) -> &Instruction {
        &self.original
    }

    /// Returns the decomposed SSA operation, if available.
    ///
    /// The operation may be `None` if:
    /// - The instruction was created with the legacy `new()` constructor
    /// - The instruction hasn't been through the decomposition pass yet
    #[must_use]
    pub const fn op(&self) -> Option<&SsaOp> {
        self.op.as_ref()
    }

    /// Returns a mutable reference to the decomposed SSA operation.
    pub fn op_mut(&mut self) -> Option<&mut SsaOp> {
        self.op.as_mut()
    }

    /// Sets the decomposed SSA operation.
    ///
    /// This also updates the `uses` and `def` fields to match the operation.
    pub fn set_op(&mut self, op: SsaOp) {
        self.uses = op.uses();
        self.def = op.dest();
        self.op = Some(op);
    }

    /// Returns `true` if this instruction has a decomposed operation.
    #[must_use]
    pub const fn has_op(&self) -> bool {
        self.op.is_some()
    }

    /// Returns `true` if this instruction is a terminator.
    ///
    /// Terminators are instructions that end a basic block (jumps, branches, returns, throws).
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        if let Some(op) = &self.op {
            op.is_terminator()
        } else {
            // Fall back to checking the CIL instruction
            matches!(
                self.original.flow_type,
                FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Return
            )
        }
    }

    /// Returns `true` if this instruction may throw an exception.
    #[must_use]
    pub fn may_throw(&self) -> bool {
        self.op.as_ref().is_some_and(SsaOp::may_throw)
    }

    /// Returns `true` if this instruction is pure (has no side effects).
    ///
    /// Pure instructions can be eliminated if their result is unused.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        self.op.as_ref().is_some_and(SsaOp::is_pure)
    }

    /// Returns the SSA variables used (read) by this instruction.
    #[must_use]
    pub fn uses(&self) -> &[SsaVarId] {
        &self.uses
    }

    /// Returns a mutable reference to the uses.
    pub fn uses_mut(&mut self) -> &mut Vec<SsaVarId> {
        &mut self.uses
    }

    /// Returns the SSA variable defined by this instruction, if any.
    #[must_use]
    pub const fn def(&self) -> Option<SsaVarId> {
        self.def
    }

    /// Sets the definition for this instruction.
    pub fn set_def(&mut self, def: Option<SsaVarId>) {
        self.def = def;
    }

    /// Returns `true` if this instruction defines a value.
    #[must_use]
    pub const fn has_def(&self) -> bool {
        self.def.is_some()
    }

    /// Returns `true` if this instruction has no uses.
    #[must_use]
    pub fn has_no_uses(&self) -> bool {
        self.uses.is_empty()
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

    /// Adds a use to this instruction.
    pub fn add_use(&mut self, var: SsaVarId) {
        self.uses.push(var);
    }

    /// Returns an iterator over all SSA variables referenced by this instruction.
    ///
    /// This includes both uses and the def (if present).
    pub fn all_variables(&self) -> impl Iterator<Item = SsaVarId> + '_ {
        self.uses.iter().copied().chain(self.def)
    }
}

impl fmt::Display for SsaInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // If we have a decomposed operation, prefer to display that
        if let Some(op) = &self.op {
            return write!(f, "{op}");
        }

        // Legacy format: [def =] mnemonic [uses]
        if let Some(def) = self.def {
            write!(f, "{def} = ")?;
        }

        write!(f, "{}", self.original.mnemonic)?;

        if !self.uses.is_empty() {
            write!(f, " ")?;
            for (i, var) in self.uses.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{var}")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{FlowType, InstructionCategory, Operand, StackBehavior};

    fn make_test_instruction(mnemonic: &'static str, pops: u8, pushes: u8) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x00,
            prefix: 0,
            mnemonic,
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops,
                pushes,
                net_effect: i8::try_from(i16::from(pushes) - i16::from(pops)).unwrap_or(0),
            },
            branch_targets: vec![],
        }
    }

    #[test]
    fn test_ssa_instruction_creation() {
        let cil = make_test_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(0), SsaVarId::new(1)],
            Some(SsaVarId::new(2)),
        );

        assert_eq!(instr.mnemonic(), "add");
        assert_eq!(instr.uses().len(), 2);
        assert_eq!(instr.uses()[0], SsaVarId::new(0));
        assert_eq!(instr.uses()[1], SsaVarId::new(1));
        assert_eq!(instr.def(), Some(SsaVarId::new(2)));
        assert!(instr.has_def());
    }

    #[test]
    fn test_ssa_instruction_no_operands() {
        let cil = make_test_instruction("nop", 0, 0);
        let instr = SsaInstruction::no_operands(cil);

        assert!(instr.has_no_uses());
        assert!(!instr.has_def());
        assert_eq!(instr.def(), None);
    }

    #[test]
    fn test_ssa_instruction_no_def() {
        let cil = make_test_instruction("pop", 1, 0);
        let instr = SsaInstruction::new(cil, vec![SsaVarId::new(5)], None);

        assert_eq!(instr.uses().len(), 1);
        assert!(!instr.has_def());
    }

    #[test]
    fn test_ssa_instruction_add_use() {
        let cil = make_test_instruction("add", 2, 1);
        let mut instr = SsaInstruction::new(cil, vec![], Some(SsaVarId::new(2)));

        instr.add_use(SsaVarId::new(0));
        instr.add_use(SsaVarId::new(1));

        assert_eq!(instr.uses().len(), 2);
    }

    #[test]
    fn test_ssa_instruction_set_def() {
        let cil = make_test_instruction("ldloc.0", 0, 1);
        let mut instr = SsaInstruction::no_operands(cil);

        assert!(!instr.has_def());

        instr.set_def(Some(SsaVarId::new(10)));
        assert!(instr.has_def());
        assert_eq!(instr.def(), Some(SsaVarId::new(10)));
    }

    #[test]
    fn test_ssa_instruction_all_variables() {
        let cil = make_test_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(0), SsaVarId::new(1)],
            Some(SsaVarId::new(2)),
        );

        let vars: Vec<_> = instr.all_variables().collect();
        assert_eq!(vars.len(), 3);
        assert!(vars.contains(&SsaVarId::new(0)));
        assert!(vars.contains(&SsaVarId::new(1)));
        assert!(vars.contains(&SsaVarId::new(2)));
    }

    #[test]
    fn test_ssa_instruction_all_variables_no_def() {
        let cil = make_test_instruction("pop", 1, 0);
        let instr = SsaInstruction::new(cil, vec![SsaVarId::new(5)], None);

        let vars: Vec<_> = instr.all_variables().collect();
        assert_eq!(vars.len(), 1);
        assert!(vars.contains(&SsaVarId::new(5)));
    }

    #[test]
    fn test_ssa_instruction_display_with_def() {
        let cil = make_test_instruction("add", 2, 1);
        let instr = SsaInstruction::new(
            cil,
            vec![SsaVarId::new(0), SsaVarId::new(1)],
            Some(SsaVarId::new(2)),
        );

        assert_eq!(format!("{instr}"), "v2 = add v0, v1");
    }

    #[test]
    fn test_ssa_instruction_display_no_def() {
        let cil = make_test_instruction("pop", 1, 0);
        let instr = SsaInstruction::new(cil, vec![SsaVarId::new(5)], None);

        assert_eq!(format!("{instr}"), "pop v5");
    }

    #[test]
    fn test_ssa_instruction_display_no_operands() {
        let cil = make_test_instruction("nop", 0, 0);
        let instr = SsaInstruction::no_operands(cil);

        assert_eq!(format!("{instr}"), "nop");
    }

    #[test]
    fn test_ssa_instruction_display_def_only() {
        let cil = make_test_instruction("ldc.i4.0", 0, 1);
        let instr = SsaInstruction::new(cil, vec![], Some(SsaVarId::new(3)));

        assert_eq!(format!("{instr}"), "v3 = ldc.i4.0");
    }

    #[test]
    fn test_ssa_instruction_rva() {
        let mut cil = make_test_instruction("nop", 0, 0);
        cil.rva = 0x2000;
        let instr = SsaInstruction::no_operands(cil);

        assert_eq!(instr.rva(), 0x2000);
    }
}
