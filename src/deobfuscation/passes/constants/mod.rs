//! Constant propagation and folding pass.
//!
//! This pass uses the Sparse Conditional Constant Propagation (SCCP) analysis
//! from the dataflow framework, then applies additional optimizations including:
//!
//! - **Constant folding**: Evaluate operations with constant operands at compile time
//! - **Identity simplification**: Recognize `x + 0 = x`, `x * 1 = x`, etc.
//! - **Absorbing elements**: Recognize `x * 0 = 0`, `x & 0 = 0`, etc.
//! - **Branch simplification**: Convert conditional branches to jumps when condition is known
//! - **Switch simplification**: Convert switches to jumps when value is known
//! - **Conversion folding**: Fold type conversions with constant operands
//! - **Overflow-checked operations**: Fold when result doesn't overflow
//!
//! # Example
//!
//! Before:
//! ```text
//! v0 = 5
//! v1 = 3
//! v2 = add v0, v1
//! v3 = mul v2, 2
//! v4 = add v3, 0   // identity
//! v5 = mul v4, 0   // absorbing
//! ```
//!
//! After:
//! ```text
//! v0 = 5
//! v1 = 3
//! v2 = 8
//! v3 = 16
//! v4 = 16          // identity simplified
//! v5 = 0           // absorbing element
//! ```

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::{
        simplify_op, CmpKind, ConstValue, ConstantPropagation, SccpResult, SimplifyResult, SsaCfg,
        SsaFunction, SsaOp, SsaType, SsaVarId,
    },
    deobfuscation::{
        changes::{EventKind, EventLog},
        context::AnalysisContext,
        pass::SsaPass,
    },
    metadata::token::Token,
    CilObject, Result,
};

/// Maximum number of iterations for the fixed-point optimization loop.
/// This handles cases where one optimization enables another.
const MAX_ITERATIONS: usize = 10;

/// Result of checking an algebraic identity.
///
/// Either the operation simplifies to a constant value (absorbing elements)
/// or to a copy of another variable (identity operations).
#[derive(Debug, Clone)]
enum AlgebraicResult {
    /// Operation result is a constant value (e.g., x * 0 = 0)
    Constant { dest: SsaVarId, value: ConstValue },
    /// Operation result is a copy of another variable (e.g., x + 0 = x)
    Copy { dest: SsaVarId, src: SsaVarId },
}

/// Information about a conversion operation for redundancy analysis.
#[derive(Debug, Clone)]
struct ConvInfo {
    /// The source operand of the conversion.
    operand: SsaVarId,
    /// The target type of the conversion.
    target: SsaType,
    /// Whether this is an overflow-checked conversion.
    overflow_check: bool,
    /// Whether the source is treated as unsigned.
    unsigned: bool,
    /// Block index where this conversion is defined.
    block_idx: usize,
    /// Instruction index within the block.
    instr_idx: usize,
}

/// Transformation to apply for redundant conversion elimination.
#[derive(Debug)]
enum ConvTransform {
    /// Replace the conversion's operand with a different source.
    /// Used for duplicate conversions and widening chains.
    ReplaceOperand {
        block_idx: usize,
        instr_idx: usize,
        dest: SsaVarId,
        new_operand: SsaVarId,
        target: SsaType,
        unsigned: bool,
        reason: &'static str,
    },
    /// Replace the conversion with a simple copy.
    /// Used for unnecessary conversions where types match.
    ReplaceWithCopy {
        block_idx: usize,
        instr_idx: usize,
        dest: SsaVarId,
        src: SsaVarId,
        reason: &'static str,
    },
}

/// Constant propagation and folding pass.
///
/// This pass combines the SCCP analysis with additional optimizations
/// for identity operations, absorbing elements, and type conversions.
pub struct ConstantPropagationPass;

impl Default for ConstantPropagationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantPropagationPass {
    /// Creates a new constant propagation pass.
    ///
    /// # Returns
    ///
    /// A new `ConstantPropagationPass` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Runs the constant propagation pass on an SSA function.
    ///
    /// This uses the existing SCCP analysis and applies additional optimizations.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze and transform.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    ///
    /// # Returns
    ///
    /// A map from SSA variables to their constant values.
    fn run_constant_propagation(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
    ) -> HashMap<SsaVarId, ConstValue> {
        let block_count = ssa.block_count();
        if block_count == 0 {
            return HashMap::new();
        }

        // Recompute use tracking before SCCP analysis.
        // Use information may be stale after SSA transformations (e.g., CFF reconstruction),
        // which can cause SCCP to miss re-evaluating instructions when phi values change.
        ssa.recompute_uses();

        // Build CFG from SSA and run SCCP analysis using the dataflow framework
        let cfg = SsaCfg::from_ssa(ssa);
        let mut sccp = ConstantPropagation::new();
        let sccp_result = sccp.analyze(ssa, &cfg);

        // Collect constants from SCCP result
        let mut constants: HashMap<SsaVarId, ConstValue> = sccp_result
            .constants()
            .map(|(var, c)| (var, c.clone()))
            .collect();

        // Apply additional optimizations iteratively
        for _ in 0..MAX_ITERATIONS {
            let prev_count = constants.len();

            // Run identity and absorbing element optimizations
            Self::optimize_algebraic_identities(ssa, &mut constants, method_token, changes);

            // Run involutory operation simplification (--x=x, ~~x=x)
            Self::simplify_involutory_ops(ssa, method_token, changes);

            // Run conversion folding
            Self::fold_conversions(ssa, &mut constants, method_token, changes);

            // Eliminate redundant conversions
            Self::eliminate_redundant_conversions(ssa, method_token, changes);

            // Run overflow-checked operation folding
            Self::fold_overflow_checked_ops(ssa, &mut constants, method_token, changes);

            // If no new constants discovered, we're done
            if constants.len() == prev_count {
                break;
            }
        }

        // Apply all constant folding transformations
        Self::apply_constant_folding(ssa, &constants, &sccp_result, method_token, changes);

        // Apply control flow simplifications
        Self::simplify_control_flow(ssa, &constants, &sccp_result, method_token, changes);

        constants
    }

    /// Optimizes algebraic identity operations and absorbing elements.
    ///
    /// Identity operations: `x + 0 = x`, `x * 1 = x`, `x - 0 = x`, etc.
    /// Absorbing elements: `x * 0 = 0`, `x & 0 = 0`, `x | -1 = -1`, etc.
    ///
    /// This handles both cases:
    /// - When both operands are constants → replace with constant
    /// - When one operand is identity element → replace with copy of the other operand
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `constants` - Map of known constants (updated with new discoveries).
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    fn optimize_algebraic_identities(
        ssa: &mut SsaFunction,
        constants: &mut HashMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let mut transformations: Vec<(usize, usize, AlgebraicResult)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let op = instr.op();
                if let Some(result) = Self::check_algebraic_identity(op, constants) {
                    transformations.push((block_idx, instr_idx, result));
                }
            }
        }

        // Apply the transformations
        for (block_idx, instr_idx, result) in transformations {
            if let Some(block) = ssa.block_mut(block_idx) {
                let instr = &mut block.instructions_mut()[instr_idx];
                let old_op_str = format!("{}", instr.op());

                match result {
                    AlgebraicResult::Constant { dest, value } => {
                        constants.insert(dest, value.clone());
                        instr.set_op(SsaOp::Const {
                            dest,
                            value: value.clone(),
                        });
                        changes
                            .record(EventKind::ConstantFolded)
                            .at(method_token, instr_idx)
                            .message(format!("{} → {} (algebraic)", old_op_str, value));
                    }
                    AlgebraicResult::Copy { dest, src } => {
                        // If src is a known constant, propagate it
                        if let Some(value) = constants.get(&src).cloned() {
                            constants.insert(dest, value.clone());
                            instr.set_op(SsaOp::Const {
                                dest,
                                value: value.clone(),
                            });
                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{} → {} (identity)", old_op_str, value));
                        } else {
                            // Replace with copy - copy propagation will handle this
                            instr.set_op(SsaOp::Copy { dest, src });
                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{} → copy {} (identity)", old_op_str, src));
                        }
                    }
                }
            }
        }
    }

    /// Checks if an operation can be simplified via algebraic identities.
    ///
    /// Uses the shared `simplify_op` function for common patterns.
    fn check_algebraic_identity(
        op: &SsaOp,
        constants: &HashMap<SsaVarId, ConstValue>,
    ) -> Option<AlgebraicResult> {
        let dest = op.dest()?;
        match simplify_op(op, constants) {
            SimplifyResult::Constant(value) => Some(AlgebraicResult::Constant { dest, value }),
            SimplifyResult::Copy(src) => Some(AlgebraicResult::Copy { dest, src }),
            SimplifyResult::None => None,
        }
    }

    /// Folds type conversion operations with constant operands.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `constants` - Map of known constants (updated with new discoveries).
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_lossless)]
    #[allow(clippy::cast_possible_wrap)]
    fn fold_conversions(
        ssa: &mut SsaFunction,
        constants: &mut HashMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::Conv {
                    dest,
                    operand,
                    target,
                    overflow_check,
                    unsigned,
                } = instr.op()
                {
                    if let Some(operand_val) = constants.get(operand) {
                        let result = if *overflow_check {
                            operand_val.convert_to_checked(target, *unsigned)
                        } else {
                            operand_val.convert_to(target, *unsigned)
                        };
                        if let Some(result) = result {
                            new_constants.push((*dest, result, block_idx, instr_idx));
                        }
                    }
                }
            }
        }

        // Apply the transformations
        for (dest, value, block_idx, instr_idx) in new_constants {
            constants.insert(dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                let instr = &mut block.instructions_mut()[instr_idx];
                let old_op_str = format!("{}", instr.op());

                instr.set_op(SsaOp::Const {
                    dest,
                    value: value.clone(),
                });

                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, instr_idx)
                    .message(format!("{} → {} (conv)", old_op_str, value));
            }
        }
    }

    /// Eliminates redundant type conversions.
    ///
    /// This handles three patterns of redundant conversions:
    ///
    /// 1. **Duplicate conversions**: `conv.i4(conv.i4(x))` → `conv.i4(x)`
    ///    When the same conversion is applied twice, the outer one is redundant.
    ///
    /// 2. **Unnecessary conversions**: `conv.i4(x)` where x is already i32 → `x`
    ///    When converting to a type the value already has.
    ///
    /// 3. **Widening chain simplification**: `conv.i8(conv.i4(x))` → `conv.i8(x)`
    ///    For unsigned widening conversions, the intermediate conversion can be skipped.
    ///    Only applied when the intermediate conversion is lossless and the unsigned flag
    ///    is consistent.
    ///
    /// Note: Narrowing conversions and lossy float conversions (`conv.r8(conv.r4(x))`)
    /// are NOT optimized as they may change semantics.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze and transform.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    fn eliminate_redundant_conversions(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        // Build a map of variable definitions: var_id -> (block_idx, instr_idx, SsaOp)
        // We need the full op to analyze Conv chains
        let mut definitions: HashMap<SsaVarId, ConvInfo> = HashMap::new();

        // First pass: collect all Conv definitions and variable types
        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::Conv {
                    dest,
                    operand,
                    target,
                    overflow_check,
                    unsigned,
                } = instr.op()
                {
                    definitions.insert(
                        *dest,
                        ConvInfo {
                            operand: *operand,
                            target: target.clone(),
                            overflow_check: *overflow_check,
                            unsigned: *unsigned,
                            block_idx,
                            instr_idx,
                        },
                    );
                }
            }
        }

        // Second pass: find redundant conversions
        let mut transformations: Vec<ConvTransform> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::Conv {
                    dest,
                    operand,
                    target,
                    overflow_check,
                    unsigned,
                } = instr.op()
                {
                    // Skip overflow-checked conversions - these have different semantics
                    if *overflow_check {
                        continue;
                    }

                    // Check if operand was also produced by a conversion
                    if let Some(inner_conv) = definitions.get(operand) {
                        // Skip if inner has overflow check - may throw
                        if inner_conv.overflow_check {
                            continue;
                        }

                        // Pattern 1: Duplicate conversion - conv.T(conv.T(x)) → conv.T(x)
                        if inner_conv.target == *target && inner_conv.unsigned == *unsigned {
                            transformations.push(ConvTransform::ReplaceOperand {
                                block_idx,
                                instr_idx,
                                dest: *dest,
                                new_operand: inner_conv.operand,
                                target: target.clone(),
                                unsigned: *unsigned,
                                reason: "duplicate conversion",
                            });
                            continue;
                        }

                        // Pattern 3: Widening chain - conv.T2(conv.T1(x)) → conv.T2(x)
                        // Only when BOTH conversions are widening and semantics are preserved.
                        // If the inner conversion narrows (truncates), we must keep it.
                        //
                        // Example that must NOT be optimized:
                        //   conv.i4(conv.u1(x)) where x is I32
                        //   conv.u1 truncates to 8 bits, conv.i4 widens back
                        //   Skipping conv.u1 would lose the truncation!
                        //
                        // We check the SOURCE type of the inner conversion to determine
                        // if the inner conversion is narrowing.
                        if let Some(source_var) = ssa.variable(inner_conv.operand) {
                            let source_type = source_var.var_type();
                            if Self::is_safe_widening_chain(
                                source_type,
                                &inner_conv.target,
                                target,
                                inner_conv.unsigned,
                                *unsigned,
                            ) {
                                transformations.push(ConvTransform::ReplaceOperand {
                                    block_idx,
                                    instr_idx,
                                    dest: *dest,
                                    new_operand: inner_conv.operand,
                                    target: target.clone(),
                                    unsigned: *unsigned,
                                    reason: "widening chain",
                                });
                                continue;
                            }
                        }
                    }

                    // Pattern 2: Unnecessary conversion - check if operand already has target type
                    if let Some(var) = ssa.variable(*operand) {
                        if Self::types_match(var.var_type(), target) {
                            transformations.push(ConvTransform::ReplaceWithCopy {
                                block_idx,
                                instr_idx,
                                dest: *dest,
                                src: *operand,
                                reason: "unnecessary conversion",
                            });
                        }
                    }
                }
            }
        }

        // Apply transformations
        for transform in transformations {
            match transform {
                ConvTransform::ReplaceOperand {
                    block_idx,
                    instr_idx,
                    dest,
                    new_operand,
                    target,
                    unsigned,
                    reason,
                } => {
                    if let Some(block) = ssa.block_mut(block_idx) {
                        let instr = &mut block.instructions_mut()[instr_idx];
                        let old_op_str = format!("{}", instr.op());

                        instr.set_op(SsaOp::Conv {
                            dest,
                            operand: new_operand,
                            target: target.clone(),
                            overflow_check: false,
                            unsigned,
                        });

                        changes
                            .record(EventKind::ConstantFolded)
                            .at(method_token, instr_idx)
                            .message(format!(
                                "{} → conv.{} {} ({})",
                                old_op_str, target, new_operand, reason
                            ));
                    }
                }
                ConvTransform::ReplaceWithCopy {
                    block_idx,
                    instr_idx,
                    dest,
                    src,
                    reason,
                } => {
                    if let Some(block) = ssa.block_mut(block_idx) {
                        let instr = &mut block.instructions_mut()[instr_idx];
                        let old_op_str = format!("{}", instr.op());

                        instr.set_op(SsaOp::Copy { dest, src });

                        changes
                            .record(EventKind::ConstantFolded)
                            .at(method_token, instr_idx)
                            .message(format!("{} → copy {} ({})", old_op_str, src, reason));
                    }
                }
            }
        }
    }

    /// Checks if two types match for the purpose of conversion elimination.
    ///
    /// This is conservative - types must match exactly or be equivalent on the stack.
    fn types_match(var_type: &SsaType, target: &SsaType) -> bool {
        if var_type == target {
            return true;
        }

        // Check stack type equivalence - CIL promotes small integers to I32
        // So if converting to I32 and var is already I8/I16/U8/U16, it's unnecessary
        matches!(
            (var_type, target),
            // Small integers (I8, U8, I16, U16, Bool, Char) are already I32 on the stack
            // U32 is treated as I32 on stack (bidirectional)
            // I64 and U64 are interchangeable for bit patterns
            // Native int types are interchangeable
            (
                SsaType::I8
                    | SsaType::U8
                    | SsaType::I16
                    | SsaType::U16
                    | SsaType::Bool
                    | SsaType::Char
                    | SsaType::U32,
                SsaType::I32
            ) | (SsaType::I32, SsaType::U32)
                | (SsaType::U64, SsaType::I64)
                | (SsaType::I64, SsaType::U64)
                | (SsaType::NativeInt, SsaType::NativeUInt)
                | (SsaType::NativeUInt, SsaType::NativeInt)
        )
    }

    /// Determines if a widening conversion chain can be safely simplified.
    ///
    /// For `conv.T2(conv.T1(x))` to become `conv.T2(x)`:
    /// - The inner conversion (source → T1) must NOT be narrowing (truncating)
    /// - T1 must be smaller than or equal to T2 (outer must be widening)
    /// - The signedness must be consistent or the conversion must be truly lossless
    /// - Float conversions are NOT simplified (conv.r8(conv.r4(x)) loses precision)
    fn is_safe_widening_chain(
        source_type: &SsaType,
        inner_target: &SsaType,
        outer_target: &SsaType,
        inner_unsigned: bool,
        outer_unsigned: bool,
    ) -> bool {
        // Don't optimize float conversions - they can lose precision
        if source_type.is_float() || inner_target.is_float() || outer_target.is_float() {
            return false;
        }

        // Get sizes of all types
        let source_size = source_type.size_bytes();
        let inner_size = inner_target.size_bytes();
        let outer_size = outer_target.size_bytes();

        // All must have known sizes
        let (Some(source_size), Some(inner_size), Some(outer_size)) =
            (source_size, inner_size, outer_size)
        else {
            return false; // Native types - be conservative
        };

        // Inner conversion must NOT be narrowing (source must be <= inner target)
        // If source > inner_target, the inner conversion truncates and we can't skip it
        if source_size > inner_size {
            return false;
        }

        // Outer conversion must be widening (inner smaller than outer)
        if inner_size >= outer_size {
            return false;
        }

        // For widening conversions, signedness matters:
        // - unsigned widening is always safe (zero extension)
        // - signed to signed widening is safe (sign extension)
        // - signed to unsigned widening can change the value (e.g., -1 as i8 -> u32 = 255, not 0xFFFFFFFF)

        // If both have the same unsigned flag, it's safe
        if inner_unsigned == outer_unsigned {
            return true;
        }

        // If inner is unsigned and outer is signed, it's safe (zero-extend then reinterpret)
        // e.g., conv.i8(conv.u4(x)) - zero extends then treats as signed, same as conv.i8.u(x)
        if inner_unsigned && !outer_unsigned {
            return true;
        }

        // If inner is signed and outer is unsigned:
        // conv.u8(conv.i4(x)) vs conv.u8(x)
        // If x is negative, conv.i4 sign-extends, then conv.u8 reinterprets
        // But conv.u8(x) would just zero-extend or truncate
        // This can differ, so don't optimize
        false
    }

    /// Folds overflow-checked arithmetic operations when result doesn't overflow.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `constants` - Map of known constants (updated with new discoveries).
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    #[allow(clippy::cast_possible_truncation)]
    fn fold_overflow_checked_ops(
        ssa: &mut SsaFunction,
        constants: &mut HashMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((dest, value)) = Self::check_overflow_op(instr.op(), constants) {
                    new_constants.push((dest, value, block_idx, instr_idx));
                }
            }
        }

        // Apply the transformations
        for (dest, value, block_idx, instr_idx) in new_constants {
            constants.insert(dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                let instr = &mut block.instructions_mut()[instr_idx];
                let old_op_str = format!("{}", instr.op());

                instr.set_op(SsaOp::Const {
                    dest,
                    value: value.clone(),
                });

                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, instr_idx)
                    .message(format!("{} → {} (ovf)", old_op_str, value));
            }
        }
    }

    /// Checks if an overflow-checked operation can be folded.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)] // Intentional bit reinterpretation for overflow checking
    fn check_overflow_op(
        op: &SsaOp,
        constants: &HashMap<SsaVarId, ConstValue>,
    ) -> Option<(SsaVarId, ConstValue)> {
        match op {
            SsaOp::AddOvf {
                dest,
                left,
                right,
                unsigned,
            } => {
                let l = constants.get(left)?;
                let r = constants.get(right)?;
                let (lv, rv) = (l.as_i64()?, r.as_i64()?);

                if *unsigned {
                    let (result, overflow) = (lv as u64).overflowing_add(rv as u64);
                    if !overflow {
                        return Some((*dest, ConstValue::I64(result as i64)));
                    }
                } else {
                    let (_, overflow) = lv.overflowing_add(rv);
                    if !overflow {
                        return Some((*dest, l.add(r)?));
                    }
                }
                None
            }

            SsaOp::SubOvf {
                dest,
                left,
                right,
                unsigned,
            } => {
                let l = constants.get(left)?;
                let r = constants.get(right)?;
                let (lv, rv) = (l.as_i64()?, r.as_i64()?);

                if *unsigned {
                    let (result, overflow) = (lv as u64).overflowing_sub(rv as u64);
                    if !overflow {
                        return Some((*dest, ConstValue::I64(result as i64)));
                    }
                } else {
                    let (_, overflow) = lv.overflowing_sub(rv);
                    if !overflow {
                        return Some((*dest, l.sub(r)?));
                    }
                }
                None
            }

            SsaOp::MulOvf {
                dest,
                left,
                right,
                unsigned,
            } => {
                let l = constants.get(left)?;
                let r = constants.get(right)?;

                // Special case: x * 0 = 0, even with overflow check
                if l.is_zero() {
                    return Some((*dest, l.clone()));
                }
                if r.is_zero() {
                    return Some((*dest, r.clone()));
                }

                let (lv, rv) = (l.as_i64()?, r.as_i64()?);

                if *unsigned {
                    let (result, overflow) = (lv as u64).overflowing_mul(rv as u64);
                    if !overflow {
                        return Some((*dest, ConstValue::I64(result as i64)));
                    }
                } else {
                    let (_, overflow) = lv.overflowing_mul(rv);
                    if !overflow {
                        return Some((*dest, l.mul(r)?));
                    }
                }
                None
            }

            _ => None,
        }
    }

    /// Applies constant folding transformations to the SSA function.
    ///
    /// This replaces non-constant operations with constant loads when
    /// the result is known to be constant.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to transform.
    /// * `constants` - Map of known constants.
    /// * `sccp_result` - The SCCP analysis results.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    #[allow(clippy::cast_possible_truncation)]
    fn apply_constant_folding(
        ssa: &mut SsaFunction,
        constants: &HashMap<SsaVarId, ConstValue>,
        sccp_result: &SccpResult,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        for block_idx in 0..ssa.block_count() {
            if !sccp_result.is_block_executable(block_idx) {
                continue;
            }

            if let Some(block) = ssa.block_mut(block_idx) {
                for (instr_idx, instr) in block.instructions_mut().iter_mut().enumerate() {
                    let op = instr.op();
                    // Skip if already a constant
                    if matches!(op, SsaOp::Const { .. }) {
                        continue;
                    }

                    // Check if this instruction's result is a known constant
                    if let Some(dest) = op.dest() {
                        if let Some(value) = constants.get(&dest) {
                            let old_op_str = format!("{op}");

                            instr.set_op(SsaOp::Const {
                                dest,
                                value: value.clone(),
                            });

                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{} → {}", old_op_str, value));
                        }
                    }
                }
            }
        }
    }

    /// Simplifies involutory operations (operations that are their own inverse).
    ///
    /// Handles patterns like:
    /// - `--x = x` (double negation)
    /// - `~~x = x` (double bitwise not)
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    fn simplify_involutory_ops(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) {
        // First, build a map of variable definitions: var_id -> (block_idx, instr_idx)
        let mut definitions: HashMap<SsaVarId, (usize, usize)> = HashMap::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if let Some(dest) = instr.op().dest() {
                definitions.insert(dest, (block_idx, instr_idx));
            }
        }

        // Now find involutory patterns
        let mut transformations: Vec<(usize, usize, SsaVarId, SsaVarId, &'static str)> = Vec::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            match instr.op() {
                // Check for --x pattern: Neg(Neg(x)) = x
                SsaOp::Neg { dest, operand } => {
                    // Look up what defines the operand
                    if let Some(&(def_block, def_instr)) = definitions.get(operand) {
                        if let Some(def_block_ref) = ssa.block(def_block) {
                            if let SsaOp::Neg {
                                operand: inner_operand,
                                ..
                            } = def_block_ref.instructions()[def_instr].op()
                            {
                                // Found --x pattern, replace with copy of inner_operand
                                transformations.push((
                                    block_idx,
                                    instr_idx,
                                    *dest,
                                    *inner_operand,
                                    "neg(neg(x))",
                                ));
                            }
                        }
                    }
                }
                // Check for ~~x pattern: Not(Not(x)) = x
                SsaOp::Not { dest, operand } => {
                    // Look up what defines the operand
                    if let Some(&(def_block, def_instr)) = definitions.get(operand) {
                        if let Some(def_block_ref) = ssa.block(def_block) {
                            if let SsaOp::Not {
                                operand: inner_operand,
                                ..
                            } = def_block_ref.instructions()[def_instr].op()
                            {
                                // Found ~~x pattern, replace with copy of inner_operand
                                transformations.push((
                                    block_idx,
                                    instr_idx,
                                    *dest,
                                    *inner_operand,
                                    "not(not(x))",
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Apply transformations
        for (block_idx, instr_idx, dest, src, pattern) in transformations {
            if let Some(block) = ssa.block_mut(block_idx) {
                let instr = &mut block.instructions_mut()[instr_idx];
                let old_op_str = format!("{}", instr.op());

                instr.set_op(SsaOp::Copy { dest, src });
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, instr_idx)
                    .message(format!("{} → copy {} ({})", old_op_str, src, pattern));
            }
        }
    }

    /// Simplifies control flow based on constant conditions.
    ///
    /// Converts branches and switches with known conditions to unconditional jumps.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to transform.
    /// * `constants` - Map of known constants.
    /// * `sccp_result` - The SCCP analysis results.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    fn simplify_control_flow(
        ssa: &mut SsaFunction,
        constants: &HashMap<SsaVarId, ConstValue>,
        sccp_result: &SccpResult,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        for block_idx in 0..ssa.block_count() {
            if !sccp_result.is_block_executable(block_idx) {
                continue;
            }

            // First pass: analyze the terminator without mutable borrow
            let simplification = if let Some(block) = ssa.block(block_idx) {
                if let Some(op) = block.terminator_op() {
                    match op {
                        SsaOp::Branch {
                            condition,
                            true_target,
                            false_target,
                        } => {
                            if let Some(c) = constants.get(condition) {
                                if let Some(is_true) = c.as_bool() {
                                    let target = if is_true { *true_target } else { *false_target };
                                    Some((SsaOp::Jump { target }, target))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        SsaOp::Switch {
                            value,
                            targets,
                            default,
                        } => {
                            // Skip simplification for preserved dispatch variables
                            // These control input-dependent control flow that must be preserved
                            if ssa.is_preserved_dispatch_var(*value) {
                                None
                            } else if let Some(c) = constants.get(value) {
                                if let Some(idx) = c.as_i32() {
                                    let target = usize::try_from(idx)
                                        .ok()
                                        .and_then(|i| targets.get(i).copied())
                                        .unwrap_or(*default);
                                    Some((SsaOp::Jump { target }, target))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        SsaOp::BranchCmp {
                            left,
                            right,
                            cmp,
                            unsigned,
                            true_target,
                            false_target,
                        } => {
                            // Try to evaluate comparison when both operands are constant
                            if let (Some(left_val), Some(right_val)) =
                                (constants.get(left), constants.get(right))
                            {
                                let result = if *unsigned {
                                    Self::eval_cmp_unsigned(*cmp, left_val, right_val)
                                } else {
                                    Self::eval_cmp_signed(*cmp, left_val, right_val)
                                };
                                if let Some(is_true) = result {
                                    let target = if is_true { *true_target } else { *false_target };
                                    Some((SsaOp::Jump { target }, target))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Second pass: apply the simplification with mutable borrow
            if let Some((new_op, target)) = simplification {
                if let Some(block) = ssa.block_mut(block_idx) {
                    if let Some(last_instr) = block.instructions_mut().last_mut() {
                        last_instr.set_op(new_op);
                        changes
                            .record(EventKind::BranchSimplified)
                            .at(method_token, block_idx)
                            .message(format!("simplified to unconditional branch to {target}"));
                    }
                }
            }
        }
    }

    /// Evaluate a signed comparison between two constant values.
    fn eval_cmp_signed(cmp: CmpKind, left: &ConstValue, right: &ConstValue) -> Option<bool> {
        // Get both values as i64 for signed comparison
        let l = left.as_i64()?;
        let r = right.as_i64()?;
        Some(match cmp {
            CmpKind::Eq => l == r,
            CmpKind::Ne => l != r,
            CmpKind::Lt => l < r,
            CmpKind::Le => l <= r,
            CmpKind::Gt => l > r,
            CmpKind::Ge => l >= r,
        })
    }

    /// Evaluate an unsigned comparison between two constant values.
    fn eval_cmp_unsigned(cmp: CmpKind, left: &ConstValue, right: &ConstValue) -> Option<bool> {
        // Get both values as u64 for unsigned comparison
        let l = left.as_u64()?;
        let r = right.as_u64()?;
        Some(match cmp {
            CmpKind::Eq => l == r,
            CmpKind::Ne => l != r,
            CmpKind::Lt => l < r,
            CmpKind::Le => l <= r,
            CmpKind::Gt => l > r,
            CmpKind::Ge => l >= r,
        })
    }
}

impl SsaPass for ConstantPropagationPass {
    fn name(&self) -> &'static str {
        "constant-propagation"
    }

    fn description(&self) -> &'static str {
        "Propagates constant values and folds constant expressions using SCCP"
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &AnalysisContext,
        _assembly: &Arc<CilObject>,
    ) -> Result<bool> {
        let mut changes = EventLog::new();

        // Run constant propagation and transformation
        let constants = Self::run_constant_propagation(ssa, method_token, &mut changes);

        // Cache the constants we found for other passes
        for (var, value) in &constants {
            ctx.add_known_value(method_token, *var, value.clone());
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests;
