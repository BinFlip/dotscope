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

use std::collections::BTreeMap;

use crate::{
    analysis::{
        simplify_op, CmpKind, ConstValue, ConstantPropagation, MethodRef, SccpResult,
        SimplifyResult, SsaCfg, SsaEvaluator, SsaFunction, SsaOp, SsaType, SsaVarId,
    },
    compiler::{
        pass::{ModificationScope, SsaPass},
        CompilerContext, EventKind, EventLog,
    },
    metadata::{token::Token, typesystem::PointerSize},
    utils::BitSet,
    CilObject, Result,
};

/// Checks whether `token` resolves to a method whose declaring type name contains `type_name`.
///
/// Handles both `MethodDef` (table 0x06) and `MemberRef` (table 0x0A) tokens. A duplicate of
/// `deobfuscation::utils::is_method_on_type` exists here so that the `compiler` feature does
/// not depend on the `deobfuscation` feature being enabled.
fn is_method_on_type(assembly: &CilObject, token: Token, type_name: &str) -> bool {
    match token.table() {
        0x06 => assembly
            .method(&token)
            .and_then(|m| m.declaring_type_rc())
            .is_some_and(|ty| ty.name.contains(type_name)),
        0x0A => assembly
            .refs_members()
            .get(&token)
            .and_then(|entry| entry.value().declaredby.fullname())
            .is_some_and(|name| name.contains(type_name)),
        _ => false,
    }
}

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

/// Recognized string operation that can be folded when all arguments are constants.
#[derive(Debug, Clone, Copy)]
enum StringFoldOp {
    /// `String.Concat(String, String)` — static, 2 args.
    Concat2,
    /// `String.Concat(String, String, String)` — static, 3 args.
    Concat3,
    /// `String.Concat(String, String, String, String)` — static, 4 args.
    Concat4,
    /// `String.Substring(Int32)` — instance, args = [this, start].
    SubstringFrom,
    /// `String.Substring(Int32, Int32)` — instance, args = [this, start, len].
    SubstringRange,
    /// `String.Replace(String, String)` — instance, args = [this, old, new].
    Replace,
    /// `String.ToLower()` — instance, args = [this].
    ToLower,
    /// `String.ToUpper()` — instance, args = [this].
    ToUpper,
}

/// Constant propagation and folding pass.
///
/// This pass combines the SCCP analysis with additional optimizations
/// for identity operations, absorbing elements, and type conversions.
pub struct ConstantPropagationPass {
    /// Maximum fixpoint iterations before stopping.
    max_iterations: usize,
}

impl ConstantPropagationPass {
    /// Creates a new constant propagation pass.
    ///
    /// # Arguments
    ///
    /// * `max_iterations` - Maximum fixpoint iterations for the internal optimization
    ///   loop (SCCP + algebraic simplification). The default config value is 10.
    #[must_use]
    pub fn new(max_iterations: usize) -> Self {
        Self { max_iterations }
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
    /// * `ptr_size` - Pointer size for the target architecture.
    /// * `max_iterations` - Maximum fixpoint iterations for the optimization loop.
    ///
    /// # Returns
    ///
    /// A map from SSA variables to their constant values.
    fn run_constant_propagation(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
        ptr_size: PointerSize,
        max_iterations: usize,
        assembly: &CilObject,
    ) -> BTreeMap<SsaVarId, ConstValue> {
        let block_count = ssa.block_count();
        if block_count == 0 {
            return BTreeMap::new();
        }

        // Recompute use tracking before SCCP analysis.
        // Use information may be stale after SSA transformations (e.g., CFF reconstruction),
        // which can cause SCCP to miss re-evaluating instructions when phi values change.
        ssa.recompute_uses();

        // Build CFG from SSA and run SCCP analysis using the dataflow framework
        let cfg = SsaCfg::from_ssa(ssa);
        let mut sccp = ConstantPropagation::new(ptr_size);
        let mut sccp_result = sccp.analyze(ssa, &cfg);

        // Collect constants from SCCP result
        let mut constants: BTreeMap<SsaVarId, ConstValue> = sccp_result
            .constants()
            .map(|(var, c)| (var, c.clone()))
            .collect();

        // Resolve calls to pure methods with all-constant arguments.
        // This enables constant propagation through converted x86 stubs
        // (ConfuserEx CFF state computation calls). If calls are folded,
        // re-run SCCP so the new constants propagate through dependent
        // operations (e.g., rem.un → switch in handler CFF dispatchers).
        let pre_fold_count = constants.len();
        Self::fold_pure_calls(
            ssa,
            &mut constants,
            method_token,
            changes,
            assembly,
            ptr_size,
        );
        if constants.len() > pre_fold_count {
            ssa.recompute_uses();
            let cfg = SsaCfg::from_ssa(ssa);
            let mut sccp2 = ConstantPropagation::new(ptr_size);
            let sccp_result2 = sccp2.analyze(ssa, &cfg);
            for (var, c) in sccp_result2.constants() {
                constants.entry(var).or_insert_with(|| c.clone());
            }
            // Update the sccp_result for downstream use
            sccp_result = sccp_result2;
        }

        // Apply additional optimizations iteratively
        for _ in 0..max_iterations {
            let prev_count = constants.len();

            // Run identity and absorbing element optimizations
            Self::optimize_algebraic_identities(ssa, &mut constants, method_token, changes);

            // Run involutory operation simplification (--x=x, ~~x=x)
            Self::simplify_involutory_ops(ssa, method_token, changes);

            // Run conversion folding
            Self::fold_conversions(ssa, &mut constants, method_token, changes, ptr_size);

            // Eliminate redundant conversions
            Self::eliminate_redundant_conversions(ssa, method_token, changes);

            // Run overflow-checked operation folding
            Self::fold_overflow_checked_ops(ssa, &mut constants, method_token, changes, ptr_size);

            // Run string operation folding (Concat, Substring, Replace, etc.)
            Self::fold_string_operations(ssa, &mut constants, method_token, changes, assembly);

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
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
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
                            .message(format!("{old_op_str} → {value} (algebraic)"));
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
                                .message(format!("{old_op_str} → {value} (identity)"));
                        } else {
                            // Replace with copy - copy propagation will handle this
                            instr.set_op(SsaOp::Copy { dest, src });
                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{old_op_str} → copy {src} (identity)"));
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
        constants: &BTreeMap<SsaVarId, ConstValue>,
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
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        ptr_size: PointerSize,
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
                            operand_val.convert_to_checked(target, *unsigned, ptr_size)
                        } else {
                            operand_val.convert_to(target, *unsigned, ptr_size)
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
                    .message(format!("{old_op_str} → {value} (conv)"));
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
        let mut definitions: BTreeMap<SsaVarId, ConvInfo> = BTreeMap::new();

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
                                "{old_op_str} → conv.{target} {new_operand} ({reason})"
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
                            .message(format!("{old_op_str} → copy {src} ({reason})"));
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
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        ptr_size: PointerSize,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((dest, value)) =
                    Self::check_overflow_op(instr.op(), constants, ptr_size)
                {
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
                    .message(format!("{old_op_str} → {value} (ovf)"));
            }
        }
    }

    /// Checks if an overflow-checked operation can be folded.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)] // Intentional bit reinterpretation for overflow checking
    fn check_overflow_op(
        op: &SsaOp,
        constants: &BTreeMap<SsaVarId, ConstValue>,
        ptr_size: PointerSize,
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
                        return Some((*dest, l.add(r, ptr_size)?));
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
                        return Some((*dest, l.sub(r, ptr_size)?));
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
                        return Some((*dest, l.mul(r, ptr_size)?));
                    }
                }
                None
            }

            _ => None,
        }
    }

    /// Folds calls to pure methods with all-constant arguments.
    ///
    /// This enables interprocedural constant propagation for simple helper methods,
    /// particularly converted x86 native stubs from ConfuserEx CFF. When all arguments
    /// to a call are known constants and the callee is a MethodDef in the same assembly
    /// with a CIL body, the callee is evaluated and the call is replaced with the result.
    fn fold_pure_calls(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        assembly: &CilObject,
        ptr_size: PointerSize,
    ) {
        let mut replacements: Vec<(usize, usize, SsaVarId, ConstValue)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let (dest, callee_token, args) = match instr.op() {
                    SsaOp::Call {
                        dest: Some(dest),
                        method,
                        args,
                    } => (*dest, method.token(), args),
                    _ => continue,
                };

                // Only handle MethodDef tokens (same-assembly methods)
                if !callee_token.is_table(crate::metadata::tables::TableId::MethodDef) {
                    continue;
                }

                // Check if all arguments are known constants.
                let concrete_args: Option<Vec<ConstValue>> = args
                    .iter()
                    .map(|&a| {
                        constants
                            .get(&a)
                            .cloned()
                            .or_else(|| match ssa.get_definition(a) {
                                Some(SsaOp::Const { value, .. }) => Some(value.clone()),
                                _ => None,
                            })
                    })
                    .collect();

                let Some(concrete_args) = concrete_args else {
                    continue;
                };

                // Try to evaluate the callee
                let Some(result) =
                    Self::evaluate_pure_call(assembly, callee_token, &concrete_args, ptr_size)
                else {
                    continue;
                };

                replacements.push((block_idx, instr_idx, dest, result));
            }
        }

        for (block_idx, instr_idx, dest, value) in replacements {
            constants.insert(dest, value.clone());
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.set_op(SsaOp::Const { dest, value });
                    changes
                        .record(EventKind::ConstantFolded)
                        .at(method_token, block_idx * 1000 + instr_idx)
                        .message("folded pure call with constant arguments");
                }
            }
        }

        // Forward-propagate folded call results through simple arithmetic in the
        // same block (e.g., rem.un used for CFF switch dispatch). This is needed
        // because SCCP doesn't visit exception handler blocks, so constants from
        // folded x86 calls wouldn't otherwise reach the switch variable.
        if !constants.is_empty() {
            Self::propagate_folded_arithmetic(ssa, constants, method_token, changes);
        }
    }

    /// Propagates known constants through arithmetic operations.
    ///
    /// After folding pure calls, some operations (like `rem.un`) may have both
    /// operands as constants but haven't been folded yet (SCCP ran before the calls
    /// were folded). This pass finds and folds such operations.
    fn propagate_folded_arithmetic(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let mut new_constants: Vec<(usize, usize, SsaVarId, ConstValue)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::Rem {
                    dest,
                    left,
                    right,
                    unsigned,
                } = instr.op()
                {
                    let lval = constants
                        .get(left)
                        .or_else(|| match ssa.get_definition(*left) {
                            Some(SsaOp::Const { value, .. }) => Some(value),
                            _ => None,
                        })
                        .and_then(ConstValue::as_i64);
                    let rval = constants
                        .get(right)
                        .or_else(|| match ssa.get_definition(*right) {
                            Some(SsaOp::Const { value, .. }) => Some(value),
                            _ => None,
                        })
                        .and_then(ConstValue::as_i64);

                    if let (Some(l), Some(r)) = (lval, rval) {
                        if r != 0 {
                            #[allow(clippy::cast_sign_loss)]
                            let result = if *unsigned {
                                ((l as u64) % (r as u64)) as i64
                            } else if l != i64::MIN || r != -1 {
                                l % r
                            } else {
                                0
                            };
                            #[allow(clippy::cast_possible_truncation)]
                            let value = ConstValue::I32(result as i32);
                            new_constants.push((block_idx, instr_idx, *dest, value));
                        }
                    }
                }
            }
        }

        for (block_idx, instr_idx, dest, value) in new_constants {
            constants.insert(dest, value.clone());
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.set_op(SsaOp::Const { dest, value });
                    changes
                        .record(EventKind::ConstantFolded)
                        .at(method_token, block_idx * 1000 + instr_idx)
                        .message("folded arithmetic with constant operands");
                }
            }
        }
    }

    /// Evaluates a pure method call with concrete arguments.
    ///
    /// Builds SSA for the callee, executes it with the given arguments using
    /// the SSA evaluator, and returns the result if execution completes.
    fn evaluate_pure_call(
        assembly: &CilObject,
        callee_token: Token,
        args: &[ConstValue],
        ptr_size: PointerSize,
    ) -> Option<ConstValue> {
        let method = assembly.method(&callee_token)?;
        let callee_ssa = method.ssa(assembly).ok()?;

        let mut eval = SsaEvaluator::new(&callee_ssa, ptr_size);
        for (var, value) in callee_ssa.argument_variables().zip(args) {
            eval.set_concrete(var.id(), value.clone());
        }

        let trace = eval.execute(0, None, 50);
        if !trace.is_complete() {
            return None;
        }

        let last_block_idx = trace.last_block()?;
        let last_block = callee_ssa.block(last_block_idx)?;

        for instr in last_block.instructions() {
            if let SsaOp::Return {
                value: Some(ret_var),
            } = instr.op()
            {
                return eval.get_concrete(*ret_var).cloned();
            }
        }

        None
    }

    /// Folds string method calls with constant arguments into `DecryptedString` constants.
    ///
    /// Scans all `Call`/`CallVirt` instructions for recognized `System.String` methods
    /// (Concat, Substring, Replace, ToLower, ToUpper) where every argument resolves to
    /// a known string constant. Matching calls are replaced with `SsaOp::Const` holding
    /// the folded `ConstValue::DecryptedString`.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to scan and transform.
    /// * `constants` - Map of known constants; newly folded strings are inserted here.
    /// * `method_token` - Method token for event logging.
    /// * `changes` - Event log for recording transformations.
    /// * `assembly` - Assembly metadata for resolving method tokens and `#US` heap strings.
    fn fold_string_operations(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        assembly: &CilObject,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let folded = match instr.op() {
                    SsaOp::Call {
                        dest: Some(dest),
                        method,
                        args,
                    }
                    | SsaOp::CallVirt {
                        dest: Some(dest),
                        method,
                        args,
                    } => Self::try_fold_string_call(*dest, method, args, constants, assembly),
                    _ => None,
                };
                if let Some((dest, value)) = folded {
                    new_constants.push((dest, value, block_idx, instr_idx));
                }
            }
        }

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
                    .message(format!("{old_op_str} → {value} (string fold)"));
            }
        }
    }

    /// Identifies a recognized `System.String` method that can be constant-folded.
    ///
    /// Resolves the method token through assembly metadata to check both the
    /// declaring type (`System.String`) and method name. Returns `None` if the
    /// method is not a foldable string operation or cannot be resolved.
    ///
    /// # Arguments
    ///
    /// * `method` - The SSA method reference to check.
    /// * `args_len` - Number of arguments (used to disambiguate overloads).
    /// * `assembly` - Assembly metadata for token resolution.
    ///
    /// # Returns
    ///
    /// The identified [`StringFoldOp`], or `None` if not a recognized operation.
    fn identify_string_op(
        method: &MethodRef,
        args_len: usize,
        assembly: &CilObject,
    ) -> Option<StringFoldOp> {
        let token = method.token();
        if !is_method_on_type(assembly, token, "String") {
            return None;
        }
        let name = assembly.resolve_method_name(token)?;
        match (name.as_str(), args_len) {
            ("Concat", 2) => Some(StringFoldOp::Concat2),
            ("Concat", 3) => Some(StringFoldOp::Concat3),
            ("Concat", 4) => Some(StringFoldOp::Concat4),
            ("Substring", 2) => Some(StringFoldOp::SubstringFrom),
            ("Substring", 3) => Some(StringFoldOp::SubstringRange),
            ("Replace", 3) => Some(StringFoldOp::Replace),
            ("ToLower", 1) => Some(StringFoldOp::ToLower),
            ("ToUpper", 1) => Some(StringFoldOp::ToUpper),
            ("ToLowerInvariant", 1) => Some(StringFoldOp::ToLower),
            ("ToUpperInvariant", 1) => Some(StringFoldOp::ToUpper),
            _ => None,
        }
    }

    /// Attempts to fold a single string method call with constant arguments.
    ///
    /// If the method is a recognized `System.String` operation and all arguments
    /// are known string constants, evaluates the operation and returns the result
    /// as a `DecryptedString`. Returns `None` if any argument is non-constant,
    /// the method is unrecognized, or the operation cannot be safely evaluated
    /// (e.g., non-ASCII strings for `Substring`).
    ///
    /// # Arguments
    ///
    /// * `dest` - The SSA variable that receives the call result.
    /// * `method` - The method being called.
    /// * `args` - SSA variables for the call arguments.
    /// * `constants` - Map of known constant values for argument lookup.
    /// * `assembly` - Assembly metadata for method resolution and heap access.
    ///
    /// # Returns
    ///
    /// `Some((dest, folded_value))` if successfully folded, `None` otherwise.
    fn try_fold_string_call(
        dest: SsaVarId,
        method: &MethodRef,
        args: &[SsaVarId],
        constants: &BTreeMap<SsaVarId, ConstValue>,
        assembly: &CilObject,
    ) -> Option<(SsaVarId, ConstValue)> {
        let string_op = Self::identify_string_op(method, args.len(), assembly)?;
        match string_op {
            StringFoldOp::Concat2 | StringFoldOp::Concat3 | StringFoldOp::Concat4 => {
                let strings: Option<Vec<String>> = args
                    .iter()
                    .map(|arg| {
                        constants
                            .get(arg)
                            .and_then(|v| v.as_string_content(assembly))
                    })
                    .collect();
                let result = strings?.concat();
                Some((dest, ConstValue::DecryptedString(result)))
            }
            StringFoldOp::SubstringFrom => {
                let this_str = constants.get(&args[0])?.as_string_content(assembly)?;
                // Bail on non-ASCII: .NET uses UTF-16 char indices, Rust uses bytes.
                if !this_str.is_ascii() {
                    return None;
                }
                let start = constants.get(&args[1])?.as_i32()? as usize;
                if start > this_str.len() {
                    return None;
                }
                Some((
                    dest,
                    ConstValue::DecryptedString(this_str[start..].to_string()),
                ))
            }
            StringFoldOp::SubstringRange => {
                let this_str = constants.get(&args[0])?.as_string_content(assembly)?;
                if !this_str.is_ascii() {
                    return None;
                }
                let start = constants.get(&args[1])?.as_i32()? as usize;
                let len = constants.get(&args[2])?.as_i32()? as usize;
                if start.saturating_add(len) > this_str.len() {
                    return None;
                }
                Some((
                    dest,
                    ConstValue::DecryptedString(this_str[start..start + len].to_string()),
                ))
            }
            StringFoldOp::Replace => {
                let this_str = constants.get(&args[0])?.as_string_content(assembly)?;
                let old = constants.get(&args[1])?.as_string_content(assembly)?;
                let new = constants.get(&args[2])?.as_string_content(assembly)?;
                Some((
                    dest,
                    ConstValue::DecryptedString(this_str.replace(&old, &new)),
                ))
            }
            StringFoldOp::ToLower => {
                let this_str = constants.get(&args[0])?.as_string_content(assembly)?;
                Some((dest, ConstValue::DecryptedString(this_str.to_lowercase())))
            }
            StringFoldOp::ToUpper => {
                let this_str = constants.get(&args[0])?.as_string_content(assembly)?;
                Some((dest, ConstValue::DecryptedString(this_str.to_uppercase())))
            }
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
        constants: &BTreeMap<SsaVarId, ConstValue>,
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
                            // Skip DecryptedArray: arrays are mutable reference types.
                            // Propagating them materializes a fresh array at each use
                            // site, breaking in-place modifications (e.g., XOR loops
                            // that modify the array and then read the result).
                            if matches!(value, ConstValue::DecryptedArray { .. }) {
                                continue;
                            }

                            let old_op_str = format!("{op}");

                            instr.set_op(SsaOp::Const {
                                dest,
                                value: value.clone(),
                            });

                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{old_op_str} → {value}"));
                        }
                    }
                }
            }
        }
    }

    /// Simplifies chains of involutory operations (Neg/Not).
    ///
    /// Involutory operations satisfy f(f(x)) = x. This pass finds maximal chains
    /// of same-type operations and collapses them:
    ///
    /// - **Even-length chains** (e.g., neg(neg(neg(neg(x))))): cancel completely,
    ///   replacing all uses of the outermost result with the innermost operand.
    /// - **Odd-length chains** (e.g., neg(neg(neg(x)))): collapse to a single
    ///   operation on the innermost operand.
    ///
    /// # Chain-based algorithm
    ///
    /// 1. Build a set of all Neg/Not operands to identify outermost instructions
    ///    (an instruction is outermost if its result is NOT used as the operand
    ///    of another same-type operation).
    /// 2. From each outermost instruction, walk backwards through same-op
    ///    definitions to collect the full chain.
    /// 3. Verify all intermediates have exactly 1 use (only the next chain member).
    /// 4. Apply the appropriate transform based on chain parity.
    fn simplify_involutory_ops(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) {
        // Step 1: Build definition map and use counts
        let mut definitions: BTreeMap<SsaVarId, (usize, usize)> = BTreeMap::new();
        let mut use_counts: BTreeMap<SsaVarId, usize> = BTreeMap::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if let Some(dest) = instr.op().dest() {
                definitions.insert(dest, (block_idx, instr_idx));
            }
            for use_var in instr.op().uses() {
                *use_counts.entry(use_var).or_default() += 1;
            }
        }
        for phi in ssa.all_phi_nodes() {
            for operand in phi.operands() {
                *use_counts.entry(operand.value()).or_default() += 1;
            }
        }

        // Step 2: Identify outermost Neg/Not instructions.
        // A Neg is outermost if its dest is NOT used as the operand of another Neg.
        let mut neg_operands = BitSet::new(ssa.var_id_capacity());
        let mut not_operands = BitSet::new(ssa.var_id_capacity());
        for (_, _, instr) in ssa.iter_instructions() {
            match instr.op() {
                SsaOp::Neg { operand, .. } => {
                    neg_operands.insert(operand.index());
                }
                SsaOp::Not { operand, .. } => {
                    not_operands.insert(operand.index());
                }
                _ => {}
            }
        }

        // Step 3: From each outermost instruction, walk backwards to find chains
        struct ChainTransform {
            outermost_dest: SsaVarId,
            innermost_operand: SsaVarId,
            chain_length: usize,
            instructions_to_nop: Vec<(usize, usize)>,
            outermost_location: (usize, usize),
            is_neg: bool,
        }

        let mut processed = BitSet::new(ssa.var_id_capacity());
        let mut transforms: Vec<ChainTransform> = Vec::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            let (dest, operand, is_neg) = match instr.op() {
                SsaOp::Neg { dest, operand } => (*dest, *operand, true),
                SsaOp::Not { dest, operand } => (*dest, *operand, false),
                _ => continue,
            };

            if processed.contains(dest.index()) {
                continue;
            }

            // Only start chains from outermost instructions
            let is_outermost = if is_neg {
                !neg_operands.contains(dest.index())
            } else {
                !not_operands.contains(dest.index())
            };
            if !is_outermost {
                continue;
            }

            // Walk chain backwards through same-op definitions
            let mut chain_locations: Vec<(usize, usize)> = vec![(block_idx, instr_idx)];
            let mut chain_dests: Vec<SsaVarId> = vec![dest];
            let mut current_operand = operand;
            let mut all_intermediates_single_use = true;

            loop {
                // Check that this intermediate has exactly 1 use (the previous chain member)
                let uses = use_counts.get(&current_operand).copied().unwrap_or(0);
                if uses != 1 {
                    all_intermediates_single_use = false;
                    break;
                }

                let Some(&(def_block, def_instr)) = definitions.get(&current_operand) else {
                    break;
                };
                let Some(def_block_ref) = ssa.block(def_block) else {
                    break;
                };

                let inner = match def_block_ref.instructions()[def_instr].op() {
                    SsaOp::Neg {
                        dest: d,
                        operand: inner,
                    } if is_neg => (*d, *inner),
                    SsaOp::Not {
                        dest: d,
                        operand: inner,
                    } if !is_neg => (*d, *inner),
                    _ => break,
                };

                chain_locations.push((def_block, def_instr));
                chain_dests.push(inner.0);
                current_operand = inner.1;
            }

            // Mark all chain members as processed
            for d in &chain_dests {
                processed.insert(d.index());
            }

            let chain_len = chain_locations.len();
            if chain_len < 2 || !all_intermediates_single_use {
                continue;
            }

            transforms.push(ChainTransform {
                outermost_dest: dest,
                innermost_operand: current_operand,
                chain_length: chain_len,
                instructions_to_nop: chain_locations,
                outermost_location: (block_idx, instr_idx),
                is_neg,
            });
        }

        // Step 4: Apply transforms
        for t in transforms {
            let op_name = if t.is_neg { "neg" } else { "not" };

            if t.chain_length % 2 == 0 {
                // Even chain: all cancel out, result = innermost_operand
                ssa.replace_uses_including_phis(t.outermost_dest, t.innermost_operand);
                for &(b, i) in &t.instructions_to_nop {
                    ssa.remove_instruction(b, i);
                }
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, t.outermost_location.1)
                    .message(format!(
                        "{} → {} ({op_name}^{}(x))",
                        t.outermost_dest, t.innermost_operand, t.chain_length
                    ));
            } else {
                // Odd chain: one operation remains, rewrite outermost to use innermost_operand
                let (b, i) = t.outermost_location;
                if let Some(block) = ssa.block_mut(b) {
                    let instr = &mut block.instructions_mut()[i];
                    if t.is_neg {
                        instr.set_op(SsaOp::Neg {
                            dest: t.outermost_dest,
                            operand: t.innermost_operand,
                        });
                    } else {
                        instr.set_op(SsaOp::Not {
                            dest: t.outermost_dest,
                            operand: t.innermost_operand,
                        });
                    }
                }
                // Nop all except the outermost
                for &(b, i) in &t.instructions_to_nop[1..] {
                    ssa.remove_instruction(b, i);
                }
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, t.outermost_location.1)
                    .message(format!(
                        "{} = {op_name}({}) ({op_name}^{}(x))",
                        t.outermost_dest, t.innermost_operand, t.chain_length
                    ));
            }
        }
    }

    /// Checks if a block is a loop header by detecting back-edges.
    ///
    /// A block is a loop header if any block with a higher index targets it,
    /// indicating a back-edge in the CFG. Switch folding must be skipped for
    /// loop headers because the switch value (which appears constant on the
    /// initial iteration) may take different values on subsequent iterations
    /// via the PHI at the loop header.
    fn is_loop_header(ssa: &SsaFunction, block_idx: usize) -> bool {
        // Check the block itself for self-targeting terminators (self-loops).
        // After jump threading, a switch case that originally targeted a
        // trampoline may be threaded to the switch block itself. These
        // self-loops won't be caught by the higher-index scan below.
        if let Some(block) = ssa.block(block_idx) {
            if let Some(op) = block.terminator_op() {
                let self_targets = match op {
                    SsaOp::Switch {
                        targets, default, ..
                    } => targets.contains(&block_idx) || *default == block_idx,
                    _ => false,
                };
                if self_targets {
                    return true;
                }
            }
        }

        // Check for back-edges from blocks with higher indices.
        for bi in (block_idx + 1)..ssa.block_count() {
            if let Some(block) = ssa.block(bi) {
                if let Some(op) = block.terminator_op() {
                    let targets_block = match op {
                        SsaOp::Jump { target } => *target == block_idx,
                        SsaOp::Leave { target } => *target == block_idx,
                        SsaOp::Branch {
                            true_target,
                            false_target,
                            ..
                        } => *true_target == block_idx || *false_target == block_idx,
                        SsaOp::BranchCmp {
                            true_target,
                            false_target,
                            ..
                        } => *true_target == block_idx || *false_target == block_idx,
                        SsaOp::Switch {
                            targets, default, ..
                        } => targets.contains(&block_idx) || *default == block_idx,
                        _ => false,
                    };
                    if targets_block {
                        return true;
                    }
                }
            }
        }
        false
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
        constants: &BTreeMap<SsaVarId, ConstValue>,
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
                            } else if Self::is_loop_header(ssa, block_idx) {
                                // Don't fold switches at loop headers. A switch whose
                                // value is constant on the initial iteration may take
                                // different values on subsequent iterations (via the
                                // PHI at the loop header). Folding it would make all
                                // non-initial-state switch cases unreachable, which is
                                // incorrect for CFF inner state machines (e.g.,
                                // JIEJIE.NET nested dispatchers within using blocks).
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

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
    ) -> Result<bool> {
        let mut changes = EventLog::new();
        let ptr_size = PointerSize::from_pe(assembly.file().pe().is_64bit);

        // Run constant propagation and transformation
        let constants = Self::run_constant_propagation(
            ssa,
            method_token,
            &mut changes,
            ptr_size,
            self.max_iterations,
            assembly,
        );

        // Cache the constants we found for other passes
        for (var, value) in &constants {
            ctx.add_known_value(method_token, *var, value.clone());
        }

        let changed = !changes.is_empty();
        if changed {
            ctx.events.merge(&changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests;
