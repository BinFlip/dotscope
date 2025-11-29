//! CIL instruction decomposition to SSA operations.
//!
//! This module converts CIL instructions to decomposed `SsaOp` form where each
//! operation follows the `result = op(operands)` pattern. This transformation
//! is essential for optimization passes that need clean, explicit data flow.
//!
//! # Design
//!
//! The decomposition process:
//! 1. Takes a CIL instruction and its stack simulation results (uses, def)
//! 2. Extracts operand information (tokens, immediates, etc.)
//! 3. Constructs the appropriate `SsaOp` variant
//!
//! # Handling Constants
//!
//! CIL constant loading instructions (ldc.i4, ldc.i8, etc.) are converted to
//! `SsaOp::Const` with the appropriate `ConstValue`.

// Branch targets in CIL use u64 (RVA) but block indices use usize.
// On 32-bit targets this could truncate, but RVAs in .NET are always 32-bit.
#![allow(clippy::cast_possible_truncation)]

use crate::{
    analysis::ssa::{
        ops::SsaOp,
        types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef},
        value::ConstValue,
        SsaVarId,
    },
    assembly::{Immediate, Instruction, Operand},
    metadata::token::Token,
};

/// Decomposes a CIL instruction into an SSA operation.
///
/// # Arguments
///
/// * `instr` - The CIL instruction to decompose
/// * `uses` - SSA variables consumed by this instruction (from stack simulation)
/// * `def` - SSA variable produced by this instruction (if any)
///
/// # Returns
///
/// The decomposed `SsaOp`, or `None` if decomposition is not possible.
/// Some instructions may not have a meaningful SSA operation (e.g., prefixes).
#[must_use]
pub fn decompose_instruction(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
) -> Option<SsaOp> {
    // Handle FE-prefixed instructions
    if instr.prefix == 0xFE {
        return decompose_fe_instruction(instr, uses, def);
    }

    match instr.opcode {
        // =====================================================================
        // Constants
        // =====================================================================
        0x14 => {
            // ldnull
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::Null,
            })
        }
        0x15 => {
            // ldc.i4.m1
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(-1),
            })
        }
        0x16 => {
            // ldc.i4.0
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(0),
            })
        }
        0x17 => {
            // ldc.i4.1
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(1),
            })
        }
        0x18 => {
            // ldc.i4.2
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(2),
            })
        }
        0x19 => {
            // ldc.i4.3
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(3),
            })
        }
        0x1A => {
            // ldc.i4.4
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(4),
            })
        }
        0x1B => {
            // ldc.i4.5
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(5),
            })
        }
        0x1C => {
            // ldc.i4.6
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(6),
            })
        }
        0x1D => {
            // ldc.i4.7
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(7),
            })
        }
        0x1E => {
            // ldc.i4.8
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(8),
            })
        }
        0x1F => {
            // ldc.i4.s
            def.and_then(|dest| {
                extract_i32(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::I32(v),
                })
            })
        }
        0x20 => {
            // ldc.i4
            def.and_then(|dest| {
                extract_i32(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::I32(v),
                })
            })
        }
        0x21 => {
            // ldc.i8
            def.and_then(|dest| {
                extract_i64(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::I64(v),
                })
            })
        }
        0x22 => {
            // ldc.r4
            def.and_then(|dest| {
                extract_f32(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::F32(v),
                })
            })
        }
        0x23 => {
            // ldc.r8
            def.and_then(|dest| {
                extract_f64(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::F64(v),
                })
            })
        }

        // =====================================================================
        // Stack operations
        // =====================================================================
        0x25 => {
            // dup
            if let (Some(src), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::Copy { dest, src: *src })
            } else {
                None
            }
        }
        0x26 => {
            // pop
            uses.first().map(|&value| SsaOp::Pop { value })
        }

        // =====================================================================
        // Arithmetic
        // =====================================================================
        0x58 => binary_op(uses, def, |dest, left, right| SsaOp::Add {
            dest,
            left,
            right,
        }), // add
        0x59 => binary_op(uses, def, |dest, left, right| SsaOp::Sub {
            dest,
            left,
            right,
        }), // sub
        0x5A => binary_op(uses, def, |dest, left, right| SsaOp::Mul {
            dest,
            left,
            right,
        }), // mul
        0x5B => binary_op(uses, def, |dest, left, right| SsaOp::Div {
            // div
            dest,
            left,
            right,
            unsigned: false,
        }),
        0x5C => binary_op(uses, def, |dest, left, right| SsaOp::Div {
            // div.un
            dest,
            left,
            right,
            unsigned: true,
        }),
        0x5D => binary_op(uses, def, |dest, left, right| SsaOp::Rem {
            // rem
            dest,
            left,
            right,
            unsigned: false,
        }),
        0x5E => binary_op(uses, def, |dest, left, right| SsaOp::Rem {
            // rem.un
            dest,
            left,
            right,
            unsigned: true,
        }),

        0x65 => unary_op(uses, def, |dest, operand| SsaOp::Neg { dest, operand }), // neg
        0x66 => unary_op(uses, def, |dest, operand| SsaOp::Not { dest, operand }), // not

        // Overflow checking arithmetic
        0xD6 => binary_op(uses, def, |dest, left, right| SsaOp::AddOvf {
            // add.ovf
            dest,
            left,
            right,
            unsigned: false,
        }),
        0xD7 => binary_op(uses, def, |dest, left, right| SsaOp::AddOvf {
            // add.ovf.un
            dest,
            left,
            right,
            unsigned: true,
        }),
        0xDA => binary_op(uses, def, |dest, left, right| SsaOp::MulOvf {
            // mul.ovf
            dest,
            left,
            right,
            unsigned: false,
        }),
        0xDB => binary_op(uses, def, |dest, left, right| SsaOp::MulOvf {
            // mul.ovf.un
            dest,
            left,
            right,
            unsigned: true,
        }),
        0xD8 => binary_op(uses, def, |dest, left, right| SsaOp::SubOvf {
            // sub.ovf
            dest,
            left,
            right,
            unsigned: false,
        }),
        0xD9 => binary_op(uses, def, |dest, left, right| SsaOp::SubOvf {
            // sub.ovf.un
            dest,
            left,
            right,
            unsigned: true,
        }),

        // =====================================================================
        // Bitwise operations
        // =====================================================================
        0x5F => binary_op(uses, def, |dest, left, right| SsaOp::And {
            dest,
            left,
            right,
        }), // and
        0x60 => binary_op(uses, def, |dest, left, right| SsaOp::Or {
            dest,
            left,
            right,
        }), // or
        0x61 => binary_op(uses, def, |dest, left, right| SsaOp::Xor {
            dest,
            left,
            right,
        }), // xor
        0x62 => binary_op(uses, def, |dest, value, amount| SsaOp::Shl {
            // shl
            dest,
            value,
            amount,
        }),
        0x63 => binary_op(uses, def, |dest, value, amount| SsaOp::Shr {
            // shr
            dest,
            value,
            amount,
            unsigned: false,
        }),
        0x64 => binary_op(uses, def, |dest, value, amount| SsaOp::Shr {
            // shr.un
            dest,
            value,
            amount,
            unsigned: true,
        }),

        // =====================================================================
        // Conversions
        // =====================================================================
        0x67 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.i1
            dest,
            operand,
            target: SsaType::I8,
            overflow_check: false,
            unsigned: false,
        }),
        0x68 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.i2
            dest,
            operand,
            target: SsaType::I16,
            overflow_check: false,
            unsigned: false,
        }),
        0x69 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.i4
            dest,
            operand,
            target: SsaType::I32,
            overflow_check: false,
            unsigned: false,
        }),
        0x6A => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.i8
            dest,
            operand,
            target: SsaType::I64,
            overflow_check: false,
            unsigned: false,
        }),
        0x6B => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.r4
            dest,
            operand,
            target: SsaType::F32,
            overflow_check: false,
            unsigned: false,
        }),
        0x6C => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.r8
            dest,
            operand,
            target: SsaType::F64,
            overflow_check: false,
            unsigned: false,
        }),
        0xD1 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.u1
            dest,
            operand,
            target: SsaType::U8,
            overflow_check: false,
            unsigned: true,
        }),
        0xD2 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.u2
            dest,
            operand,
            target: SsaType::U16,
            overflow_check: false,
            unsigned: true,
        }),
        0x6D => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.u4
            dest,
            operand,
            target: SsaType::U32,
            overflow_check: false,
            unsigned: true,
        }),
        0x6E => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.u8
            dest,
            operand,
            target: SsaType::U64,
            overflow_check: false,
            unsigned: true,
        }),
        0xD3 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.i
            dest,
            operand,
            target: SsaType::NativeInt,
            overflow_check: false,
            unsigned: false,
        }),
        0xE0 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.u
            dest,
            operand,
            target: SsaType::NativeUInt,
            overflow_check: false,
            unsigned: true,
        }),
        0x76 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.r.un
            dest,
            operand,
            target: SsaType::F64,
            overflow_check: false,
            unsigned: true,
        }),

        // Overflow-checking conversions
        0xB3 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i1
            dest,
            operand,
            target: SsaType::I8,
            overflow_check: true,
            unsigned: false,
        }),
        0x82 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i1.un
            dest,
            operand,
            target: SsaType::I8,
            overflow_check: true,
            unsigned: true,
        }),
        0xB5 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i2
            dest,
            operand,
            target: SsaType::I16,
            overflow_check: true,
            unsigned: false,
        }),
        0x83 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i2.un
            dest,
            operand,
            target: SsaType::I16,
            overflow_check: true,
            unsigned: true,
        }),
        0xB7 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i4
            dest,
            operand,
            target: SsaType::I32,
            overflow_check: true,
            unsigned: false,
        }),
        0x84 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i4.un
            dest,
            operand,
            target: SsaType::I32,
            overflow_check: true,
            unsigned: true,
        }),
        0xB9 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i8
            dest,
            operand,
            target: SsaType::I64,
            overflow_check: true,
            unsigned: false,
        }),
        0x85 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i8.un
            dest,
            operand,
            target: SsaType::I64,
            overflow_check: true,
            unsigned: true,
        }),
        0xD4 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i
            dest,
            operand,
            target: SsaType::NativeInt,
            overflow_check: true,
            unsigned: false,
        }),
        0x8A => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.i.un
            dest,
            operand,
            target: SsaType::NativeInt,
            overflow_check: true,
            unsigned: true,
        }),
        0xB4 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u1
            dest,
            operand,
            target: SsaType::U8,
            overflow_check: true,
            unsigned: false,
        }),
        0x86 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u1.un
            dest,
            operand,
            target: SsaType::U8,
            overflow_check: true,
            unsigned: true,
        }),
        0xB6 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u2
            dest,
            operand,
            target: SsaType::U16,
            overflow_check: true,
            unsigned: false,
        }),
        0x87 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u2.un
            dest,
            operand,
            target: SsaType::U16,
            overflow_check: true,
            unsigned: true,
        }),
        0xB8 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u4
            dest,
            operand,
            target: SsaType::U32,
            overflow_check: true,
            unsigned: false,
        }),
        0x88 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u4.un
            dest,
            operand,
            target: SsaType::U32,
            overflow_check: true,
            unsigned: true,
        }),
        0xBA => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u8
            dest,
            operand,
            target: SsaType::U64,
            overflow_check: true,
            unsigned: false,
        }),
        0x89 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u8.un
            dest,
            operand,
            target: SsaType::U64,
            overflow_check: true,
            unsigned: true,
        }),
        0xD5 => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u
            dest,
            operand,
            target: SsaType::NativeUInt,
            overflow_check: true,
            unsigned: false,
        }),
        0x8B => unary_op(uses, def, |dest, operand| SsaOp::Conv {
            // conv.ovf.u.un
            dest,
            operand,
            target: SsaType::NativeUInt,
            overflow_check: true,
            unsigned: true,
        }),

        // =====================================================================
        // Comparison
        // =====================================================================
        // Note: CIL comparison instructions like beq, blt, etc. are branches,
        // handled in control flow section. The ceq, clt, cgt instructions
        // are in the FE-prefixed section.

        // =====================================================================
        // Control flow
        // =====================================================================
        0x2A => Some(SsaOp::Return {
            // ret
            value: uses.first().copied(),
        }),

        // Unconditional branches
        0x2B | 0x38 => {
            // br.s, br
            instr.branch_targets.first().map(|&target| SsaOp::Jump {
                target: target as usize,
            })
        }

        // Conditional branches (with single operand)
        0x2C | 0x39 => {
            // brfalse.s, brfalse
            uses.first().and_then(|&condition| {
                instr.branch_targets.first().map(|&true_target| {
                    // brfalse jumps to target if false, falls through if true
                    // We model this as: branch !condition, target, fallthrough
                    // But since we don't have a proper fallthrough block index here,
                    // we need to rely on the second branch target if available
                    let false_target = instr.branch_targets.get(1).copied().unwrap_or(true_target);
                    SsaOp::Branch {
                        condition,
                        true_target: false_target as usize,
                        false_target: true_target as usize,
                    }
                })
            })
        }
        0x2D | 0x3A => {
            // brtrue.s, brtrue
            uses.first().and_then(|&condition| {
                instr.branch_targets.first().map(|&true_target| {
                    let false_target = instr.branch_targets.get(1).copied().unwrap_or(true_target);
                    SsaOp::Branch {
                        condition,
                        true_target: true_target as usize,
                        false_target: false_target as usize,
                    }
                })
            })
        }

        // Binary conditional branches
        0x2E | 0x3B => {
            // beq.s, beq
            comparison_branch(uses, instr, false)
        }
        0x2F | 0x3C => {
            // bge.s, bge
            comparison_branch(uses, instr, false)
        }
        0x30 | 0x3D => {
            // bgt.s, bgt
            comparison_branch(uses, instr, false)
        }
        0x31 | 0x3E => {
            // ble.s, ble
            comparison_branch(uses, instr, false)
        }
        0x32 | 0x3F => {
            // blt.s, blt
            comparison_branch(uses, instr, false)
        }
        0x33 | 0x40 => {
            // bne.un.s, bne.un
            comparison_branch(uses, instr, true)
        }
        0x34 | 0x41 => {
            // bge.un.s, bge.un
            comparison_branch(uses, instr, true)
        }
        0x35 | 0x42 => {
            // bgt.un.s, bgt.un
            comparison_branch(uses, instr, true)
        }
        0x36 | 0x43 => {
            // ble.un.s, ble.un
            comparison_branch(uses, instr, true)
        }
        0x37 | 0x44 => {
            // blt.un.s, blt.un
            comparison_branch(uses, instr, true)
        }

        0x45 => {
            // switch
            uses.first().and_then(|&value| {
                if instr.branch_targets.len() >= 2 {
                    let default = instr.branch_targets.last().copied().unwrap_or(0) as usize;
                    let targets: Vec<usize> = instr.branch_targets
                        [..instr.branch_targets.len() - 1]
                        .iter()
                        .map(|&t| t as usize)
                        .collect();
                    Some(SsaOp::Switch {
                        value,
                        targets,
                        default,
                    })
                } else {
                    None
                }
            })
        }

        0xDD => {
            // leave.s
            instr.branch_targets.first().map(|&target| SsaOp::Leave {
                target: target as usize,
            })
        }
        0xDE => {
            // leave
            instr.branch_targets.first().map(|&target| SsaOp::Leave {
                target: target as usize,
            })
        }

        // =====================================================================
        // Load/Store arguments and locals
        // =====================================================================
        // These are handled by stack simulation, but we generate Copy ops
        0x02..=0x05 | 0x0E => {
            // ldarg.0-3, ldarg.s
            // These load from argument, which becomes a Copy in SSA
            None // Already tracked by uses/def
        }
        0x06..=0x09 | 0x11 => {
            // ldloc.0-3, ldloc.s
            None // Already tracked by uses/def
        }
        0x0A..=0x0D | 0x13 => {
            // stloc.0-3, stloc.s
            None // Already tracked by uses/def
        }
        0x0F | 0x10 | 0x12 => {
            // ldarga.s, starg.s, ldloca.s
            // Address loading - generates LoadArgAddr/LoadLocalAddr
            match (instr.opcode, def) {
                (0x0F, Some(dest)) => extract_u16(&instr.operand)
                    .map(|arg_index| SsaOp::LoadArgAddr { dest, arg_index }),
                (0x12, Some(dest)) => extract_u16(&instr.operand)
                    .map(|local_index| SsaOp::LoadLocalAddr { dest, local_index }),
                _ => None,
            }
        }

        // =====================================================================
        // Object operations
        // =====================================================================
        0x6F => {
            // callvirt
            call_op(instr, uses, def, true)
        }
        0x28 => {
            // call
            call_op(instr, uses, def, false)
        }
        0x29 => {
            // calli
            if let Some(signature) = extract_signature_token(&instr.operand) {
                let (fptr, args) = if uses.is_empty() {
                    (SsaVarId::new(0), vec![])
                } else {
                    // Last use is the function pointer
                    let fptr = *uses.last().unwrap();
                    let args = uses[..uses.len() - 1].to_vec();
                    (fptr, args)
                };
                Some(SsaOp::CallIndirect {
                    dest: def,
                    fptr,
                    signature,
                    args,
                })
            } else {
                None
            }
        }

        0x73 => {
            // newobj
            if let Some(ctor) = extract_method_token(&instr.operand) {
                def.map(|dest| SsaOp::NewObj {
                    dest,
                    ctor,
                    args: uses.to_vec(),
                })
            } else {
                None
            }
        }
        0x8D => {
            // newarr
            if let (Some(elem_type), Some(&length), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::NewArr {
                    dest,
                    elem_type,
                    length,
                })
            } else {
                None
            }
        }

        0x74 => {
            // castclass
            if let (Some(target_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::CastClass {
                    dest,
                    object,
                    target_type,
                })
            } else {
                None
            }
        }
        0x75 => {
            // isinst
            if let (Some(target_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::IsInst {
                    dest,
                    object,
                    target_type,
                })
            } else {
                None
            }
        }

        0x8C => {
            // box
            if let (Some(value_type), Some(&value), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::Box {
                    dest,
                    value,
                    value_type,
                })
            } else {
                None
            }
        }
        0x79 => {
            // unbox
            if let (Some(value_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::Unbox {
                    dest,
                    object,
                    value_type,
                })
            } else {
                None
            }
        }
        0xA5 => {
            // unbox.any
            if let (Some(value_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::UnboxAny {
                    dest,
                    object,
                    value_type,
                })
            } else {
                None
            }
        }

        // =====================================================================
        // Field operations
        // =====================================================================
        0x7B => {
            // ldfld
            if let (Some(field), Some(&object), Some(dest)) =
                (extract_field_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::LoadField {
                    dest,
                    object,
                    field,
                })
            } else {
                None
            }
        }
        0x7D => {
            // stfld
            if let (Some(field), Some(object), Some(value)) = (
                extract_field_token(&instr.operand),
                uses.first(),
                uses.get(1),
            ) {
                Some(SsaOp::StoreField {
                    object: *object,
                    field,
                    value: *value,
                })
            } else {
                None
            }
        }
        0x7C => {
            // ldflda
            if let (Some(field), Some(&object), Some(dest)) =
                (extract_field_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::LoadFieldAddr {
                    dest,
                    object,
                    field,
                })
            } else {
                None
            }
        }
        0x7E => {
            // ldsfld
            if let (Some(field), Some(dest)) = (extract_field_token(&instr.operand), def) {
                Some(SsaOp::LoadStaticField { dest, field })
            } else {
                None
            }
        }
        0x80 => {
            // stsfld
            if let (Some(field), Some(&value)) = (extract_field_token(&instr.operand), uses.first())
            {
                Some(SsaOp::StoreStaticField { field, value })
            } else {
                None
            }
        }
        0x7F => {
            // ldsflda
            if let (Some(field), Some(dest)) = (extract_field_token(&instr.operand), def) {
                Some(SsaOp::LoadStaticFieldAddr { dest, field })
            } else {
                None
            }
        }

        // =====================================================================
        // Array operations
        // =====================================================================
        0x8E => {
            // ldlen
            if let (Some(&array), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::ArrayLength { dest, array })
            } else {
                None
            }
        }
        0x8F => {
            // ldelema
            if let (Some(&array), Some(&index), Some(dest)) = (uses.first(), uses.get(1), def) {
                let elem_type =
                    extract_type_token(&instr.operand).map_or(SsaType::Unknown, type_ref_to_ssa);
                Some(SsaOp::LoadElementAddr {
                    dest,
                    array,
                    index,
                    elem_type,
                })
            } else {
                None
            }
        }

        // ldelem variants
        0xA3 => {
            // ldelem
            ldelem_op(uses, def, &instr.operand)
        }
        0x90 => ldelem_typed(uses, def, SsaType::I8), // ldelem.i1
        0x91 => ldelem_typed(uses, def, SsaType::U8), // ldelem.u1
        0x92 => ldelem_typed(uses, def, SsaType::I16), // ldelem.i2
        0x93 => ldelem_typed(uses, def, SsaType::U16), // ldelem.u2
        0x94 => ldelem_typed(uses, def, SsaType::I32), // ldelem.i4
        0x95 => ldelem_typed(uses, def, SsaType::U32), // ldelem.u4
        0x96 => ldelem_typed(uses, def, SsaType::I64), // ldelem.i8
        0x97 => ldelem_typed(uses, def, SsaType::NativeInt), // ldelem.i
        0x98 => ldelem_typed(uses, def, SsaType::F32), // ldelem.r4
        0x99 => ldelem_typed(uses, def, SsaType::F64), // ldelem.r8
        0x9A => ldelem_typed(uses, def, SsaType::Object), // ldelem.ref

        // stelem variants
        0xA4 => {
            // stelem
            stelem_op(uses, &instr.operand)
        }
        0x9C => stelem_typed(uses, SsaType::I8), // stelem.i1
        0x9D => stelem_typed(uses, SsaType::I16), // stelem.i2
        0x9E => stelem_typed(uses, SsaType::I32), // stelem.i4
        0x9F => stelem_typed(uses, SsaType::I64), // stelem.i8
        0xA0 => stelem_typed(uses, SsaType::F32), // stelem.r4
        0xA1 => stelem_typed(uses, SsaType::F64), // stelem.r8
        0xA2 => stelem_typed(uses, SsaType::Object), // stelem.ref
        0x9B => stelem_typed(uses, SsaType::NativeInt), // stelem.i

        // =====================================================================
        // Indirect access (ldind/stind)
        // =====================================================================
        0x46 => ldind_typed(uses, def, SsaType::I8), // ldind.i1
        0x47 => ldind_typed(uses, def, SsaType::U8), // ldind.u1
        0x48 => ldind_typed(uses, def, SsaType::I16), // ldind.i2
        0x49 => ldind_typed(uses, def, SsaType::U16), // ldind.u2
        0x4A => ldind_typed(uses, def, SsaType::I32), // ldind.i4
        0x4B => ldind_typed(uses, def, SsaType::U32), // ldind.u4
        0x4C => ldind_typed(uses, def, SsaType::I64), // ldind.i8
        0x4D => ldind_typed(uses, def, SsaType::NativeInt), // ldind.i
        0x4E => ldind_typed(uses, def, SsaType::F32), // ldind.r4
        0x4F => ldind_typed(uses, def, SsaType::F64), // ldind.r8
        0x50 => ldind_typed(uses, def, SsaType::Object), // ldind.ref

        0x52 => stind_typed(uses, SsaType::I8),  // stind.i1
        0x53 => stind_typed(uses, SsaType::I16), // stind.i2
        0x54 => stind_typed(uses, SsaType::I32), // stind.i4
        0x55 => stind_typed(uses, SsaType::I64), // stind.i8
        0x56 => stind_typed(uses, SsaType::F32), // stind.r4
        0x57 => stind_typed(uses, SsaType::F64), // stind.r8
        0x51 => stind_typed(uses, SsaType::Object), // stind.ref
        0xDF => stind_typed(uses, SsaType::NativeInt), // stind.i

        // =====================================================================
        // Object memory operations
        // =====================================================================
        0x71 => {
            // ldobj
            if let (Some(&src_addr), Some(dest)) = (uses.first(), def) {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::LoadObj {
                    dest,
                    src_addr,
                    value_type,
                })
            } else {
                None
            }
        }
        0x81 => {
            // stobj
            if let (Some(&dest_addr), Some(&value)) = (uses.first(), uses.get(1)) {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::StoreObj {
                    dest_addr,
                    value,
                    value_type,
                })
            } else {
                None
            }
        }
        0x70 => {
            // cpobj
            if let (Some(&dest_addr), Some(&src_addr)) = (uses.first(), uses.get(1)) {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::CopyObj {
                    dest_addr,
                    src_addr,
                    value_type,
                })
            } else {
                None
            }
        }

        // =====================================================================
        // Exception handling
        // =====================================================================
        0x7A => {
            // throw
            uses.first().map(|&exception| SsaOp::Throw { exception })
        }
        // rethrow is FE 1A
        // endfinally is DC
        0xDC => Some(SsaOp::EndFinally), // endfinally

        // =====================================================================
        // Misc
        // =====================================================================
        0x00 => Some(SsaOp::Nop),   // nop
        0x01 => Some(SsaOp::Break), // break

        0x72 => {
            // ldstr
            def.and_then(|dest| {
                extract_string_token(&instr.operand).map(|idx| SsaOp::Const {
                    dest,
                    value: ConstValue::String(idx),
                })
            })
        }
        0xD0 => {
            // ldtoken
            def.and_then(|dest| {
                extract_type_token(&instr.operand).map(|token| SsaOp::LoadToken { dest, token })
            })
        }

        0xC3 => {
            // ckfinite
            if let (Some(&operand), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::Ckfinite { dest, operand })
            } else {
                None
            }
        }

        // Default: no decomposition available for this opcode
        _ => None,
    }
}

/// Decomposes FE-prefixed instructions.
fn decompose_fe_instruction(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
) -> Option<SsaOp> {
    match instr.opcode {
        // Comparison operations
        0x01 => binary_op(uses, def, |dest, left, right| SsaOp::Ceq {
            dest,
            left,
            right,
        }), // ceq
        0x02 => binary_op(uses, def, |dest, left, right| SsaOp::Cgt {
            // cgt
            dest,
            left,
            right,
            unsigned: false,
        }),
        0x03 => binary_op(uses, def, |dest, left, right| SsaOp::Cgt {
            // cgt.un
            dest,
            left,
            right,
            unsigned: true,
        }),
        0x04 => binary_op(uses, def, |dest, left, right| SsaOp::Clt {
            // clt
            dest,
            left,
            right,
            unsigned: false,
        }),
        0x05 => binary_op(uses, def, |dest, left, right| SsaOp::Clt {
            // clt.un
            dest,
            left,
            right,
            unsigned: true,
        }),

        // Function pointers
        0x06 => {
            // ldftn
            if let (Some(method), Some(dest)) = (extract_method_token(&instr.operand), def) {
                Some(SsaOp::LoadFunctionPtr { dest, method })
            } else {
                None
            }
        }
        0x07 => {
            // ldvirtftn
            if let (Some(method), Some(&object), Some(dest)) =
                (extract_method_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::LoadVirtFunctionPtr {
                    dest,
                    object,
                    method,
                })
            } else {
                None
            }
        }

        // Argument/Local long forms
        // 0x09 (ldarg), 0x0B (starg), 0x0C (ldloc), 0x0E (stloc) - handled by stack sim
        0x0A => {
            // ldarga
            def.and_then(|dest| {
                extract_u16(&instr.operand).map(|arg_index| SsaOp::LoadArgAddr { dest, arg_index })
            })
        }
        0x0D => {
            // ldloca
            def.and_then(|dest| {
                extract_u16(&instr.operand)
                    .map(|local_index| SsaOp::LoadLocalAddr { dest, local_index })
            })
        }

        // Memory operations
        0x15 => {
            // initobj
            if let Some(&dest_addr) = uses.first() {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::InitObj {
                    dest_addr,
                    value_type,
                })
            } else {
                None
            }
        }
        0x17 => {
            // cpblk
            if let (Some(&dest_addr), Some(&src_addr), Some(&size)) =
                (uses.first(), uses.get(1), uses.get(2))
            {
                Some(SsaOp::CopyBlk {
                    dest_addr,
                    src_addr,
                    size,
                })
            } else {
                None
            }
        }
        0x18 => {
            // initblk
            if let (Some(&dest_addr), Some(&value), Some(&size)) =
                (uses.first(), uses.get(1), uses.get(2))
            {
                Some(SsaOp::InitBlk {
                    dest_addr,
                    value,
                    size,
                })
            } else {
                None
            }
        }

        // Exception handling
        0x1A => Some(SsaOp::Rethrow), // rethrow
        0x11 => {
            // endfilter
            uses.first().map(|&result| SsaOp::EndFilter { result })
        }

        // Allocation
        0x0F => {
            // localloc
            if let (Some(&size), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::LocalAlloc { dest, size })
            } else {
                None
            }
        }

        // Sizeof
        0x1C => {
            // sizeof
            if let (Some(value_type), Some(dest)) = (extract_type_token(&instr.operand), def) {
                Some(SsaOp::SizeOf { dest, value_type })
            } else {
                None
            }
        }

        // Constrained prefix
        0x16 => extract_type_token(&instr.operand)
            .map(|constraint_type| SsaOp::Constrained { constraint_type }),

        _ => None,
    }
}

// =============================================================================
// Helper functions
// =============================================================================

fn binary_op<F>(uses: &[SsaVarId], def: Option<SsaVarId>, f: F) -> Option<SsaOp>
where
    F: FnOnce(SsaVarId, SsaVarId, SsaVarId) -> SsaOp,
{
    if let (Some(&left), Some(&right), Some(dest)) = (uses.first(), uses.get(1), def) {
        Some(f(dest, left, right))
    } else {
        None
    }
}

fn unary_op<F>(uses: &[SsaVarId], def: Option<SsaVarId>, f: F) -> Option<SsaOp>
where
    F: FnOnce(SsaVarId, SsaVarId) -> SsaOp,
{
    if let (Some(&operand), Some(dest)) = (uses.first(), def) {
        Some(f(dest, operand))
    } else {
        None
    }
}

fn comparison_branch(uses: &[SsaVarId], instr: &Instruction, _unsigned: bool) -> Option<SsaOp> {
    // Binary comparison branches need to be decomposed into:
    // 1. A comparison operation (ceq, clt, etc.)
    // 2. A branch on the result
    // For now, we just create a simple branch - the comparison is implicit
    if let (Some(&_left), Some(&_right)) = (uses.first(), uses.get(1)) {
        // This is a simplification - we should ideally generate a temporary
        // variable for the comparison result. For now, we use the first operand.
        if let Some(&true_target) = instr.branch_targets.first() {
            let false_target = instr.branch_targets.get(1).copied().unwrap_or(true_target);
            // Use first operand as the "condition" - this is a placeholder
            // Real implementation would decompose this into cmp + branch
            uses.first().map(|&condition| SsaOp::Branch {
                condition,
                true_target: true_target as usize,
                false_target: false_target as usize,
            })
        } else {
            None
        }
    } else {
        None
    }
}

fn call_op(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
    is_virtual: bool,
) -> Option<SsaOp> {
    extract_method_token(&instr.operand).map(|method| {
        if is_virtual {
            SsaOp::CallVirt {
                dest: def,
                method,
                args: uses.to_vec(),
            }
        } else {
            SsaOp::Call {
                dest: def,
                method,
                args: uses.to_vec(),
            }
        }
    })
}

fn ldelem_op(uses: &[SsaVarId], def: Option<SsaVarId>, operand: &Operand) -> Option<SsaOp> {
    let elem_type = extract_type_token(operand).map_or(SsaType::Unknown, type_ref_to_ssa);
    ldelem_typed(uses, def, elem_type)
}

fn ldelem_typed(uses: &[SsaVarId], def: Option<SsaVarId>, elem_type: SsaType) -> Option<SsaOp> {
    if let (Some(&array), Some(&index), Some(dest)) = (uses.first(), uses.get(1), def) {
        Some(SsaOp::LoadElement {
            dest,
            array,
            index,
            elem_type,
        })
    } else {
        None
    }
}

fn stelem_op(uses: &[SsaVarId], operand: &Operand) -> Option<SsaOp> {
    let elem_type = extract_type_token(operand).map_or(SsaType::Unknown, type_ref_to_ssa);
    stelem_typed(uses, elem_type)
}

fn stelem_typed(uses: &[SsaVarId], elem_type: SsaType) -> Option<SsaOp> {
    if let (Some(&array), Some(&index), Some(&value)) = (uses.first(), uses.get(1), uses.get(2)) {
        Some(SsaOp::StoreElement {
            array,
            index,
            value,
            elem_type,
        })
    } else {
        None
    }
}

fn ldind_typed(uses: &[SsaVarId], def: Option<SsaVarId>, value_type: SsaType) -> Option<SsaOp> {
    if let (Some(&addr), Some(dest)) = (uses.first(), def) {
        Some(SsaOp::LoadIndirect {
            dest,
            addr,
            value_type,
        })
    } else {
        None
    }
}

fn stind_typed(uses: &[SsaVarId], value_type: SsaType) -> Option<SsaOp> {
    if let (Some(&addr), Some(&value)) = (uses.first(), uses.get(1)) {
        Some(SsaOp::StoreIndirect {
            addr,
            value,
            value_type,
        })
    } else {
        None
    }
}

// =============================================================================
// Operand extraction helpers
// =============================================================================

fn extract_i32(operand: &Operand) -> Option<i32> {
    match operand {
        Operand::Immediate(Immediate::Int8(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::Int16(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::Int32(v)) => Some(*v),
        Operand::Immediate(Immediate::UInt8(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::UInt16(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::UInt32(v)) => i32::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_i64(operand: &Operand) -> Option<i64> {
    match operand {
        Operand::Immediate(Immediate::Int64(v)) => Some(*v),
        Operand::Immediate(Immediate::UInt64(v)) => i64::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_f32(operand: &Operand) -> Option<f32> {
    match operand {
        Operand::Immediate(Immediate::Float32(v)) => Some(*v),
        _ => None,
    }
}

fn extract_f64(operand: &Operand) -> Option<f64> {
    match operand {
        Operand::Immediate(Immediate::Float64(v)) => Some(*v),
        _ => None,
    }
}

fn extract_u16(operand: &Operand) -> Option<u16> {
    match operand {
        Operand::Immediate(Immediate::UInt8(v)) => Some(u16::from(*v)),
        Operand::Immediate(Immediate::UInt16(v)) | Operand::Argument(v) | Operand::Local(v) => {
            Some(*v)
        }
        Operand::Immediate(Immediate::Int8(v)) => u16::try_from(*v).ok(),
        Operand::Immediate(Immediate::Int16(v)) => u16::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_method_token(operand: &Operand) -> Option<MethodRef> {
    match operand {
        Operand::Token(token) => Some(MethodRef::new(*token)),
        _ => None,
    }
}

fn extract_field_token(operand: &Operand) -> Option<FieldRef> {
    match operand {
        Operand::Token(token) => Some(FieldRef::new(*token)),
        _ => None,
    }
}

fn extract_type_token(operand: &Operand) -> Option<TypeRef> {
    match operand {
        Operand::Token(token) => Some(TypeRef::new(*token)),
        _ => None,
    }
}

fn extract_signature_token(operand: &Operand) -> Option<SigRef> {
    match operand {
        Operand::Token(token) => Some(SigRef::new(*token)),
        _ => None,
    }
}

fn extract_string_token(operand: &Operand) -> Option<u32> {
    match operand {
        Operand::Token(token) => Some(token.value() & 0x00FF_FFFF),
        Operand::Immediate(Immediate::UInt32(v)) => Some(*v),
        _ => None,
    }
}

fn type_ref_to_ssa(_type_ref: TypeRef) -> SsaType {
    // For now, return Unknown - we'd need assembly context to resolve this
    SsaType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{FlowType, InstructionCategory, StackBehavior};

    fn make_instruction(
        opcode: u8,
        prefix: u8,
        mnemonic: &'static str,
        operand: Operand,
        pops: u8,
        pushes: u8,
    ) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode,
            prefix,
            mnemonic,
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand,
            stack_behavior: StackBehavior {
                pops,
                pushes,
                net_effect: i8::try_from(i16::from(pushes) - i16::from(pops)).unwrap_or(0),
            },
            branch_targets: vec![],
        }
    }

    #[test]
    fn test_decompose_add() {
        let instr = make_instruction(0x58, 0, "add", Operand::None, 2, 1);
        let uses = vec![SsaVarId::new(0), SsaVarId::new(1)];
        let def = Some(SsaVarId::new(2));

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Add { dest, left, right }) = op {
            assert_eq!(dest, SsaVarId::new(2));
            assert_eq!(left, SsaVarId::new(0));
            assert_eq!(right, SsaVarId::new(1));
        } else {
            panic!("Expected SsaOp::Add");
        }
    }

    #[test]
    fn test_decompose_ldc_i4_0() {
        let instr = make_instruction(0x16, 0, "ldc.i4.0", Operand::None, 0, 1);
        let uses = vec![];
        let def = Some(SsaVarId::new(0));

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Const { dest, value }) = op {
            assert_eq!(dest, SsaVarId::new(0));
            assert_eq!(value, ConstValue::I32(0));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ldc_i4_s() {
        let instr = make_instruction(
            0x1F,
            0,
            "ldc.i4.s",
            Operand::Immediate(Immediate::Int8(42)),
            0,
            1,
        );
        let uses = vec![];
        let def = Some(SsaVarId::new(0));

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Const { dest, value }) = op {
            assert_eq!(dest, SsaVarId::new(0));
            assert_eq!(value, ConstValue::I32(42));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ret_with_value() {
        let instr = make_instruction(0x2A, 0, "ret", Operand::None, 1, 0);
        let uses = vec![SsaVarId::new(5)];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Return { value }) = op {
            assert_eq!(value, Some(SsaVarId::new(5)));
        } else {
            panic!("Expected SsaOp::Return");
        }
    }

    #[test]
    fn test_decompose_ret_void() {
        let instr = make_instruction(0x2A, 0, "ret", Operand::None, 0, 0);
        let uses = vec![];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Return { value }) = op {
            assert_eq!(value, None);
        } else {
            panic!("Expected SsaOp::Return");
        }
    }

    #[test]
    fn test_decompose_ceq() {
        let instr = make_instruction(0x01, 0xFE, "ceq", Operand::None, 2, 1);
        let uses = vec![SsaVarId::new(0), SsaVarId::new(1)];
        let def = Some(SsaVarId::new(2));

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Ceq { dest, left, right }) = op {
            assert_eq!(dest, SsaVarId::new(2));
            assert_eq!(left, SsaVarId::new(0));
            assert_eq!(right, SsaVarId::new(1));
        } else {
            panic!("Expected SsaOp::Ceq");
        }
    }

    #[test]
    fn test_decompose_nop() {
        let instr = make_instruction(0x00, 0, "nop", Operand::None, 0, 0);
        let uses = vec![];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def);
        assert_eq!(op, Some(SsaOp::Nop));
    }

    #[test]
    fn test_decompose_conv_i4() {
        let instr = make_instruction(0x69, 0, "conv.i4", Operand::None, 1, 1);
        let uses = vec![SsaVarId::new(0)];
        let def = Some(SsaVarId::new(1));

        let op = decompose_instruction(&instr, &uses, def);
        assert!(op.is_some());

        if let Some(SsaOp::Conv {
            dest,
            operand,
            target,
            overflow_check,
            unsigned,
        }) = op
        {
            assert_eq!(dest, SsaVarId::new(1));
            assert_eq!(operand, SsaVarId::new(0));
            assert_eq!(target, SsaType::I32);
            assert!(!overflow_check);
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::Conv");
        }
    }
}
