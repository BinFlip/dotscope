use std::sync::Arc;

use super::*;
use crate::{
    analysis::{CallGraph, SsaFunctionBuilder, SsaType},
    metadata::typesystem::PointerSize,
    test::helpers::test_assembly_arc,
};

/// Creates a test compiler context.
fn test_context() -> CompilerContext {
    let call_graph = Arc::new(CallGraph::new());
    CompilerContext::new(call_graph)
}

#[test]
fn test_pass_creation() {
    let pass = ConstantPropagationPass::new();
    assert_eq!(pass.name(), "constant-propagation");
    assert!(!pass.description().is_empty());
}

#[test]
fn test_pass_default() {
    let pass = ConstantPropagationPass;
    assert_eq!(pass.name(), "constant-propagation");
}

#[test]
fn test_conv_i32_to_i8() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::I8, false, PointerSize::Bit64),
        Some(ConstValue::I8(42))
    );
}

#[test]
fn test_conv_i32_to_i8_truncate() {
    let operand = ConstValue::I32(1000);
    // 1000 truncated to i8 is -24 (1000 & 0xFF = 232, as signed = -24)
    assert_eq!(
        operand.convert_to(&SsaType::I8, false, PointerSize::Bit64),
        Some(ConstValue::I8(-24))
    );
}

#[test]
fn test_conv_i32_to_i64() {
    let operand = ConstValue::I32(-42);
    assert_eq!(
        operand.convert_to(&SsaType::I64, false, PointerSize::Bit64),
        Some(ConstValue::I64(-42))
    );
}

#[test]
fn test_conv_to_bool_nonzero() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::Bool, false, PointerSize::Bit64),
        Some(ConstValue::True)
    );
}

#[test]
fn test_conv_to_bool_zero() {
    let operand = ConstValue::I32(0);
    assert_eq!(
        operand.convert_to(&SsaType::Bool, false, PointerSize::Bit64),
        Some(ConstValue::False)
    );
}

#[test]
fn test_conv_to_f32() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::F32, false, PointerSize::Bit64),
        Some(ConstValue::F32(42.0))
    );
}

#[test]
fn test_conv_ovf_in_range() {
    let operand = ConstValue::I32(100);
    assert_eq!(
        operand.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64),
        Some(ConstValue::I8(100))
    );
}

#[test]
fn test_conv_ovf_out_of_range() {
    let operand = ConstValue::I32(1000);
    assert_eq!(
        operand.convert_to_checked(&SsaType::I8, false, PointerSize::Bit64),
        None
    ); // Would overflow
}

#[test]
fn test_conv_u8() {
    let operand = ConstValue::I32(200);
    assert_eq!(
        operand.convert_to(&SsaType::U8, false, PointerSize::Bit64),
        Some(ConstValue::U8(200))
    );
}

#[test]
fn test_conv_u16() {
    let operand = ConstValue::I32(50000);
    assert_eq!(
        operand.convert_to(&SsaType::U16, false, PointerSize::Bit64),
        Some(ConstValue::U16(50000))
    );
}

#[test]
fn test_conv_u32() {
    let operand = ConstValue::I64(3_000_000_000);
    assert_eq!(
        operand.convert_to(&SsaType::U32, false, PointerSize::Bit64),
        Some(ConstValue::U32(3_000_000_000))
    );
}

#[test]
fn test_conv_u64() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::U64, false, PointerSize::Bit64),
        Some(ConstValue::U64(42))
    );
}

#[test]
fn test_conv_f64() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::F64, false, PointerSize::Bit64),
        Some(ConstValue::F64(42.0))
    );
}

#[test]
fn test_conv_native_int() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::NativeInt, false, PointerSize::Bit64),
        Some(ConstValue::NativeInt(42))
    );
}

#[test]
fn test_conv_native_uint() {
    let operand = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::NativeUInt, false, PointerSize::Bit64),
        Some(ConstValue::NativeUInt(42))
    );
}

#[test]
fn test_conv_char() {
    let operand = ConstValue::I32(65); // 'A'
    assert_eq!(
        operand.convert_to(&SsaType::Char, false, PointerSize::Bit64),
        Some(ConstValue::U16(65))
    );
}

#[test]
fn test_identity_add_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Add {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    // Result should be a Copy to v0 (since v0 has value 42, not a zero)
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_mul_one() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(1));

    let op = SsaOp::Mul {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_and_minus_one() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(-1));

    let op = SsaOp::And {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_absorbing_mul_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Mul {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Constant { dest, value }) => {
            assert_eq!(dest, v2);
            assert_eq!(value, ConstValue::I32(0));
        }
        _ => panic!("Expected Constant result"),
    }
}

#[test]
fn test_absorbing_and_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::And {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Constant { dest, value }) => {
            assert_eq!(dest, v2);
            assert_eq!(value, ConstValue::I32(0));
        }
        _ => panic!("Expected Constant result"),
    }
}

#[test]
fn test_absorbing_or_minus_one() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(-1));

    let op = SsaOp::Or {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Constant { dest, value }) => {
            assert_eq!(dest, v2);
            assert_eq!(value, ConstValue::I32(-1));
        }
        _ => panic!("Expected Constant result"),
    }
}

#[test]
fn test_add_ovf_no_overflow() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(100));
    constants.insert(v1, ConstValue::I32(50));

    let op = SsaOp::AddOvf {
        dest: v2,
        left: v0,
        right: v1,
        unsigned: false,
    };

    let result = ConstantPropagationPass::check_overflow_op(&op, &constants, PointerSize::Bit64);
    assert!(result.is_some());
}

#[test]
fn test_mul_ovf_with_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(100));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::MulOvf {
        dest: v2,
        left: v0,
        right: v1,
        unsigned: false,
    };

    // x * 0 = 0, even with overflow check
    let result = ConstantPropagationPass::check_overflow_op(&op, &constants, PointerSize::Bit64);
    assert_eq!(result, Some((v2, ConstValue::I32(0))));
}

#[test]
fn test_pass_empty_function() {
    let pass = ConstantPropagationPass::new();
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|_f| {});
    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_pass_simple_folding() {
    let pass = ConstantPropagationPass::new();
    // Create a block with: v0 = 5, v1 = 3, v2 = add v0, v1
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
        f.block(0, |b| {
            let v0 = b.const_i32(5);
            let v1 = b.const_i32(3);
            let _v2 = b.add(v0, v1);
            b.ret();
        });
    });

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that v2 was folded to constant 8
    let changed = result.unwrap();
    assert!(changed);

    // Verify the instruction was replaced
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::Const { value, .. } = instr.op() {
        assert_eq!(*value, ConstValue::I32(8));
    } else {
        panic!("Expected Const instruction");
    }
}

#[test]
fn test_pass_branch_simplification() {
    let pass = ConstantPropagationPass::new();
    // Block 0: v0 = true, branch v0, B1, B2
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
        f.block(0, |b| {
            let cond = b.const_true();
            b.branch(cond, 1, 2);
        });
        f.block(1, |b| b.ret());
        f.block(2, |b| b.ret());
    });

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that branch was simplified to jump
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.terminator_op() {
        assert_eq!(*target, 1);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_pass_switch_simplification() {
    let pass = ConstantPropagationPass::new();
    // Block 0: v0 = 1, switch v0, [B1, B2, B3], default=B4
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
        f.block(0, |b| {
            let v0 = b.const_i32(1);
            b.switch(v0, vec![1, 2, 3], 4);
        });
        // Blocks 1-4: return
        f.block(1, |b| b.ret());
        f.block(2, |b| b.ret());
        f.block(3, |b| b.ret());
        f.block(4, |b| b.ret());
    });

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that switch was simplified to jump to target 2 (index 1)
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.terminator_op() {
        assert_eq!(*target, 2);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_constants_cached_in_context() {
    let pass = ConstantPropagationPass::new();
    let (mut ssa, v0) = {
        let mut v0_out = SsaVarId::new();
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(42);
                v0_out = v0;
                b.ret_val(v0);
            });
        });
        (ssa, v0_out)
    };

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that constant was cached
    assert!(ctx.known_value_is(method_token, v0, |v| *v == ConstValue::I32(42)));
}

#[test]
fn test_identity_shl_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Shl {
        dest: v2,
        value: v0,
        amount: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_shr_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Shr {
        dest: v2,
        value: v0,
        amount: v1,
        unsigned: false,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_xor_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Xor {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_div_one() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(1));

    let op = SsaOp::Div {
        dest: v2,
        left: v0,
        right: v1,
        unsigned: false,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_sub_zero() {
    let mut constants = HashMap::new();
    let v0 = SsaVarId::new();
    let v1 = SsaVarId::new();
    let v2 = SsaVarId::new();
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Sub {
        dest: v2,
        left: v0,
        right: v1,
    };

    let result = ConstantPropagationPass::check_algebraic_identity(&op, &constants);
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_chained_constant_folding() {
    let pass = ConstantPropagationPass::new();
    // v0 = 2, v1 = 3, v2 = v0 + v1, v3 = 2, v4 = v2 * v3, v5 = 0, v6 = v4 + v5
    let (mut ssa, v4) = {
        let mut v4_out = SsaVarId::new();
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(2);
                let v1 = b.const_i32(3);
                let v2 = b.add(v0, v1); // v2 = 5
                let v3 = b.const_i32(2);
                let v4 = b.mul(v2, v3); // v4 = 10
                v4_out = v4;
                let v5 = b.const_i32(0);
                // Now add v4 + 0 (identity) - should fold to 10
                let v6 = b.add(v4, v5);
                b.ret_val(v6);
            });
        });
        (ssa, v4_out)
    };

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that v4 was folded to 10
    assert!(ctx.known_value_is(method_token, v4, |v| *v == ConstValue::I32(10)));
}

#[test]
fn test_branch_false_condition() {
    let pass = ConstantPropagationPass::new();
    // Block 0: v0 = false, branch v0, B1, B2
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
        f.block(0, |b| {
            let cond = b.const_false();
            b.branch(cond, 1, 2);
        });
        f.block(1, |b| b.ret());
        f.block(2, |b| b.ret());
    });

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that branch was simplified to jump to false branch (target 2)
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.terminator_op() {
        assert_eq!(*target, 2);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_switch_out_of_range_uses_default() {
    let pass = ConstantPropagationPass::new();
    // Block 0: v0 = 100 (out of range), switch v0, [B1, B2, B3], default=B4
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
        f.block(0, |b| {
            let v0 = b.const_i32(100); // Out of range
            b.switch(v0, vec![1, 2, 3], 4);
        });
        // Blocks 1-4: return
        f.block(1, |b| b.ret());
        f.block(2, |b| b.ret());
        f.block(3, |b| b.ret());
        f.block(4, |b| b.ret());
    });

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = pass.run_on_method(&mut ssa, method_token, &ctx, &test_assembly_arc());
    assert!(result.is_ok());

    // Check that switch was simplified to jump to default (target 4)
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.terminator_op() {
        assert_eq!(*target, 4);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_types_match_identical() {
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I64,
        &SsaType::I64
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::F32,
        &SsaType::F32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::F64,
        &SsaType::F64
    ));
}

#[test]
fn test_types_match_stack_equivalence() {
    // Small integers promote to I32 on the stack
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I8,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U8,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I16,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U16,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::Bool,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::Char,
        &SsaType::I32
    ));

    // U32 and I32 are interchangeable
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U32,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::U32
    ));

    // I64 and U64 are interchangeable
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I64,
        &SsaType::U64
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U64,
        &SsaType::I64
    ));

    // Native int types
    assert!(ConstantPropagationPass::types_match(
        &SsaType::NativeInt,
        &SsaType::NativeUInt
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::NativeUInt,
        &SsaType::NativeInt
    ));
}

#[test]
fn test_types_no_match() {
    // Floats don't match integers
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::F32,
        &SsaType::I32
    ));
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::F32
    ));

    // Different sizes don't match
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::I64
    ));
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::I64,
        &SsaType::I32
    ));
}

#[test]
fn test_is_safe_widening_chain_same_sign() {
    // Unsigned widening: source <= inner < outer
    // conv.u32(conv.u8(x)) where x is u8 - both conversions widen
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U8,  // inner target (same as source - no-op)
        &SsaType::U32, // outer target
        true,
        true
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U16, // inner target
        &SsaType::U64, // outer target
        true,
        true
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U16, // source
        &SsaType::U32, // inner target
        &SsaType::U64, // outer target
        true,
        true
    ));

    // Signed widening: source <= inner < outer
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I8,  // inner target
        &SsaType::I32, // outer target
        false,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I16, // inner target
        &SsaType::I64, // outer target
        false,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I16, // source
        &SsaType::I32, // inner target
        &SsaType::I64, // outer target
        false,
        false
    ));
}

#[test]
fn test_is_safe_widening_chain_unsigned_to_signed() {
    // unsigned to signed widening is safe (zero extend then reinterpret)
    // conv.i32(conv.u8(x)) where x is u8
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U8,  // inner target
        &SsaType::I32, // outer target
        true,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U16, // inner target
        &SsaType::I64, // outer target
        true,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U16, // source
        &SsaType::U32, // inner target
        &SsaType::I64, // outer target
        true,
        false
    ));
}

#[test]
fn test_is_safe_widening_chain_signed_to_unsigned() {
    // signed to unsigned widening is NOT safe (sign extend vs zero extend)
    // conv.u32(conv.i8(x)) where x is i8 - inner is signed, outer is unsigned
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I8,  // inner target
        &SsaType::U32, // outer target
        false,
        true
    ));
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I16, // inner target
        &SsaType::U64, // outer target
        false,
        true
    ));
}

#[test]
fn test_is_safe_widening_chain_narrowing_rejected() {
    // Outer narrowing is NOT safe - inner >= outer means data loss
    // conv.i32(conv.i64(x)) where x is i32 - outer narrows from i64 to i32
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I32, // source
        &SsaType::I64, // inner target
        &SsaType::I32, // outer target (narrowing!)
        false,
        false
    ));
    // conv.u8(conv.u32(x)) where x is u8 - outer narrows from u32 to u8
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U32, // inner target
        &SsaType::U8,  // outer target (narrowing!)
        true,
        true
    ));

    // Inner narrowing is also NOT safe - source > inner means truncation
    // conv.i32(conv.u1(x)) where x is i32 - inner truncates i32 to u8
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I32, // source (larger than inner!)
        &SsaType::U8,  // inner target (truncates source)
        &SsaType::I32, // outer target
        true,
        false
    ));
}

#[test]
fn test_is_safe_widening_chain_float_rejected() {
    // Float conversions are NOT safe - precision loss
    // conv.f64(conv.f32(x)) - float widening can lose precision
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::F32, // source
        &SsaType::F32, // inner target
        &SsaType::F64, // outer target
        false,
        false
    ));
    // conv.f64(conv.i32(x)) - int to float conversion
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I32, // source
        &SsaType::I32, // inner target
        &SsaType::F64, // outer target
        false,
        false
    ));
}

#[test]
fn test_duplicate_conversion_elimination() {
    // conv.i4(conv.i4(v0)) should become conv.i4(v0)
    let (mut ssa, v0) = {
        let mut v0_out = SsaVarId::new();
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                // v0 = some value (simulated by const for simplicity)
                let v0 = b.const_i64(42);
                v0_out = v0;
                // v1 = conv.i4 v0
                let v1 = b.conv(v0, SsaType::I32);
                // v2 = conv.i4 v1 (duplicate!)
                let v2 = b.conv(v1, SsaType::I32);
                b.ret_val(v2);
            });
        });
        (ssa, v0_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should now be conv.i4(v0), not conv.i4(v1)
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::Conv { operand, .. } = instr.op() {
        assert_eq!(
            *operand, v0,
            "Duplicate conversion should use original operand"
        );
    } else {
        panic!("Expected Conv instruction");
    }
}

#[test]
fn test_widening_chain_elimination() {
    // conv.i8(conv.i4(v0)) should become conv.i8(v0) when unsigned
    let (mut ssa, v0) = {
        let mut v0_out = SsaVarId::new();
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                // v0 = some value
                let v0 = b.const_val(ConstValue::U8(42));
                v0_out = v0;
                // v1 = conv.u4 v0 (u8 -> u32)
                let v1 = b.conv_un(v0, SsaType::U32);
                // v2 = conv.u8 v1 (u32 -> u64 widening chain)
                let v2 = b.conv_un(v1, SsaType::U64);
                b.ret_val(v2);
            });
        });
        (ssa, v0_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should now be conv.u8(v0), not conv.u8(v1)
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::Conv {
        operand, target, ..
    } = instr.op()
    {
        assert_eq!(*operand, v0, "Widening chain should use original operand");
        assert_eq!(*target, SsaType::U64);
    } else {
        panic!("Expected Conv instruction");
    }
}

#[test]
fn test_overflow_checked_conversion_not_eliminated() {
    // conv.ovf.i4(conv.i4(v0)) should NOT eliminate the outer conversion
    let (mut ssa, v1) = {
        let mut v1_out = SsaVarId::new();
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i64(42);
                // v1 = conv.i4 v0
                let v1 = b.conv(v0, SsaType::I32);
                v1_out = v1;
                // v2 = conv.ovf.i4 v1 (overflow check!)
                let v2 = b.conv_ovf(v1, SsaType::I32);
                b.ret_val(v2);
            });
        });
        (ssa, v1_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should still be conv.ovf.i4(v1), not modified
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::Conv {
        operand,
        overflow_check,
        ..
    } = instr.op()
    {
        assert_eq!(
            *operand, v1,
            "Overflow-checked conversion should not be modified"
        );
        assert!(*overflow_check);
    } else {
        panic!("Expected Conv instruction");
    }
}

#[test]
fn test_float_widening_not_eliminated() {
    // conv.r8(conv.r4(v0)) should NOT be simplified (precision loss)
    let (mut ssa, v1) = {
        let mut v1_out = SsaVarId::new();
        let ssa = SsaFunctionBuilder::new(0, 0).build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(42);
                // v1 = conv.r4 v0 (int -> float32)
                let v1 = b.conv(v0, SsaType::F32);
                v1_out = v1;
                // v2 = conv.r8 v1 (float32 -> float64, can lose precision info!)
                let v2 = b.conv(v1, SsaType::F64);
                b.ret_val(v2);
            });
        });
        (ssa, v1_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should still use v1, not v0
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::Conv { operand, .. } = instr.op() {
        assert_eq!(
            *operand, v1,
            "Float conversion chain should not be simplified"
        );
    } else {
        panic!("Expected Conv instruction");
    }
}
