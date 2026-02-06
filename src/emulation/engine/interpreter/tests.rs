//! Unit tests for the CIL interpreter.
//!
//! This module contains tests for the interpreter's instruction execution,
//! verifying correct behavior for:
//! - Stack operations (nop, dup, pop)
//! - Load constant instructions (ldc.i4.*, ldc.i8, ldc.r4, ldc.r8)
//! - Arithmetic operations (add, sub, mul, div, rem, neg)
//! - Bitwise operations (and, or, xor, not, shl, shr)
//! - Control flow (branch instructions, return)
//! - Local variable access (ldloc, stloc)
//! - Argument access (ldarg)
//! - Type conversions (conv.*)
//! - Execution limits and statistics

use std::sync::Arc;

use crate::{
    assembly::{FlowType, Immediate, InstructionCategory, Operand, StackBehavior},
    emulation::{
        process::EmulationLimits, AddressSpace, CaptureContext, EmulationThread, SharedFakeObjects,
        ThreadId,
    },
    metadata::{token::Token, typesystem::CilFlavor},
    test::emulation::create_test_thread,
};

use super::*;

fn create_test_address_space() -> Arc<AddressSpace> {
    Arc::new(AddressSpace::new())
}

fn create_test_interpreter() -> (Interpreter, Arc<AddressSpace>) {
    let address_space = create_test_address_space();
    let limits = EmulationLimits::default();
    (
        Interpreter::new(limits, Arc::clone(&address_space)),
        address_space,
    )
}

fn create_test_thread_with_locals(local_types: Vec<CilFlavor>) -> EmulationThread {
    let address_space = create_test_address_space();
    let capture = Arc::new(CaptureContext::new());
    let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    let mut thread =
        EmulationThread::new(ThreadId::MAIN, address_space, capture, None, fake_objects);
    thread.start_method(Token::new(0x06000001), local_types, vec![], false);
    thread
}

fn create_test_thread_with_args(
    args: Vec<(EmValue, CilFlavor)>,
    local_types: Vec<CilFlavor>,
) -> EmulationThread {
    let address_space = create_test_address_space();
    let capture = Arc::new(CaptureContext::new());
    let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    let mut thread =
        EmulationThread::new(ThreadId::MAIN, address_space, capture, None, fake_objects);
    thread.start_method(Token::new(0x06000001), local_types, args, false);
    thread
}

fn make_instruction(opcode: u8, mnemonic: &'static str) -> Instruction {
    Instruction {
        rva: 0,
        offset: 0,
        size: 1,
        opcode,
        prefix: 0,
        mnemonic,
        category: InstructionCategory::Misc,
        flow_type: FlowType::Sequential,
        operand: Operand::None,
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: vec![],
    }
}

fn make_instruction_with_operand(
    opcode: u8,
    mnemonic: &'static str,
    operand: Operand,
) -> Instruction {
    Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode,
        prefix: 0,
        mnemonic,
        category: InstructionCategory::Misc,
        flow_type: FlowType::Sequential,
        operand,
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: vec![],
    }
}

#[test]
fn test_nop() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x00, "nop");

    // Create a minimal context - we won't actually use it for nop
    // In real usage, this would be a proper EmulationContext
    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_ldc_i4_constants() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test ldc.i4.0 through ldc.i4.8
    for (opcode, expected) in [
        (0x16, 0),
        (0x17, 1),
        (0x18, 2),
        (0x19, 3),
        (0x1A, 4),
        (0x1B, 5),
        (0x1C, 6),
        (0x1D, 7),
        (0x1E, 8),
    ] {
        thread.stack_mut().clear();
        let instr = make_instruction(opcode, "ldc.i4.*");
        interpreter.execute_standard(&mut thread, &instr).unwrap();

        let value = thread.pop().unwrap();
        assert_eq!(value, EmValue::I32(expected));
    }
}

#[test]
fn test_ldc_i4_m1() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x15, "ldc.i4.m1");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let value = thread.pop().unwrap();
    assert_eq!(value, EmValue::I32(-1));
}

#[test]
fn test_ldnull() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x14, "ldnull");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let value = thread.pop().unwrap();
    assert_eq!(value, EmValue::Null);
}

#[test]
fn test_dup() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x25, "dup");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert_eq!(thread.stack().depth(), 2);
    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
}

#[test]
fn test_pop() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();
    thread.push(EmValue::I32(100)).unwrap();

    let instr = make_instruction(0x26, "pop");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert_eq!(thread.stack().depth(), 1);
    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
}

#[test]
fn test_add() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(10)).unwrap();
    thread.push(EmValue::I32(20)).unwrap();

    let instr = make_instruction(0x58, "add");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(30));
}

#[test]
fn test_sub() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(50)).unwrap();
    thread.push(EmValue::I32(20)).unwrap();

    let instr = make_instruction(0x59, "sub");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(30));
}

#[test]
fn test_mul() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(5)).unwrap();
    thread.push(EmValue::I32(6)).unwrap();

    let instr = make_instruction(0x5A, "mul");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(30));
}

#[test]
fn test_neg() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x65, "neg");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(-42));
}

#[test]
fn test_ldloc_stloc() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread_with_locals(vec![CilFlavor::I4, CilFlavor::I4]);

    // Store 42 in local 0
    thread.push(EmValue::I32(42)).unwrap();
    let stloc0 = make_instruction(0x0A, "stloc.0");
    interpreter.execute_standard(&mut thread, &stloc0).unwrap();

    // Load local 0
    let ldloc0 = make_instruction(0x06, "ldloc.0");
    interpreter.execute_standard(&mut thread, &ldloc0).unwrap();

    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
}

#[test]
fn test_branch_brtrue() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test brtrue with non-zero value (should branch)
    thread.push(EmValue::I32(1)).unwrap();
    let brtrue = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2D,
        prefix: 0,
        mnemonic: "brtrue.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 1,
            pushes: 0,
            net_effect: -1,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &brtrue).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));

    // Test brtrue with zero value (should not branch)
    thread.push(EmValue::I32(0)).unwrap();
    let result = interpreter.execute_standard(&mut thread, &brtrue).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_branch_brfalse() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test brfalse with zero value (should branch)
    thread.push(EmValue::I32(0)).unwrap();
    let brfalse = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2C,
        prefix: 0,
        mnemonic: "brfalse.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 1,
            pushes: 0,
            net_effect: -1,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &brfalse).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));

    // Test brfalse with non-zero value (should not branch)
    thread.push(EmValue::I32(1)).unwrap();
    let result = interpreter.execute_standard(&mut thread, &brfalse).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_conv_i8() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x6A, "conv.i8");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I64(42));
}

#[test]
fn test_execution_stats() {
    let limits = EmulationLimits::new().with_max_instructions(10);
    let address_space = create_test_address_space();
    let mut interpreter = Interpreter::new(limits, address_space);
    interpreter.start();

    // Manually increment the counter to simulate executing instructions
    for _ in 0..5 {
        interpreter.stats_mut().increment_instructions();
    }

    assert_eq!(interpreter.stats().instructions_executed, 5);
}

#[test]
fn test_instruction_limit() {
    let limits = EmulationLimits::new().with_max_instructions(5);
    let address_space = create_test_address_space();
    let mut interpreter = Interpreter::new(limits, address_space);
    interpreter.start();

    // Manually increment the counter to simulate executing instructions
    for _ in 0..5 {
        interpreter.stats_mut().increment_instructions();
    }

    // Check that limits are exceeded (pass call depth 0 - testing instruction limit)
    assert!(interpreter.check_limits(0).is_err());
}

#[test]
fn test_div() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(100)).unwrap();
    thread.push(EmValue::I32(5)).unwrap();

    let instr = make_instruction(0x5B, "div");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(20));
}

#[test]
fn test_rem() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(17)).unwrap();
    thread.push(EmValue::I32(5)).unwrap();

    let instr = make_instruction(0x5D, "rem");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(2));
}

#[test]
fn test_and() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0b1111_0000)).unwrap();
    thread.push(EmValue::I32(0b1010_1010)).unwrap();

    let instr = make_instruction(0x5F, "and");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(0b1010_0000));
}

#[test]
fn test_or() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0b1111_0000)).unwrap();
    thread.push(EmValue::I32(0b0000_1111)).unwrap();

    let instr = make_instruction(0x60, "or");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(0b1111_1111));
}

#[test]
fn test_xor() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0b1111_0000)).unwrap();
    thread.push(EmValue::I32(0b1010_1010)).unwrap();

    let instr = make_instruction(0x61, "xor");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(0b0101_1010));
}

#[test]
fn test_not() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0)).unwrap();

    let instr = make_instruction(0x66, "not");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(-1)); // Bitwise NOT of 0 is all 1s = -1
}

#[test]
fn test_shl() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(1)).unwrap();
    thread.push(EmValue::I32(4)).unwrap();

    let instr = make_instruction(0x62, "shl");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(16)); // 1 << 4 = 16
}

#[test]
fn test_shr() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(64)).unwrap();
    thread.push(EmValue::I32(2)).unwrap();

    let instr = make_instruction(0x63, "shr");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(16)); // 64 >> 2 = 16
}

#[test]
fn test_ret() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x2A, "ret");
    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert!(matches!(result, StepResult::Return { value: None }));
}

#[test]
fn test_break() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x01, "break");
    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert!(matches!(result, StepResult::Breakpoint));
}

#[test]
fn test_br_s() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2B,
        prefix: 0,
        mnemonic: "br.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::UnconditionalBranch,
        operand: Operand::Target(0x50),
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: vec![0x50],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x50 }));
}

#[test]
fn test_ldc_i4_s() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr =
        make_instruction_with_operand(0x1F, "ldc.i4.s", Operand::Immediate(Immediate::Int8(-42)));
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(-42));
}

#[test]
fn test_ldc_i4() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr =
        make_instruction_with_operand(0x20, "ldc.i4", Operand::Immediate(Immediate::Int32(123456)));
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(123456));
}

#[test]
fn test_ldc_i8() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction_with_operand(
        0x21,
        "ldc.i8",
        Operand::Immediate(Immediate::Int64(0x1234_5678_9ABC_DEF0)),
    );
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I64(0x1234_5678_9ABC_DEF0));
}

#[test]
fn test_ldc_r4() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction_with_operand(
        0x22,
        "ldc.r4",
        Operand::Immediate(Immediate::Float32(std::f32::consts::PI)),
    );
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F32(f) = result {
        assert!((f - std::f32::consts::PI).abs() < 0.001);
    } else {
        panic!("Expected F32, got {:?}", result);
    }
}

#[test]
fn test_ldc_r8() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction_with_operand(
        0x23,
        "ldc.r8",
        Operand::Immediate(Immediate::Float64(std::f64::consts::PI)),
    );
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F64(f) = result {
        assert!((f - std::f64::consts::PI).abs() < 0.0000001);
    } else {
        panic!("Expected F64, got {:?}", result);
    }
}

#[test]
fn test_ldarg_0_through_3() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread_with_args(
        vec![
            (EmValue::I32(100), CilFlavor::I4),
            (EmValue::I32(200), CilFlavor::I4),
            (EmValue::I32(300), CilFlavor::I4),
            (EmValue::I32(400), CilFlavor::I4),
        ],
        vec![], // no locals
    );

    // ldarg.0
    let instr = make_instruction(0x02, "ldarg.0");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(100));

    // ldarg.1
    let instr = make_instruction(0x03, "ldarg.1");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(200));

    // ldarg.2
    let instr = make_instruction(0x04, "ldarg.2");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(300));

    // ldarg.3
    let instr = make_instruction(0x05, "ldarg.3");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(400));
}

#[test]
fn test_conv_r4() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x6B, "conv.r4");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F32(f) = result {
        assert!((f - 42.0).abs() < 0.001);
    } else {
        panic!("Expected F32, got {:?}", result);
    }
}

#[test]
fn test_conv_r8() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x6C, "conv.r8");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F64(f) = result {
        assert!((f - 42.0).abs() < 0.0001);
    } else {
        panic!("Expected F64, got {:?}", result);
    }
}

#[test]
fn test_conv_i4() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I64(0x1_0000_002A)).unwrap(); // Value > i32::MAX

    let instr = make_instruction(0x69, "conv.i4");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(42)); // Truncated to lower 32 bits
}

#[test]
fn test_float_arithmetic() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test add with floats
    thread.push(EmValue::F64(1.5)).unwrap();
    thread.push(EmValue::F64(2.5)).unwrap();

    let instr = make_instruction(0x58, "add");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F64(f) = result {
        assert!((f - 4.0).abs() < 0.0001);
    } else {
        panic!("Expected F64, got {:?}", result);
    }
}

#[test]
fn test_i64_arithmetic() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test mul with i64
    thread.push(EmValue::I64(0x1_0000_0000)).unwrap();
    thread.push(EmValue::I64(2)).unwrap();

    let instr = make_instruction(0x5A, "mul");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I64(0x2_0000_0000));
}

#[test]
fn test_beq_s_branches_when_equal() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();
    thread.push(EmValue::I32(42)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2E,
        prefix: 0,
        mnemonic: "beq.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));
}

#[test]
fn test_beq_s_continues_when_not_equal() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();
    thread.push(EmValue::I32(100)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2E,
        prefix: 0,
        mnemonic: "beq.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_bgt_s() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // 50 > 30 should branch
    thread.push(EmValue::I32(50)).unwrap();
    thread.push(EmValue::I32(30)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x30,
        prefix: 0,
        mnemonic: "bgt.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));

    // 30 > 50 should not branch
    thread.push(EmValue::I32(30)).unwrap();
    thread.push(EmValue::I32(50)).unwrap();

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_blt_s() {
    let (interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // 30 < 50 should branch
    thread.push(EmValue::I32(30)).unwrap();
    thread.push(EmValue::I32(50)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x32,
        prefix: 0,
        mnemonic: "blt.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));
}
