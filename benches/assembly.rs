#![allow(unused)]
extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::assembly::{
    decode_instruction, decode_stream, InstructionAssembler, InstructionEncoder,
};
use dotscope::metadata::token::Token;
use dotscope::Parser;

pub fn criterion_benchmark(c: &mut Criterion) {
    // Simple method: basic arithmetic
    c.bench_function("bench_assemble_simple_method", |b| {
        b.iter(|| {
            let mut asm = InstructionAssembler::new();
            asm.ldarg_1()
                .unwrap()
                .ldarg_2()
                .unwrap()
                .add()
                .unwrap()
                .ret()
                .unwrap();
            asm.finish().unwrap()
        });
    });

    // Complex method: loops, branches, and object operations
    c.bench_function("bench_assemble_complex_method", |b| {
        b.iter(|| {
            let mut asm = InstructionAssembler::new();
            asm.ldc_i4_0()
                .unwrap() // int i = 0
                .stloc_0()
                .unwrap()
                .br("loop_condition")
                .unwrap()
                .label("loop_start")
                .unwrap()
                .ldarg_0()
                .unwrap() // Load array
                .ldloc_0()
                .unwrap() // Load index
                .ldarg_1()
                .unwrap() // Load value
                .stelem_i4()
                .unwrap() // array[i] = value
                .ldloc_0()
                .unwrap() // i++
                .ldc_i4_1()
                .unwrap()
                .add()
                .unwrap()
                .stloc_0()
                .unwrap()
                .label("loop_condition")
                .unwrap()
                .ldloc_0()
                .unwrap() // if (i < 10)
                .ldc_i4_const(10)
                .unwrap()
                .clt()
                .unwrap()
                .brtrue("loop_start")
                .unwrap()
                .ret()
                .unwrap();
            asm.finish().unwrap()
        });
    });

    // Object-heavy method: field access and method calls
    c.bench_function("bench_assemble_object_method", |b| {
        let field_token = Token::new(0x04000001);
        let method_token = Token::new(0x06000001);
        let type_token = Token::new(0x02000001);

        b.iter(|| {
            let mut asm = InstructionAssembler::new();
            asm.ldarg_0()
                .unwrap() // this
                .ldfld(field_token)
                .unwrap() // Load field
                .ldnull()
                .unwrap() // Compare with null
                .ceq()
                .unwrap()
                .brfalse("not_null")
                .unwrap()
                .ldarg_0()
                .unwrap() // Create new object
                .newobj(method_token)
                .unwrap()
                .stfld(field_token)
                .unwrap()
                .label("not_null")
                .unwrap()
                .ldarg_0()
                .unwrap() // Return field value
                .ldfld(field_token)
                .unwrap()
                .callvirt(method_token)
                .unwrap()
                .ret()
                .unwrap();
            asm.finish().unwrap()
        });
    });

    // Low-level encoder benchmark
    c.bench_function("bench_assemble_encoder_direct", |b| {
        b.iter(|| {
            let mut encoder = InstructionEncoder::new();
            encoder.emit_instruction("ldarg.1", None).unwrap();
            encoder.emit_instruction("ldarg.2", None).unwrap();
            encoder.emit_instruction("add", None).unwrap();
            encoder.emit_instruction("ret", None).unwrap();
            encoder.finalize().unwrap().0
        });
    });

    // Roundtrip benchmark: assemble then disassemble
    let simple_bytecode = {
        let mut asm = InstructionAssembler::new();
        asm.ldarg_1()
            .unwrap()
            .ldarg_2()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();
        asm.finish().unwrap().0
    };

    c.bench_function("bench_roundtrip_simple", |b| {
        b.iter(|| {
            // Assemble
            let mut asm = InstructionAssembler::new();
            asm.ldarg_1()
                .unwrap()
                .ldarg_2()
                .unwrap()
                .add()
                .unwrap()
                .ret()
                .unwrap();
            let (bytecode, _max_stack) = asm.finish().unwrap();

            // Disassemble
            let mut parser = dotscope::Parser::new(&bytecode);
            decode_stream(&mut parser, 0x1000).unwrap()
        });
    });

    let complex_bytecode = {
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br("loop_condition")
            .unwrap()
            .label("loop_start")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .stelem_i4()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("loop_condition")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_const(10)
            .unwrap()
            .clt()
            .unwrap()
            .brtrue("loop_start")
            .unwrap()
            .ret()
            .unwrap();
        asm.finish().unwrap().0
    };

    c.bench_function("bench_roundtrip_complex", |b| {
        b.iter(|| {
            // Assemble
            let mut asm = InstructionAssembler::new();
            asm.ldc_i4_0()
                .unwrap()
                .stloc_0()
                .unwrap()
                .br("loop_condition")
                .unwrap()
                .label("loop_start")
                .unwrap()
                .ldarg_0()
                .unwrap()
                .ldloc_0()
                .unwrap()
                .ldarg_1()
                .unwrap()
                .stelem_i4()
                .unwrap()
                .ldloc_0()
                .unwrap()
                .ldc_i4_1()
                .unwrap()
                .add()
                .unwrap()
                .stloc_0()
                .unwrap()
                .label("loop_condition")
                .unwrap()
                .ldloc_0()
                .unwrap()
                .ldc_i4_const(10)
                .unwrap()
                .clt()
                .unwrap()
                .brtrue("loop_start")
                .unwrap()
                .ret()
                .unwrap();
            let (bytecode, _max_stack) = asm.finish().unwrap();

            // Disassemble
            let mut parser = dotscope::Parser::new(&bytecode);
            decode_stream(&mut parser, 0x1000).unwrap()
        });
    });

    // Disassemble-only benchmarks for comparison
    c.bench_function("bench_disassemble_simple", |b| {
        b.iter(|| {
            let mut parser = dotscope::Parser::new(&simple_bytecode);
            decode_stream(&mut parser, 0x1000).unwrap()
        });
    });

    c.bench_function("bench_disassemble_complex", |b| {
        b.iter(|| {
            let mut parser = dotscope::Parser::new(&complex_bytecode);
            decode_stream(&mut parser, 0x1000).unwrap()
        });
    });

    // Optimization benchmark: compare ldc_i4_const vs manual selection
    c.bench_function("bench_assemble_with_optimizations", |b| {
        b.iter(|| {
            let mut asm = InstructionAssembler::new();
            asm.ldc_i4_const(0)
                .unwrap() // Should use ldc.i4.0
                .ldc_i4_const(1)
                .unwrap() // Should use ldc.i4.1
                .ldc_i4_const(127)
                .unwrap() // Should use ldc.i4.s
                .ldc_i4_const(1000)
                .unwrap() // Should use ldc.i4
                .add()
                .unwrap()
                .add()
                .unwrap()
                .add()
                .unwrap()
                .ret()
                .unwrap();
            asm.finish().unwrap()
        });
    });

    c.bench_function("bench_assemble_manual_selection", |b| {
        b.iter(|| {
            let mut asm = InstructionAssembler::new();
            asm.ldc_i4_0()
                .unwrap()
                .ldc_i4_1()
                .unwrap()
                .ldc_i4_s(127)
                .unwrap()
                .ldc_i4(1000)
                .unwrap()
                .add()
                .unwrap()
                .add()
                .unwrap()
                .add()
                .unwrap()
                .ret()
                .unwrap();
            asm.finish().unwrap()
        });
    });

    // Memory-intensive benchmark: large method with many labels
    c.bench_function("bench_assemble_large_method", |b| {
        b.iter(|| {
            let mut asm = InstructionAssembler::new();

            // Create a method with many branches and labels
            for i in 0..50 {
                asm.ldarg_0()
                    .unwrap()
                    .ldc_i4_const(i)
                    .unwrap()
                    .ceq()
                    .unwrap()
                    .brtrue(&format!("case_{i}"))
                    .unwrap();
            }

            asm.ldc_i4_m1().unwrap().ret().unwrap();

            for i in 0..50 {
                asm.label(&format!("case_{i}"))
                    .unwrap()
                    .ldc_i4_const(i * 2)
                    .unwrap()
                    .ret()
                    .unwrap();
            }

            asm.finish().unwrap()
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
