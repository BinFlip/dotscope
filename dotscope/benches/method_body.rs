//! Benchmarks for method body parsing.
//!
//! Tests parsing performance for various method body formats:
//! - Tiny headers (1 byte, up to 63 bytes code)
//! - Fat headers (12+ bytes, complex methods)
//! - Exception handlers (try/catch/finally blocks)

extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::metadata::method::MethodBody;
use std::{fs, hint::black_box, path::PathBuf};

/// Run a method-body parsing benchmark over a sample file. Skips with a
/// diagnostic message when the file cannot be read.
fn bench_method_file(c: &mut Criterion, group_name: &str, sample: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(sample);

    let Ok(data) = fs::read(&path) else {
        eprintln!("Skipping {group_name}: failed to read {}", path.display());
        return;
    };
    let file_size = data.len();

    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(MethodBody::from(black_box(&data)).ok());
        });
    });
    group.finish();
}

/// Benchmark parsing a tiny method header.
///
/// Tiny headers are 1 byte and can represent methods up to 63 bytes of IL code.
/// This is the fastest path for simple methods.
fn bench_parse_method_tiny(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_tiny",
        "tests/samples/WB_METHOD_TINY_0600032D.bin",
    );
}

/// Benchmark parsing a fat method header.
///
/// Fat headers are 12+ bytes and support complex methods with local variables,
/// exception handlers, and large code sizes.
fn bench_parse_method_fat(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_fat",
        "tests/samples/WB_METHOD_FAT_0600033E.bin",
    );
}

/// Benchmark parsing a method with a single exception handler.
///
/// Tests the overhead of parsing exception handling sections.
fn bench_parse_method_with_exception(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_exception_single",
        "tests/samples/WB_METHOD_FAT_EXCEPTION_06000341.bin",
    );
}

/// Benchmark parsing a method with local variables and exception handlers.
///
/// Tests a more realistic complex method scenario.
fn bench_parse_method_with_locals_and_exception(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_with_locals",
        "tests/samples/WB_METHOD_FAT_EXCEPTION_N1_2LOCALS_060001AA.bin",
    );
}

/// Benchmark parsing a method with multiple exception handlers.
///
/// Tests parsing of complex exception handling with multiple try/catch/finally blocks.
fn bench_parse_method_multiple_exceptions(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_exception_multiple",
        "tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000421.bin",
    );
}

/// Benchmark parsing another complex method with nested exception handlers.
fn bench_parse_method_complex_exceptions(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_exception_complex",
        "tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000D54.bin",
    );
}

criterion_group!(
    benches,
    bench_parse_method_tiny,
    bench_parse_method_fat,
    bench_parse_method_with_exception,
    bench_parse_method_with_locals_and_exception,
    bench_parse_method_multiple_exceptions,
    bench_parse_method_complex_exceptions,
);
criterion_main!(benches);
