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

/// Benchmark parsing a tiny method header.
///
/// Tiny headers are 1 byte and can represent methods up to 63 bytes of IL code.
/// This is the fastest path for simple methods.
fn bench_parse_method_tiny(c: &mut Criterion) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WB_METHOD_TINY_0600032D.bin");

    let data = fs::read(&path).expect("Failed to read tiny method file");
    let file_size = data.len();

    let mut group = c.benchmark_group("method_body_tiny");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(&data)).unwrap();
            black_box(body)
        });
    });
    group.finish();
}

/// Benchmark parsing a fat method header.
///
/// Fat headers are 12+ bytes and support complex methods with local variables,
/// exception handlers, and large code sizes.
fn bench_parse_method_fat(c: &mut Criterion) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WB_METHOD_FAT_0600033E.bin");

    let data = fs::read(&path).expect("Failed to read fat method file");
    let file_size = data.len();

    let mut group = c.benchmark_group("method_body_fat");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(&data)).unwrap();
            black_box(body)
        });
    });
    group.finish();
}

/// Benchmark parsing a method with a single exception handler.
///
/// Tests the overhead of parsing exception handling sections.
fn bench_parse_method_with_exception(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples/WB_METHOD_FAT_EXCEPTION_06000341.bin");

    let data = fs::read(&path).expect("Failed to read method with exception file");
    let file_size = data.len();

    let mut group = c.benchmark_group("method_body_exception_single");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(&data)).unwrap();
            black_box(body)
        });
    });
    group.finish();
}

/// Benchmark parsing a method with local variables and exception handlers.
///
/// Tests a more realistic complex method scenario.
fn bench_parse_method_with_locals_and_exception(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples/WB_METHOD_FAT_EXCEPTION_N1_2LOCALS_060001AA.bin");

    let data = fs::read(&path).expect("Failed to read method with locals file");
    let file_size = data.len();

    let mut group = c.benchmark_group("method_body_with_locals");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(&data)).unwrap();
            black_box(body)
        });
    });
    group.finish();
}

/// Benchmark parsing a method with multiple exception handlers.
///
/// Tests parsing of complex exception handling with multiple try/catch/finally blocks.
fn bench_parse_method_multiple_exceptions(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000421.bin");

    let data = fs::read(&path).expect("Failed to read method with multiple exceptions file");
    let file_size = data.len();

    let mut group = c.benchmark_group("method_body_exception_multiple");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(&data)).unwrap();
            black_box(body)
        });
    });
    group.finish();
}

/// Benchmark parsing another complex method with nested exception handlers.
fn bench_parse_method_complex_exceptions(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples/WB_METHOD_FAT_EXCEPTION_N2_06000D54.bin");

    let data = fs::read(&path).expect("Failed to read complex exception method file");
    let file_size = data.len();

    let mut group = c.benchmark_group("method_body_exception_complex");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(&data)).unwrap();
            black_box(body)
        });
    });
    group.finish();
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
