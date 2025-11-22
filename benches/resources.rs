#![allow(unused)]
extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::metadata::resources::{parse_dotnet_resource, parse_dotnet_resource_ref};
use std::{fs, hint::black_box, path::PathBuf};

/// Benchmark parsing from standalone .resources file (WindowsBase resources)
///
/// This benchmark compares the performance of owned vs zero-copy resource parsing
/// using a real .NET resources file extracted from WindowsBase.dll.
fn bench_parse_resources_file(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples/WB_FxResources.WindowsBase.SR.resources.bin");

    // Load the standalone .resources file
    let data = fs::read(&path).expect("Failed to read resources file");
    let file_size = data.len();

    println!(
        "Benchmarking resource file: {} bytes ({:.2} KB)",
        file_size,
        file_size as f64 / 1024.0
    );

    // Benchmark owned variant (allocates copies of strings and byte arrays)
    let mut group = c.benchmark_group("resources_owned");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse_dotnet_resource", |b| {
        b.iter(|| {
            let parsed = parse_dotnet_resource(black_box(&data)).unwrap();
            black_box(parsed)
        });
    });
    group.finish();

    // Benchmark zero-copy variant (borrows strings and byte arrays from source)
    let mut group = c.benchmark_group("resources_zerocopy");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse_dotnet_resource_ref", |b| {
        b.iter(|| {
            let parsed = parse_dotnet_resource_ref(black_box(&data)).unwrap();
            black_box(parsed)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_parse_resources_file);
criterion_main!(benches);
