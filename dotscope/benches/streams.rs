//! Benchmarks for metadata stream parsing.
//!
//! Tests parsing performance for .NET metadata heaps:
//! - #Strings heap (UTF-8 identifiers)
//! - #Blob heap (binary data, signatures)
//! - #US heap (UTF-16 user strings)
//! - #GUID heap (16-byte GUIDs)
//!
//! Includes both construction/parsing and access pattern benchmarks.

extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::metadata::streams::{Blob, Guid, Strings, UserStrings};
use std::{fs, hint::black_box, path::PathBuf};

/// Read a sample file from the workspace samples directory. Returns `None`
/// (with a stderr diagnostic) if the file is missing, so benchmarks can be
/// skipped without panicking.
fn read_sample(name: &str) -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    match fs::read(&path) {
        Ok(data) => Some(data),
        Err(err) => {
            eprintln!(
                "Skipping benchmark: failed to read {}: {err}",
                path.display()
            );
            None
        }
    }
}

/// Benchmark parsing the complete #Strings heap.
fn bench_strings_heap_parse(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_STRINGS.bin") else {
        return;
    };
    let file_size = data.len();

    let mut group = c.benchmark_group("strings_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(Strings::from(black_box(&data)).ok());
        });
    });
    group.finish();
}

/// Benchmark iterating over all strings in the heap.
fn bench_strings_heap_iterate(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_STRINGS.bin") else {
        return;
    };
    let Ok(strings) = Strings::from(&data) else {
        eprintln!("Skipping iterate: failed to parse strings heap");
        return;
    };

    let string_count = strings.iter().count();

    let mut group = c.benchmark_group("strings_heap");
    group.throughput(Throughput::Elements(string_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&strings).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to strings by offset.
fn bench_strings_heap_random_access(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_STRINGS.bin") else {
        return;
    };
    let Ok(strings) = Strings::from(&data) else {
        eprintln!("Skipping random_access: failed to parse strings heap");
        return;
    };

    let offsets: Vec<usize> = strings.iter().map(|(offset, _)| offset).collect();

    let mut group = c.benchmark_group("strings_heap");
    group.throughput(Throughput::Elements(offsets.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &offset in black_box(&offsets) {
                let _ = black_box(strings.get(offset));
            }
        });
    });
    group.finish();
}

/// Benchmark parsing the complete #Blob heap.
fn bench_blob_heap_parse(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_BLOB.bin") else {
        return;
    };
    let file_size = data.len();

    let mut group = c.benchmark_group("blob_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(Blob::from(black_box(&data)).ok());
        });
    });
    group.finish();
}

/// Benchmark iterating over all blobs in the heap.
fn bench_blob_heap_iterate(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_BLOB.bin") else {
        return;
    };
    let Ok(blob) = Blob::from(&data) else {
        eprintln!("Skipping iterate: failed to parse blob heap");
        return;
    };

    let blob_count = blob.iter().count();

    let mut group = c.benchmark_group("blob_heap");
    group.throughput(Throughput::Elements(blob_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&blob).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to blobs by offset.
fn bench_blob_heap_random_access(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_BLOB.bin") else {
        return;
    };
    let Ok(blob) = Blob::from(&data) else {
        eprintln!("Skipping random_access: failed to parse blob heap");
        return;
    };

    let offsets: Vec<usize> = blob.iter().map(|(offset, _)| offset).collect();

    let mut group = c.benchmark_group("blob_heap");
    group.throughput(Throughput::Elements(offsets.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &offset in black_box(&offsets) {
                let _ = black_box(blob.get(offset));
            }
        });
    });
    group.finish();
}

/// Benchmark parsing the complete #US (User Strings) heap.
fn bench_userstrings_heap_parse(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_US.bin") else {
        return;
    };
    let file_size = data.len();

    let mut group = c.benchmark_group("userstrings_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(UserStrings::from(black_box(&data)).ok());
        });
    });
    group.finish();
}

/// Benchmark iterating over all user strings in the heap.
fn bench_userstrings_heap_iterate(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_US.bin") else {
        return;
    };
    let Ok(us) = UserStrings::from(&data) else {
        eprintln!("Skipping iterate: failed to parse user strings heap");
        return;
    };

    let string_count = us.iter().count();

    let mut group = c.benchmark_group("userstrings_heap");
    group.throughput(Throughput::Elements(string_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&us).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to user strings by offset.
fn bench_userstrings_heap_random_access(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_US.bin") else {
        return;
    };
    let Ok(us) = UserStrings::from(&data) else {
        eprintln!("Skipping random_access: failed to parse user strings heap");
        return;
    };

    let offsets: Vec<usize> = us.iter().map(|(offset, _)| offset).collect();

    let mut group = c.benchmark_group("userstrings_heap");
    group.throughput(Throughput::Elements(offsets.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &offset in black_box(&offsets) {
                let _ = black_box(us.get(offset));
            }
        });
    });
    group.finish();
}

/// Benchmark parsing the complete #GUID heap.
fn bench_guid_heap_parse(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_GUID.bin") else {
        return;
    };
    let file_size = data.len();

    let mut group = c.benchmark_group("guid_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(Guid::from(black_box(&data)).ok());
        });
    });
    group.finish();
}

/// Benchmark iterating over all GUIDs in the heap.
fn bench_guid_heap_iterate(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_GUID.bin") else {
        return;
    };
    let Ok(guid) = Guid::from(&data) else {
        eprintln!("Skipping iterate: failed to parse GUID heap");
        return;
    };

    let guid_count = guid.iter().count();

    let mut group = c.benchmark_group("guid_heap");
    group.throughput(Throughput::Elements(guid_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&guid).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to GUIDs by index (1-based as per ECMA-335).
fn bench_guid_heap_random_access(c: &mut Criterion) {
    let Some(data) = read_sample("tests/samples/WB_GUID.bin") else {
        return;
    };
    let Ok(guid) = Guid::from(&data) else {
        eprintln!("Skipping random_access: failed to parse GUID heap");
        return;
    };

    let indices: Vec<usize> = guid.iter().map(|(idx, _)| idx).collect();

    let mut group = c.benchmark_group("guid_heap");
    group.throughput(Throughput::Elements(indices.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &index in black_box(&indices) {
                let _ = black_box(guid.get(index));
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    // Strings heap
    bench_strings_heap_parse,
    bench_strings_heap_iterate,
    bench_strings_heap_random_access,
    // Blob heap
    bench_blob_heap_parse,
    bench_blob_heap_iterate,
    bench_blob_heap_random_access,
    // User strings heap
    bench_userstrings_heap_parse,
    bench_userstrings_heap_iterate,
    bench_userstrings_heap_random_access,
    // GUID heap
    bench_guid_heap_parse,
    bench_guid_heap_iterate,
    bench_guid_heap_random_access,
);
criterion_main!(benches);
