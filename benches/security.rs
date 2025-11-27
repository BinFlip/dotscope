//! Benchmarks for security/permission set parsing.
//!
//! Tests parsing performance for .NET declarative security attributes
//! which define code access security permissions.

extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::metadata::security::PermissionSet;
use std::{fs, hint::black_box, path::PathBuf};

/// Benchmark parsing a real declarative security blob from WindowsBase.dll.
///
/// This tests parsing of the binary format used by modern .NET assemblies
/// for encoding security permissions.
fn bench_permission_set_parse(c: &mut Criterion) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WB_DeclSecurity_1.bin");

    let data = fs::read(&path).expect("Failed to read security declaration file");
    let file_size = data.len();

    let mut group = c.benchmark_group("permission_set");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse_binary", |b| {
        b.iter(|| {
            let perm_set = PermissionSet::new(black_box(&data)).unwrap();
            black_box(perm_set)
        });
    });
    group.finish();
}

/// Benchmark parsing a simple binary permission set (crafted).
///
/// This is a minimal valid binary format permission set with a single
/// permission containing no properties.
fn bench_permission_set_minimal(c: &mut Criterion) {
    // Binary format: '.' marker, permission count (1), empty permission
    // Format: [0x2E][count=1][class_name_len=10]["TestClass\0"][blob_len=1][prop_count=0]
    let data = [
        0x2E, // '.' format marker
        0x01, // 1 permission
        0x09, // class name length (compressed)
        b'T', b'e', b's', b't', b'C', b'l', b'a', b's', b's', // "TestClass"
        0x01, // blob length
        0x00, // 0 properties
    ];

    c.bench_function("permission_set_minimal", |b| {
        b.iter(|| {
            let perm_set = PermissionSet::new(black_box(&data)).unwrap();
            black_box(perm_set)
        });
    });
}

/// Benchmark parsing an XML format permission set.
///
/// Some older assemblies use XML format for declarative security.
fn bench_permission_set_xml_minimal(c: &mut Criterion) {
    // Minimal valid XML permission set
    let data = b"<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\"/>";

    c.bench_function("permission_set_xml_minimal", |b| {
        b.iter(|| {
            let perm_set = PermissionSet::new(black_box(data)).unwrap();
            black_box(perm_set)
        });
    });
}

/// Benchmark parsing an XML permission set with permissions.
fn bench_permission_set_xml_with_permission(c: &mut Criterion) {
    let data = br#"<PermissionSet class="System.Security.PermissionSet" version="1">
<IPermission class="System.Security.Permissions.SecurityPermission, mscorlib" version="1" Flags="UnmanagedCode"/>
</PermissionSet>"#;

    c.bench_function("permission_set_xml_with_permission", |b| {
        b.iter(|| {
            let perm_set = PermissionSet::new(black_box(data)).unwrap();
            black_box(perm_set)
        });
    });
}

/// Benchmark parsing repeated permission sets to measure consistency.
fn bench_permission_set_repeated(c: &mut Criterion) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WB_DeclSecurity_1.bin");

    let data = fs::read(&path).expect("Failed to read security declaration file");

    let mut group = c.benchmark_group("permission_set");
    group.throughput(Throughput::Elements(100));
    group.bench_function("parse_100x", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let perm_set = PermissionSet::new(black_box(&data)).unwrap();
                black_box(perm_set);
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_permission_set_parse,
    bench_permission_set_minimal,
    bench_permission_set_xml_minimal,
    bench_permission_set_xml_with_permission,
    bench_permission_set_repeated,
);
criterion_main!(benches);
