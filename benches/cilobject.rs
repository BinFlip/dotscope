#![allow(unused)]
extern crate dotscope;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::{metadata::cilobject::CilObject, ValidationConfig};
use std::path::{Path, PathBuf};

pub fn criterion_benchmark(c: &mut Criterion) {
    //    // Set rayon to use only 1 thread for this benchmark to profile
    //    rayon::ThreadPoolBuilder::new()
    //        .num_threads(1)
    //        .build_global()
    //        .unwrap();

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    c.bench_function("bench_cilobject", |b| {
        b.iter({ || CilObject::from_file(&path).unwrap() });
    });

    c.bench_function("bench_cilobject_validation", |b| {
        b.iter({
            || CilObject::from_file_with_validation(&path, ValidationConfig::strict()).unwrap()
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
