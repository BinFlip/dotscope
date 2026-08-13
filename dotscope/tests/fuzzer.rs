#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Regression tests over adversarial inputs.
//!
//! Every file loaded here is malformed on purpose. A parse error is the expected outcome and
//! is not a failure; the property under test is that `CilObject::from_path` returns rather
//! than panicking, aborting, hanging, or exhausting memory.
//!
//! # Two corpora, two guarantees
//!
//! - [`fuzzer_crashes`] runs over `tests/samples/fuzz-regressions/`, which is **committed**.
//!   Each file there once crashed the parser. This test is mandatory: if the directory is
//!   missing or empty, that is itself a failure, because a regression suite that silently
//!   finds nothing to check is worse than no suite at all.
//! - [`fuzzer_corpus`] runs over the local fuzzing corpus under `fuzz/corpus/`, which is too
//!   large to commit and is therefore absent on a clean checkout. It skips loudly when
//!   absent, and is exercised by anyone who has run the fuzzer locally.

use std::{
    fs,
    path::{Path, PathBuf},
};

use dotscope::metadata::cilobject::CilObject;

/// Loads every input in the committed crash corpus.
///
/// Fails if the directory is missing or empty — see the module docs for why.
#[test]
fn fuzzer_crashes() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/fuzz-regressions");
    let loaded = load_every_file(&path).unwrap_or_else(|e| {
        panic!(
            "crash-regression corpus at {} is unusable: {e}.\n\
             These inputs are committed to the repository; if they are missing, the checkout \
             is incomplete or the corpus was deleted.",
            path.display()
        )
    });

    assert!(
        loaded > 0,
        "crash-regression corpus at {} contains no files — this test would otherwise pass \
         without checking anything",
        path.display()
    );
}

/// Loads every input in the local fuzzing corpus, when one is present.
///
/// The corpus is hundreds of megabytes and is not committed, so this skips on a clean
/// checkout. It prints when it skips so a vacuous pass is visible in the test output rather
/// than indistinguishable from a real one.
#[test]
fn fuzzer_corpus() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/cilobject");
    match load_every_file(&path) {
        Ok(loaded) => println!(
            "fuzzer_corpus: loaded {loaded} inputs from {}",
            path.display()
        ),
        Err(e) => println!(
            "fuzzer_corpus: SKIPPED — no local corpus at {} ({e}). \
             Run `make fuzz` to generate one.",
            path.display()
        ),
    }
}

/// Loads every regular file in `dir` through the parser, returning how many were loaded.
///
/// Parse errors are ignored by design; the assertion is that the call returns at all.
///
/// # Errors
///
/// Returns the underlying I/O error if `dir` cannot be read.
fn load_every_file(dir: &Path) -> std::io::Result<usize> {
    let mut loaded = 0usize;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            // Malformed input: an `Err` is the expected result and is discarded. What this
            // exercises is that the call returns instead of taking the process down.
            let _ = CilObject::from_path(&path);
            loaded += 1;
        }
    }
    Ok(loaded)
}
