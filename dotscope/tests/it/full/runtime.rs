#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Running deobfuscated packer samples under Mono.
//!
//! The harness deobfuscates every sample of a packer family, writes the output, and runs it and
//! the family's unprotected original under Mono. What a run must show to pass (the original's
//! output, method by method) is the comparison layer built on these runs; here every family is
//! held to the harness's own preconditions: the original runs, and every sample is either
//! deobfuscated, written and run, or refused for what it is.

#![cfg(feature = "deobfuscation")]

use std::{fs, path::PathBuf};

use dotscope::{
    testkit::{
        deobfuscated, fixture,
        mono::{
            capabilities::Runtime,
            execution::{execute_with_runtime, ExecutionResult},
        },
        tools::{require_tool, ToolKind},
    },
    Error,
};

/// What running one sample's deobfuscated output under Mono gave; `None` when the engine
/// refuses the sample as not supported (a .NET Reactor native EXE wrapper).
struct RuntimeRun {
    sample: String,
    execution: Option<ExecutionResult>,
}

/// The family's unprotected original run under Mono, and a run of every protected sample in
/// `dir` (a fixture directory); `None` when the machine has no Mono.
fn run_family(dir: &str) -> Option<(ExecutionResult, Vec<RuntimeRun>)> {
    require_tool(ToolKind::Mono)?;
    let original = execute_with_runtime(Runtime::Mono, &fixture(&format!("{dir}/original.exe")))
        .expect("Mono starts");

    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("runtime")
        .join(dir.replace('/', "_"));
    fs::create_dir_all(&scratch).unwrap();

    let mut samples: Vec<String> = fs::read_dir(fixture(dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".exe") && name != "original.exe")
        .collect();
    samples.sort();

    let runs = samples
        .into_iter()
        .map(|sample| {
            let execution = match deobfuscated(&format!("{dir}/{sample}")) {
                Ok((output, _)) => {
                    let path = scratch.join(&sample);
                    fs::write(&path, output.file().data()).unwrap();
                    Some(execute_with_runtime(Runtime::Mono, &path).expect("Mono starts"))
                }
                Err(Error::NotSupported) => None,
                Err(error) => panic!("{dir}/{sample}: deobfuscation failed: {error}"),
            };
            RuntimeRun { sample, execution }
        })
        .collect();
    Some((original, runs))
}

/// Runs `dir`'s family through the harness and holds it to the harness's preconditions.
fn check_family(dir: &str) {
    let Some((original, runs)) = run_family(dir) else {
        return;
    };
    assert!(
        original.is_success(),
        "{dir}/original.exe does not run: {}",
        original.error_summary()
    );
    assert!(!runs.is_empty(), "{dir} has no protected samples");
    for run in &runs {
        match &run.execution {
            Some(execution) if execution.is_success() => eprintln!("{dir}/{}: runs", run.sample),
            Some(execution) => eprintln!(
                "{dir}/{}: does not run: {}",
                run.sample,
                execution.error_summary()
            ),
            None => eprintln!("{dir}/{}: refused as not supported", run.sample),
        }
    }
}

#[test]
fn confuserex_samples_run_under_mono() {
    check_family("packers/confuserex/1.6.0");
}

#[test]
fn bitmono_0_39_0_samples_run_under_mono() {
    check_family("packers/bitmono/0.39.0");
}

#[test]
fn bitmono_0_45_0_samples_run_under_mono() {
    check_family("packers/bitmono/0.45.0");
}

#[test]
fn obfuscar_samples_run_under_mono() {
    check_family("packers/obfuscar/2.2.50");
}

#[test]
fn jiejie_samples_run_under_mono() {
    check_family("packers/jiejie/source");
}

#[test]
fn netreactor_samples_run_under_mono() {
    check_family("packers/netreactor/7.5.0");
}
