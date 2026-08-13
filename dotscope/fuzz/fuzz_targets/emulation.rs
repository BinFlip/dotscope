//! Fuzzes the CIL interpreter under tight resource limits.
//!
//! This is the only target that executes attacker-controlled *instructions* rather than just
//! parsing attacker-controlled bytes, so it reaches the interpreter, the BCL hooks, the managed
//! heap and the exception-unwind machinery — the surfaces where unbounded allocation and
//! unwind-ordering defects live.
//!
//! # Why it is structured this way
//!
//! Random bytes almost never form a loadable assembly, so most iterations stop at
//! `CilObject::from_mem`. That is expected and still useful: the fuzzer's coverage feedback
//! drives it toward inputs that get further, and the committed corpus seeds it with real
//! PE-shaped material. The alternative — synthesising a valid PE wrapper around fuzzed IL —
//! would test a narrower, more artificial surface.
//!
//! # Limits
//!
//! Every budget is set far below the production default. A fuzz iteration must finish in
//! milliseconds, and an input that merely *runs for a long time* is not the bug class this
//! target hunts — unbounded work that ignores the budget entirely is. Keeping the budget tiny
//! makes a hang stand out instead of blending into normal execution time.

#![no_main]

use dotscope::{
    emulation::ProcessBuilder,
    metadata::{cilobject::CilObject, token::Token},
};
use libfuzzer_sys::fuzz_target;

/// Instruction budget per emulated method. Production defaults to ~10M.
const MAX_INSTRUCTIONS: u64 = 20_000;

/// Call-depth budget. Deep enough to exercise unwinding across frames, shallow enough to stay
/// fast.
const MAX_CALL_DEPTH: usize = 32;

/// Wall-clock budget per emulated method.
const TIMEOUT_MS: u64 = 500;

/// How many methods to try per input, so one assembly cannot dominate the run.
const MAX_METHODS: usize = 8;

fuzz_target!(|data: &[u8]| {
    let Ok(assembly) = CilObject::from_mem(data.to_vec()) else {
        return;
    };

    // Collect a few method tokens before building the process: `methods()` borrows the
    // assembly, which the builder takes by value.
    let tokens: Vec<Token> = assembly
        .methods()
        .iter()
        .take(MAX_METHODS)
        .map(|entry| *entry.key())
        .collect();

    if tokens.is_empty() {
        return;
    }

    let Ok(process) = ProcessBuilder::new()
        .assembly(assembly)
        .with_max_instructions(MAX_INSTRUCTIONS)
        .with_max_call_depth(MAX_CALL_DEPTH)
        .with_timeout_ms(TIMEOUT_MS)
        .build()
    else {
        return;
    };

    for token in tokens {
        // Errors and limit-reached outcomes are both fine. The property under test is that the
        // call returns at all — rather than panicking, aborting, exhausting host memory, or
        // running past its budget.
        let _ = process.execute_method(token, Vec::new());
    }
});
