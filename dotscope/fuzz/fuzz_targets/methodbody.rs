//! Fuzzes method-body header parsing and CIL block decoding.
//!
//! Two stages, both attacker-controlled:
//!
//! 1. `MethodBody::from` parses the tiny/fat header, the `size_code` field and the exception
//!    section chain. The fat header's size-in-dwords nibble decides where the header ends, so
//!    a hostile value can make it overlap the code it precedes.
//! 2. `decode_blocks` walks the IL into basic blocks. `switch` reads an attacker-chosen case
//!    count, and decoding must stay inside the method's declared `size_code` rather
//!    than run to the end of the buffer.
//!
//! The decode runs on the raw input rather than on the body's code window on purpose: it is
//! the linear-disassembly entry point, and bounding it is the caller's job — which is the
//! contract this target covers.

#![no_main]

use dotscope::assembly::decode_blocks;
use libfuzzer_sys::fuzz_target;

/// Keeps a single iteration cheap enough that the fuzzer explores rather than grinds.
const MAX_DECODE_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Stage 1: header + exception section chain.
    let _ = dotscope::metadata::method::MethodBody::from(data);

    // Stage 2: block decoding, bounded so one pathological input cannot dominate the run.
    if !data.is_empty() {
        let limit = data.len().min(MAX_DECODE_BYTES);
        let _ = decode_blocks(data, 0, 0x2000, Some(limit));
    }
});
