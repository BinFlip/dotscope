//! Fuzzes the raw PE + metadata-stream view.
//!
//! `CilAssemblyView` is the layer beneath `CilObject`: it parses the PE headers, locates the
//! CLI directory and slices the metadata heaps, all before any table or signature parsing
//! happens. Fuzzing it directly reaches header and stream-slicing arithmetic that the
//! `cilobject` target only exercises when the outer parse gets far enough to call it.
//!
//! Malformed input is expected; an `Err` is a pass. The property is that the call returns
//! rather than panicking, aborting, or reading out of bounds.

#![no_main]

use dotscope::metadata::cilassemblyview::CilAssemblyView;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = CilAssemblyView::from_mem(data.to_vec());
});
