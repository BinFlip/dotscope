//! Fuzzes every signature-blob parser against the same input.
//!
//! Signature blobs come straight from the `#Blob` heap and are the crate's most recursive
//! parsing surface — the one that produced a deeply-nested `TypeSignature` whose
//! *drop glue* overflowed the stack. Driving all six entry points from one input is
//! deliberate: they share `SignatureParser`, so a single crafted blob usually reaches several
//! of them and any one may be the arm that mishandles it.
//!
//! Note this also exercises teardown. The returned values are dropped at the end of each
//! iteration, which is where a recursive `Drop` would fail rather than in the parser.

#![no_main]

use dotscope::metadata::signatures::{
    parse_field_signature, parse_local_var_signature, parse_method_signature,
    parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Each parser is independent; a failure in one says nothing about the others, so all six
    // run on every input rather than short-circuiting.
    let _ = parse_method_signature(data);
    let _ = parse_field_signature(data);
    let _ = parse_property_signature(data);
    let _ = parse_local_var_signature(data);
    let _ = parse_type_spec_signature(data);
    let _ = parse_method_spec_signature(data);
});
