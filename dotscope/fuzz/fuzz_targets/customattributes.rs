//! Fuzzes the custom-attribute value-blob parser.
//!
//! CA blobs are parsed for every row of the CustomAttribute table during the default load, on
//! rayon workers, before any validation stage runs. The blob is fully attacker-controlled and
//! its grammar is self-describing — element-type tags select the parse, so a dozen bytes can
//! request an enormous amount of work or an enormous reservation.
//!
//! The constructor parameter list is empty on purpose. Parameters only supply expected types
//! for the fixed arguments; leaving them empty drives the *tag-driven* path, which is the one
//! that lacked the array bound.

#![no_main]

use std::sync::Arc;

use dotscope::metadata::customattributes::parse_custom_attribute_data;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let params = Arc::new(boxcar::Vec::new());
    let _ = parse_custom_attribute_data(data, &params);
});
