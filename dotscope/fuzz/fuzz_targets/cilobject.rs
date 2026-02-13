#![no_main]

use libfuzzer_sys::fuzz_target;
use dotscope::metadata::cilobject::CilObject;

fuzz_target!(|data: &[u8]| {
    let _ = CilObject::from_mem(data.to_vec());
});
