#![no_main]
use libfuzzer_sys::fuzz_target;
use safehub_types::decode_ref_head;

fuzz_target!(|data: &[u8]| {
    let _ = decode_ref_head(data);
});
