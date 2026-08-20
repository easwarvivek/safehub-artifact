#![no_main]
use libfuzzer_sys::fuzz_target;
use safehub_crypto::aead::CommittingAead;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let _ = CommittingAead::open(&key, b"fuzz", &data[32..]);
});
