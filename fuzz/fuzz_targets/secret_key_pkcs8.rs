#![no_main]

use freebird_crypto::privacy_pass::SecretKey;
use libfuzzer_sys::fuzz_target;

// RSA private-key validation is expensive; bound the parser's input even when
// this target is run without a matching libFuzzer -max_len option.
const MAX_PKCS8_LEN: usize = 4096;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > MAX_PKCS8_LEN {
        return;
    }
    if let Ok(key) = SecretKey::from_pkcs8(bytes) {
        assert_eq!(key.to_pkcs8().unwrap(), bytes);
    }
});
