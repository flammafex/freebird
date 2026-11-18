#![no_main]

use freebird_crypto::privacy_pass::SecretKey;
use libfuzzer_sys::fuzz_target;

// Cap input size to limit the cost of RSA private key validation.
// This cap also applies if `libFuzzer` runs without a matching `-max_len` setting.
const MAX_PKCS8_LEN: usize = 4096;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > MAX_PKCS8_LEN {
        return;
    }
    if let Ok(key) = SecretKey::from_pkcs8(bytes) {
        assert_eq!(key.to_pkcs8().unwrap(), bytes);
    }
});
