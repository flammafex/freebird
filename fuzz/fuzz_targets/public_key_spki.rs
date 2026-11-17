#![no_main]

use freebird_crypto::privacy_pass::PublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(key) = PublicKey::from_spki(bytes) {
        assert_eq!(key.to_spki(), bytes);
    }
});
