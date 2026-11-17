#![no_main]

use freebird_common::privacy_pass::TokenResponse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(response) = TokenResponse::from_bytes(bytes) {
        assert_eq!(response.to_bytes().as_slice(), bytes);
    }
});
