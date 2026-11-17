#![no_main]

use freebird_common::privacy_pass::TokenRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(request) = TokenRequest::from_bytes(bytes) {
        assert_eq!(request.to_bytes().as_slice(), bytes);
    }
});
