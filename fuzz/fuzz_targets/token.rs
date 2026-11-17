#![no_main]

use freebird_common::privacy_pass::Token;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(token) = Token::from_bytes(bytes) {
        assert_eq!(token.to_bytes().as_slice(), bytes);
    }
});
