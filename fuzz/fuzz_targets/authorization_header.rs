#![no_main]

use freebird_common::privacy_pass::{build_authorization_header, parse_authorization_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // Skip invalid UTF-8 because the header parser accepts strings.
    if let Ok(header) = std::str::from_utf8(bytes) {
        if let Ok(token) = parse_authorization_header(header) {
            let canonical = build_authorization_header(&token);
            assert_eq!(parse_authorization_header(&canonical).unwrap(), token);
        }
    }
});
