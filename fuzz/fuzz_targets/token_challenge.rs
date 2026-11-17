#![no_main]

use freebird_common::privacy_pass::TokenChallenge;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(challenge) = TokenChallenge::parse(bytes) {
        assert_eq!(challenge.serialize(), bytes);
        let digest = challenge.digest();
        assert_eq!(digest, challenge.digest());
        assert_eq!(digest, TokenChallenge::parse(bytes).unwrap().digest());
    }
});
