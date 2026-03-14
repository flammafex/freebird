use freebird_crypto::{Client, Server};
use proptest::prelude::*;
// Fix: Import Encoding trait for Base64UrlUnpadded methods
use base64ct::Encoding;

// Define the VOPRF context
const CTX: &[u8] = b"freebird-property-tests";

proptest! {
    // Run 100 random scenarios
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_voprf_correctness(
        // Generate random 32-byte secret keys
        sk_bytes in proptest::array::uniform32(0u8..255),
        // Generate random input data (1 to 100 bytes)
        input in proptest::collection::vec(any::<u8>(), 1..100)
    ) {
        // 1. Setup Server (Issuer)
        // We allow initialization to fail if the random bytes happen to be an invalid scalar (extremely rare),
        // so we handle the Result gracefully or skip the test case.
        let server = match Server::from_secret_key(sk_bytes, CTX) {
            Ok(s) => s,
            Err(_) => return Ok(()), // Skip invalid keys (scalar == 0)
        };
        let pk = server.public_key_sec1_compressed();
        let pk_b64 = base64ct::Base64UrlUnpadded::encode_string(&pk);

        // 2. Client Blinding
        let mut client = Client::new(CTX);
        let (blinded_b64, state) = client.blind(&input).expect("blinding failed");

        // 3. Server Evaluation
        // The server should be able to evaluate ANY valid blinded element
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluation failed");

        // 4. Client Finalization — returns unblinded PRF output
        let client_output = client.finalize(state, &eval_b64, &pk_b64)
            .expect("client finalization failed");

        // 5. Property Assertion: output is non-empty base64
        assert!(!client_output.is_empty(), "Client output should be non-empty");
    }

    #[test]
    fn test_voprf_corrupted_token_fails(
        sk_bytes in proptest::array::uniform32(0u8..255),
        input in proptest::collection::vec(any::<u8>(), 1..50),
        mutation_idx in 0usize..100 // Where to inject the fault
    ) {
        // Setup — use inner core API to get token bytes for corruption testing
        let server = match Server::from_secret_key(sk_bytes, CTX) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        let pk = server.public_key_sec1_compressed();

        // Use the wrapper to blind and finalize (ensures client works)
        let pk_b64 = base64ct::Base64UrlUnpadded::encode_string(&pk);
        let mut client = Client::new(CTX);
        let (blinded_b64, state) = client.blind(&input).unwrap();
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();

        // Decode eval token to manipulate bytes
        let mut token_bytes = base64ct::Base64UrlUnpadded::decode_vec(&eval_b64).unwrap();

        // Tamper with the token
        if mutation_idx < token_bytes.len() {
            token_bytes[mutation_idx] ^= 0xFF; // Flip bits
        } else {
            token_bytes.push(0x00); // Append garbage
        }

        let corrupted_eval = base64ct::Base64UrlUnpadded::encode_string(&token_bytes);

        // Client finalization should fail with corrupted evaluation
        let result = client.finalize(state, &corrupted_eval, &pk_b64);
        assert!(result.is_err(), "Client accepted corrupted evaluation token!");
    }

    #[test]
    fn test_voprf_wrong_key_fails(
        sk1_bytes in proptest::array::uniform32(0u8..255),
        sk2_bytes in proptest::array::uniform32(0u8..255),
        input in proptest::collection::vec(any::<u8>(), 1..50)
    ) {
        // Ensure keys are different
        if sk1_bytes == sk2_bytes { return Ok(()); }

        let server1 = match Server::from_secret_key(sk1_bytes, CTX) { Ok(s) => s, Err(_) => return Ok(()) };
        let server2 = match Server::from_secret_key(sk2_bytes, CTX) { Ok(s) => s, Err(_) => return Ok(()) };

        let pk2 = server2.public_key_sec1_compressed();
        let pk2_b64 = base64ct::Base64UrlUnpadded::encode_string(&pk2);

        // Client blinds
        let mut client = Client::new(CTX);
        let (blinded_b64, state) = client.blind(&input).unwrap();

        // Server 1 evaluates (using Key 1)
        let eval_b64 = server1.evaluate_with_proof(&blinded_b64).unwrap();

        // Client tries to finalize using Key 2's public key
        // This checks if the DLEQ proof correctly binds the evaluation to the specific key
        let result = client.finalize(state, &eval_b64, &pk2_b64);

        assert!(result.is_err(), "Client finalized token with wrong public key!");
    }
}
