use freebird_crypto::{Client, Server, Verifier};
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

        // 2. Client Blinding
        let mut client = Client::new(CTX);
        let (blinded_b64, state) = client.blind(&input).expect("blinding failed");

        // 3. Server Evaluation
        // The server should be able to evaluate ANY valid blinded element
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluation failed");

        // 4. Client Finalization
        let (token_b64, client_output) = client.finalize(state, &eval_b64, &pk)
            .expect("client finalization failed");

        // 5. Verification
        let verifier = Verifier::new(CTX);
        let verifier_output = verifier.verify(&token_b64, &pk)
            .expect("verification failed");

        // 6. Property Assertion
        // The output derived by the client (during issuance) MUST match
        // the output derived by the verifier (during redemption).
        assert_eq!(client_output, verifier_output, "Client and Verifier outputs mismatch");
    }

    #[test]
    fn test_voprf_corrupted_token_fails(
        sk_bytes in proptest::array::uniform32(0u8..255),
        input in proptest::collection::vec(any::<u8>(), 1..50),
        mutation_idx in 0usize..100 // Where to inject the fault
    ) {
        // Setup
        let server = match Server::from_secret_key(sk_bytes, CTX) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        let pk = server.public_key_sec1_compressed();

        let mut client = Client::new(CTX);
        let (blinded_b64, state) = client.blind(&input).unwrap();
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();
        let (token_b64, _output) = client.finalize(state, &eval_b64, &pk).unwrap();

        // Decode token to manipulate bytes
        let mut token_bytes = base64ct::Base64UrlUnpadded::decode_vec(&token_b64).unwrap();

        // Tamper with the token
        if mutation_idx < token_bytes.len() {
            token_bytes[mutation_idx] ^= 0xFF; // Flip bits
        } else {
            token_bytes.push(0x00); // Append garbage
        }

        let corrupted_token = base64ct::Base64UrlUnpadded::encode_string(&token_bytes);

        // Verification should fail
        let verifier = Verifier::new(CTX);
        let result = verifier.verify(&corrupted_token, &pk);

        assert!(result.is_err(), "Verifier accepted corrupted token!");
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

        // Client blinds
        let mut client = Client::new(CTX);
        let (blinded_b64, state) = client.blind(&input).unwrap();

        // Server 1 evaluates (using Key 1)
        let eval_b64 = server1.evaluate_with_proof(&blinded_b64).unwrap();

        // Client tries to finalize using Key 2's public key
        // This checks if the DLEQ proof correctly binds the evaluation to the specific key
        let result = client.finalize(state, &eval_b64, &pk2);

        assert!(result.is_err(), "Client finalized token with wrong public key!");
    }
}