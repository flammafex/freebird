// issuer/src/sybil_resistance/proof_of_burn.rs
use std::sync::Arc;
use super::SybilResistance;
use crate::ledger::BurnLedger;
use freebird_common::api::SybilProof;
use anyhow::{anyhow, Result};
use freebird_crypto::nullifier_key; 

pub struct ProofOfBurn {
    ledger: Arc<dyn BurnLedger>,
    // We don't strictly need issuer_id here unless validating input_issuer_id match,
    // but keeping it for consistency with your snippet.
    _issuer_id: String, 
}

impl ProofOfBurn {
    pub fn new(ledger: Arc<dyn BurnLedger>, issuer_id: String) -> Self {
        Self { ledger, _issuer_id: issuer_id }
    }
}

impl SybilResistance for ProofOfBurn {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        let (input_token, input_issuer) = match proof {
            SybilProof::ProofOfBurn { input_token, input_issuer_id, .. } => 
                (input_token, input_issuer_id),
            _ => return Err(anyhow!("Invalid proof type")),
        };

        // 1. Calculate the Nullifier (The "Fingerprint" of the coin)
        // We use the crypto helper to ensure it matches how Verifiers calculate it
        let nullifier_hash = nullifier_key(input_issuer, input_token);

        // 2. Interact with the Ledger
        // Since verify is synchronous but the ledger is async (network/db),
        // we use the runtime handle to block.
        let rt = tokio::runtime::Handle::current();
        
        rt.block_on(async {
            // Check if it's already spent
            if self.ledger.is_spent(&nullifier_hash).await? {
                return Err(anyhow!("Double Spend Detected: Token already burned"));
            }

            // Burn it
            self.ledger.mark_spent(&nullifier_hash).await?;
            
            Ok(())
        })
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::ProofOfBurn { .. })
    }

    fn cost(&self) -> u64 { 0 }
}