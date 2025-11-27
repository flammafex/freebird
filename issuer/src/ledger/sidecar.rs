// issuer/src/ledger/sidecar.rs
use async_trait::async_trait;
use anyhow::{anyhow, Result};
use super::BurnLedger; // Assuming trait is defined in mod.rs

pub struct SidecarLedger {
    client: reqwest::Client,
    url: String,
}

impl SidecarLedger {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }
}

#[async_trait]
impl BurnLedger for SidecarLedger {
    async fn is_spent(&self, nullifier: &str) -> Result<bool> {
        let url = format!("{}/check?n={}", self.url, nullifier);
        let resp = self.client.get(&url).send().await?;
        
        // Assuming sidecar returns JSON: { "spent": true/false }
        let json: serde_json::Value = resp.json().await?;
        Ok(json["spent"].as_bool().unwrap_or(false))
    }

    async fn mark_spent(&self, nullifier: &str) -> Result<()> {
        let url = format!("{}/burn", self.url);
        let resp = self.client.post(&url)
            .json(&serde_json::json!({ "nullifier": nullifier }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("Failed to burn token: Sidecar returned {}", resp.status()))
        }
    }
}