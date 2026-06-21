// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{Context, Result};
use attester::{
    api::{router, AppState},
    keys::AttesterKey,
    scoring::ScoringConfig,
    types::AttesterConfig,
};
use std::{env, sync::Arc};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let config = load_config()?;
    let key = AttesterKey::load_or_generate(&config.private_key_path, config.kid.clone())?;
    let bind_addr = config.bind_addr.clone();
    let app = router(AppState {
        config: Arc::new(config),
        key: Arc::new(key),
    });
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(%bind_addr, "starting social graph attester");
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config() -> Result<AttesterConfig> {
    let roots = env::var("ATTESTER_TRUSTED_ROOTS")
        .context("ATTESTER_TRUSTED_ROOTS is required")?
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    anyhow::ensure!(!roots.is_empty(), "ATTESTER_TRUSTED_ROOTS is required");
    Ok(AttesterConfig {
        bind_addr: var("ATTESTER_BIND_ADDR", "0.0.0.0:8083"),
        private_key_path: var("ATTESTER_PRIVATE_KEY_PATH", "attester_sk.bin"),
        kid: var("ATTESTER_KID", "attester-key-1"),
        attester_id: var("ATTESTER_ID", "attester:local:v1"),
        policy_id: var("ATTESTER_POLICY_ID", "clout-trust-v1"),
        ttl_secs: parse("ATTESTER_TTL_SECS", 300)?,
        trusted_roots: roots,
        scoring: ScoringConfig {
            min_independent_edges: parse("ATTESTER_MIN_INDEPENDENT_EDGES", 2)?,
            min_edge_age_days: parse("ATTESTER_MIN_EDGE_AGE_DAYS", 7)?,
            min_weighted_score: parse("ATTESTER_MIN_WEIGHTED_SCORE", 0.3)?,
            fanout_cap: parse("ATTESTER_FANOUT_CAP", 20)?,
        },
    })
}
fn var(k: &str, d: &str) -> String {
    env::var(k).unwrap_or_else(|_| d.to_owned())
}
fn parse<T: std::str::FromStr>(k: &str, d: T) -> Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env::var(k).map_or(Ok(d), |v| Ok(v.parse()?))
}
