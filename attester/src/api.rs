// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    keys::AttesterKey,
    scoring::{evaluate_social_graph, ScoringResult},
    types::{AttestRequest, AttestResponse, AttesterConfig, SocialGraphAttestation},
};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AttesterConfig>,
    pub key: Arc<AttesterKey>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/attest", post(attest))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/health", get(health))
        .with_state(state)
}

pub async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok"}))
}

pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.key.jwks())
}

pub async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> impl IntoResponse {
    let now = now_secs();
    match evaluate_social_graph(
        &req.subject,
        &req.evidence,
        &state.config.trusted_roots,
        now,
        &state.config.scoring,
    ) {
        ScoringResult::Pass {
            eligibility_level, ..
        } => match create_attestation(&req, eligibility_level, now, &state.config, &state.key) {
            Ok(attestation) => (
                StatusCode::OK,
                Json(AttestResponse::Success {
                    attestation: Box::new(attestation),
                }),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AttestResponse::Failure {
                    reasons: vec!["attestation_error".into()],
                }),
            )
                .into_response(),
        },
        ScoringResult::Fail { reasons, .. } => (
            StatusCode::FORBIDDEN,
            Json(AttestResponse::Failure { reasons }),
        )
            .into_response(),
    }
}

pub fn create_attestation(
    req: &AttestRequest,
    eligibility_level: u8,
    now: u64,
    config: &AttesterConfig,
    key: &AttesterKey,
) -> anyhow::Result<SocialGraphAttestation> {
    let mut att = SocialGraphAttestation {
        contract_version: "sophia/v1".into(),
        artifact_type: "social_graph.attestation".into(),
        version: "1".into(),
        attester_id: config.attester_id.clone(),
        kid: key.kid.clone(),
        policy_id: config.policy_id.clone(),
        issued_at: now,
        expires_at: now + config.ttl_secs,
        eligibility_level,
        quota_nullifier: None,
        jti: Uuid::new_v4().to_string(),
        holder_commitment: req.holder_commitment.clone(),
        signature: String::new(),
    };
    key.sign_attestation(&mut att)?;
    Ok(att)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
