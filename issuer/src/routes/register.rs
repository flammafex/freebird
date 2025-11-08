use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
use std::sync::Arc;

use crate::webauthn::WebAuthnCtx;
use crate::store::CredStore;

#[derive(Clone)]
pub struct AppState {
    pub wa: Arc<WebAuthnCtx>,
    pub store: CredStore,
}

#[derive(Serialize)]
pub struct StartRegResp {
    pub options: PublicKeyCredentialCreationOptions,
    pub session: RegistrationState,
}

pub async fn start(
    State(state): State<AppState>,
) -> Json<StartRegResp> {
    // "username" is optional if you want username-less registration; WebAuthn still needs a user handle.
    let user = PublicKeyUser {
        id: b"user-1".to_vec().into(),
        name: "freebird".into(),
        display_name: "Freebird User".into(),
    };

    let (options, reg_state) = state.wa.webauthn.start_passkey_registration(
        user,
        None, // exclude credentials
        None, // authenticator selection from builder
    ).expect("start registration");

    Json(StartRegResp { options, session: reg_state })
}

#[derive(Deserialize)]
pub struct FinishRegReq {
    pub session: RegistrationState,
    pub response: RegisterPublicKeyCredential,
}

pub async fn finish(
    State(state): State<AppState>,
    Json(req): Json<FinishRegReq>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, &'static str)> {
    let result = state.wa.webauthn.finish_passkey_registration(&req.response, &req.session)
        .map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "registration failed"))?;

    // Persist credential
    state.store.save(
        result.cred_id.clone(),
        result.credential.clone(),
        result.public_key.clone(),
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "cred_id_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&result.cred_id),
    })))
}
