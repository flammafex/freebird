// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
