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
// issuer/src/routes/issue.rs
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{debug, error, info};

use crate::{voprf_core, AppState};

#[derive(Deserialize, Debug)]
pub struct IssueReq {
    #[serde(alias = "blinded")]
    pub blinded_element_b64: String,

    #[serde(default)]
    pub ctx_b64: Option<String>,
}

#[derive(Serialize)]
pub struct IssueResp {
    // 👈 interface expects this exact name now
    pub token: String,
    pub proof: String,
    pub kid: String,
    pub exp: i64,
}

pub async fn handle(
    State(st): State<Arc<AppState>>,
    voprf: Arc<voprf_core::VoprfCore>,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    info!(
        "📥 /v1/oprf/issue entered; kid={}, body.len≈{}",
        st.kid,
        req.blinded_element_b64.len()
    );

    // Decode base64 early and enforce 33-byte SEC1-compressed point
    let blinded_bytes = Base64UrlUnpadded::decode_vec(&req.blinded_element_b64)
        .map_err(|e| {
            error!("invalid base64 for blinded_element_b64: {e:?}");
            (StatusCode::BAD_REQUEST, "invalid base64".to_string())
        })?;

    if blinded_bytes.len() != 33 {
        error!("blinded_element length = {}, expected 33", blinded_bytes.len());
        return Err((
            StatusCode::BAD_REQUEST,
            "blinded_element must be 33 bytes".to_string(),
        ));
    }

    // Optional context sanity (decode-only)
    if let Some(ctx_b64) = &req.ctx_b64 {
        if let Err(e) = Base64UrlUnpadded::decode_vec(ctx_b64) {
            error!("ctx_b64 decode failed: {e:?}");
            return Err((StatusCode::BAD_REQUEST, "invalid ctx_b64".into()));
        }
    }

    // Evaluate in the VOPRF core
    debug!("calling voprf.evaluate_b64()");
    let evaluated_b64 = match voprf.evaluate_b64(&req.blinded_element_b64) {
        Ok(tok) => tok,
        Err(e) => {
            error!("evaluate_b64 failed: {e:?}");
            return Err((StatusCode::BAD_REQUEST, "invalid blinded_element".into()));
        }
    };

    let exp = OffsetDateTime::now_utc().unix_timestamp() + st.exp_sec as i64;
    debug!("issued token for kid={} exp={}", st.kid, exp);

    // 👇 Return the field name the client expects
    Ok(Json(IssueResp {
        token: evaluated_b64,
        proof: String::new(),
        kid: st.kid.clone(),
        exp,
    }))
}
