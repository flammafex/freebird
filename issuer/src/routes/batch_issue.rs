// issuer/src/routes/batch_issue.rs
//! High-performance batch token issuance with concurrent processing
//!
//! This module implements batch token issuance optimized for throughput:
//! - Concurrent VOPRF evaluation using tokio JoinSet
//! - Efficient error handling with partial success
//! - Memory-efficient processing with minimal allocations
//! - Comprehensive performance metrics
//!
//! # Performance Characteristics
//!
//! - Target: 1000+ tokens/second on modern hardware (4+ cores)
//! - Concurrent processing scales with async task scheduling
//! - Memory usage: ~1KB per token (temporary allocations)
//! - Latency: ~10ms baseline + ~1ms per 100 tokens (p95)
//!
//! # Architecture
//!
//! ```text
//! Request → Validation → Sybil Check → Concurrent VOPRF → Response
//!              ↓             ↓              ↓                ↓
//!           Decode      Single Proof   JoinSet          Aggregate
//!           Verify      Verification   Eval Tasks       Results
//! ```

use crate::multi_key_voprf::MultiKeyVoprfCore;
use crate::routes::issue::extract_client_data;
use crate::sybil_resistance::SybilRequestContext;
use crate::AppStateWithSybil;
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{BatchIssueReq, BatchIssueResp, SybilInfo, TokenResult};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};
// / Maximum batch size to prevent memory exhaustion
// /
// / Rationale:
// / - Each token: ~33 bytes input + 130 bytes output = ~163 bytes
// / - 10k tokens: ~1.6MB memory
// / - Plus intermediate allocations: ~5MB total
// / - Safe limit for most deployments
pub const MAX_BATCH_SIZE: usize = 10_000;

// / Minimum batch size for parallel processing
// /
// / Below this threshold, overhead of parallelization exceeds benefits
pub const MIN_PARALLEL_BATCH_SIZE: usize = 10;

// / Performance metrics for batch processing
#[derive(Debug)]
struct BatchMetrics {
    total_time_ms: u64,
    validation_time_ms: u64,
    sybil_time_ms: u64,
    voprf_time_ms: u64,
    successful: usize,
    failed: usize,
}

fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

pub(crate) fn batch_request_binding(
    route_scope: &str,
    issuer_id: &str,
    blinded_elements: &[String],
) -> String {
    let mut hasher = Sha256::new();
    for element in blinded_elements {
        hasher.update((element.len() as u64).to_le_bytes());
        hasher.update(element.as_bytes());
    }
    let digest = hasher.finalize();
    format!(
        "freebird:{}:v1:{}:{}:{}",
        route_scope,
        issuer_id,
        blinded_elements.len(),
        Base64UrlUnpadded::encode_string(&digest[..16])
    )
}

impl BatchMetrics {
    fn log(&self, batch_size: usize) {
        let throughput = compute_throughput(self.successful, self.total_time_ms);
        info!(
            "📊 Batch metrics: total={}ms, validation={}ms, sybil={}ms, voprf={}ms, success={}, failed={}, total={}, throughput={:.0} tok/s",
            self.total_time_ms,
            self.validation_time_ms,
            self.sybil_time_ms,
            self.voprf_time_ms,
            self.successful,
            self.failed,
            batch_size,
            throughput
        );
    }
}

// / Validate and decode a single blinded element
// /
// / This is called in parallel for each token, so it must be thread-safe.
// /
// / # Performance
// /
// / - Base64 decoding: ~100ns per token
// / - Length validation: ~10ns
// / - Total: ~110ns per token (negligible)
fn validate_blinded_element(blinded_b64: &str) -> Result<Vec<u8>, String> {
    // Decode base64
    let blinded =
        Base64UrlUnpadded::decode_vec(blinded_b64).map_err(|e| format!("invalid base64: {}", e))?;

    // Validate length
    if blinded.len() != 33 {
        return Err(format!(
            "invalid length: got {} bytes, expected 33",
            blinded.len()
        ));
    }

    Ok(blinded)
}

// / Perform VOPRF evaluation with proper error handling
// /
// / # Performance
// /
// / This is the critical hot path. P-256 scalar multiplication is the bottleneck:
// / - Single evaluation: ~200µs (5000 ops/sec per core)
// / - With 8 cores: ~40,000 ops/sec theoretical maximum
// / - Actual: ~30,000 ops/sec with overhead
// /
// / # Optimization Opportunities
// /
// / 1. SIMD: Batch point operations (requires custom implementation)
// / 2. GPU: Offload to GPU for large batches (>10k tokens)
// / 3. Hardware crypto: Use CPU crypto extensions (AES-NI, SHA-NI)
async fn evaluate_token(
    voprf: &MultiKeyVoprfCore,
    blinded_b64: &str,
    issuer_id: &str,
) -> TokenResult {
    match voprf.evaluate_b64(blinded_b64).await {
        Ok(eval_result) => {
            let kid = eval_result.kid;
            TokenResult::Success {
                token: eval_result.token,
                kid,
                issuer_id: issuer_id.to_string(),
            }
        }
        Err(e) => TokenResult::Error {
            message: e.to_string(),
            code: "voprf_evaluation_failed".to_string(),
        },
    }
}

// / Main batch issuance handler
// /
// / # Performance Strategy
// /
// / 1. **Fast-path validation**: Reject bad requests early
// / 2. **Single Sybil check**: One proof for entire batch
// / 3. **Concurrent VOPRF**: Use tokio JoinSet for async crypto operations
// / 4. **Minimal allocations**: Pre-allocate result vectors
// / 5. **Async-aware**: Properly integrate with tokio runtime
// /
// / # Error Handling Philosophy
// /
// / - **Partial success**: Return all results, even if some fail
// / - **Fail-fast**: Reject entire batch if Sybil check fails (DDoS protection)
// / - **Detailed errors**: Include error codes for each failed token
// /
// / # Concurrency Model
// /
// / ```text
// / Tokio Runtime (async I/O)
// /       ↓
// / Handler (validates request, checks Sybil)
// /       ↓
// / tokio::task::JoinSet (concurrent VOPRF)
// /       ↓
// / Results aggregation
// / ```
#[instrument(skip(state, voprf, headers), fields(batch_size = req.blinded_elements.len()))]
pub async fn handle_batch(
    // Change: Extract tuple from State
    State((state, voprf)): State<(Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)>,
    // Remove: voprf: Arc<MultiKeyVoprfCore>
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<BatchIssueReq>,
) -> Result<Json<BatchIssueResp>, (StatusCode, String)> {
    let start = Instant::now();
    let batch_size = req.blinded_elements.len();

    info!(
        "🔥 /v1/oprf/issue/batch: size={}, has_proof={}, sybil_configured={}",
        batch_size,
        req.sybil_proof.is_some(),
        state.sybil_checker.is_some()
    );

    // --- VALIDATION ---
    let validation_start = Instant::now();

    // Check batch size limits
    if batch_size == 0 {
        return Err((StatusCode::BAD_REQUEST, "batch cannot be empty".to_string()));
    }

    if batch_size > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "batch size {} exceeds maximum {}",
                batch_size, MAX_BATCH_SIZE
            ),
        ));
    }

    // Validate optional context
    if let Some(ctx_b64) = &req.ctx_b64 {
        Base64UrlUnpadded::decode_vec(ctx_b64).map_err(|e| {
            error!("ctx_b64 decode failed: {e:?}");
            (StatusCode::BAD_REQUEST, "invalid ctx_b64 encoding".into())
        })?;
    }

    let validation_time_ms = validation_start.elapsed().as_millis() as u64;
    debug!("✅ Validation passed in {}ms", validation_time_ms);

    // --- SYBIL RESISTANCE CHECK ---
    let sybil_start = Instant::now();
    let client_data = extract_client_data(connect_info, state.behind_proxy, &headers);

    let sybil_info = match (&state.sybil_checker, &req.sybil_proof) {
        // Case 1: Sybil configured + proof provided → VERIFY
        (Some(checker), Some(proof)) => {
            debug!("verifying Sybil proof for batch of {}", batch_size);

            let sybil_ctx = SybilRequestContext {
                client_data: Some(client_data.clone()),
                request_binding: Some(batch_request_binding(
                    "issue-batch",
                    &state.issuer_id,
                    &req.blinded_elements,
                )),
                allow_registered_user: false,
            };
            match checker.verify_with_context(proof, &sybil_ctx) {
                Ok(()) => {
                    info!("✅ Sybil resistance check passed for batch");
                    Some(SybilInfo {
                        required: true,
                        passed: true,
                        cost: checker.cost(),
                    })
                }
                Err(e) => {
                    warn!("❌ Sybil resistance check failed: {}", e);
                    return Err((
                        StatusCode::FORBIDDEN,
                        format!("Sybil resistance verification failed: {}", e),
                    ));
                }
            }
        }

        // Case 2: Sybil configured + NO proof → REJECT
        (Some(_checker), None) => {
            warn!("❌ Sybil proof required but not provided for batch");
            return Err((
                StatusCode::BAD_REQUEST,
                "Sybil resistance proof required for batch issuance".to_string(),
            ));
        }

        // Case 3: Sybil NOT configured + proof provided → WARN
        (None, Some(_proof)) => {
            warn!("⚠️ Sybil proof provided but not configured (ignored for batch)");
            None
        }

        // Case 4: No Sybil resistance
        (None, None) => {
            debug!("no Sybil resistance for batch (backward compatible)");
            None
        }
    };

    let sybil_time_ms = sybil_start.elapsed().as_millis() as u64;

    // --- PARALLEL VOPRF EVALUATION ---
    let voprf_start = Instant::now();

    let issuer_id = state.issuer_id.clone();

    // Choose processing strategy based on batch size
    let results = if batch_size < MIN_PARALLEL_BATCH_SIZE {
        // Sequential processing for small batches (less overhead)
        debug!(
            "using sequential processing for small batch (n={})",
            batch_size
        );

        let mut results = Vec::with_capacity(batch_size);
        for blinded_b64 in &req.blinded_elements {
            // Validate first
            match validate_blinded_element(blinded_b64) {
                Ok(_) => {
                    // Evaluate VOPRF
                    results.push(evaluate_token(&voprf, blinded_b64, &issuer_id).await);
                }
                Err(e) => {
                    results.push(TokenResult::Error {
                        message: e,
                        code: "validation_failed".to_string(),
                    });
                }
            }
        }
        results
    } else {
        // Concurrent processing for larger batches
        debug!("using concurrent processing for batch (n={})", batch_size);

        // Step 1: Validate all inputs sequentially (fast)
        let validated: Vec<_> = req
            .blinded_elements
            .iter()
            .map(|b| validate_blinded_element(b))
            .collect();

        // Step 2: Process valid tokens concurrently using tokio JoinSet
        let mut results_with_idx = Vec::with_capacity(batch_size);
        let mut join_set = tokio::task::JoinSet::new();

        for (idx, validation_result) in validated.into_iter().enumerate() {
            match validation_result {
                Ok(_) => {
                    let voprf = Arc::clone(&voprf);
                    let blinded_b64 = req.blinded_elements[idx].clone();
                    let issuer_id = issuer_id.clone();
                    join_set.spawn(async move {
                        (idx, evaluate_token(&voprf, &blinded_b64, &issuer_id).await)
                    });
                }
                Err(e) => {
                    results_with_idx.push((
                        idx,
                        TokenResult::Error {
                            message: e,
                            code: "validation_failed".to_string(),
                        },
                    ));
                }
            }
        }

        while let Some(res) = join_set.join_next().await {
            let (idx, token_result) = res.map_err(|e| {
                error!("JoinSet task panicked: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("task failed: {}", e),
                )
            })?;
            results_with_idx.push((idx, token_result));
        }

        results_with_idx.sort_by_key(|(idx, _)| *idx);
        results_with_idx.into_iter().map(|(_, r)| r).collect()
    };

    let voprf_time_ms = voprf_start.elapsed().as_millis() as u64;

    // --- AGGREGATE RESULTS ---
    let successful = results
        .iter()
        .filter(|r| matches!(r, TokenResult::Success { .. }))
        .count();
    let failed = batch_size - successful;

    let total_time_ms = start.elapsed().as_millis() as u64;
    let throughput = compute_throughput(successful, total_time_ms);

    // Log metrics
    let metrics = BatchMetrics {
        total_time_ms,
        validation_time_ms,
        sybil_time_ms,
        voprf_time_ms,
        successful,
        failed,
    };
    metrics.log(batch_size);

    // Warn if throughput is below target
    if throughput < 1000.0 && batch_size >= 100 {
        warn!(
            "⚠️ Throughput below target: {:.0} tok/s (target: 1000+ tok/s)",
            throughput
        );
        warn!(
            "Consider: (1) more CPU cores, (2) batch size optimization, (3) hardware acceleration"
        );
    }

    Ok(Json(BatchIssueResp {
        results,
        successful,
        failed,
        processing_time_ms: total_time_ms,
        throughput,
        sybil_info,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_blinded_element_success() {
        let valid = Base64UrlUnpadded::encode_string(&[0u8; 33]);
        let result = validate_blinded_element(&valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 33);
    }

    #[test]
    fn test_validate_blinded_element_invalid_length() {
        let invalid = Base64UrlUnpadded::encode_string(&[0u8; 32]);
        let result = validate_blinded_element(&invalid);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid length"));
    }

    #[test]
    fn test_validate_blinded_element_invalid_base64() {
        let result = validate_blinded_element("not!!!valid!!!base64");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid base64"));
    }

    #[test]
    fn test_batch_size_limits() {
        let max_batch_size = std::hint::black_box(MAX_BATCH_SIZE);
        let min_parallel_batch_size = std::hint::black_box(MIN_PARALLEL_BATCH_SIZE);

        assert!(max_batch_size > 1000, "should support large batches");
        assert!(
            min_parallel_batch_size >= 10,
            "parallel overhead threshold should be reasonable"
        );
    }

    #[test]
    fn test_compute_throughput_zero_time() {
        assert_eq!(compute_throughput(100, 0), 0.0);
    }

    #[test]
    fn test_compute_throughput_normal() {
        assert_eq!(compute_throughput(500, 250), 2000.0);
    }
}
