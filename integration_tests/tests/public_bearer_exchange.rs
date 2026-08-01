// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Result;

#[path = "public_bearer_exchange/graph_issuance.rs"]
mod graph_issuance;
#[path = "public_bearer_exchange/replay_authority.rs"]
mod replay_authority;
#[path = "public_bearer_exchange/support.rs"]
mod support;
#[path = "public_bearer_exchange/v2_exchange.rs"]
mod v2_exchange;

#[test]
fn v2_graph_config_rejects_self_edges_and_conflicting_key_metadata() -> Result<()> {
    v2_exchange::v2_graph_config_rejects_self_edges_and_conflicting_key_metadata()
}

#[tokio::test]
async fn disabled_v2_exchange_routes_are_generic_and_require_status_capability() -> Result<()> {
    v2_exchange::disabled_v2_exchange_routes_are_generic_and_require_status_capability().await
}

#[tokio::test]
async fn startup_characterizes_exchange_graph_modes_readiness_and_failure_precedence() -> Result<()>
{
    v2_exchange::startup_characterizes_exchange_graph_modes_readiness_and_failure_precedence().await
}

#[tokio::test]
async fn valid_exchange_graph_runtime_reaches_durable_state_before_occupied_bind() -> Result<()> {
    v2_exchange::valid_exchange_graph_runtime_reaches_durable_state_before_occupied_bind().await
}

#[tokio::test]
async fn startup_exchange_failure_precedence_isolated_by_redis() -> Result<()> {
    v2_exchange::startup_exchange_failure_precedence_isolated_by_redis().await
}

#[tokio::test]
async fn v2_graph_http_exchange_atomicity_binding_cycles_and_restart() -> Result<()> {
    v2_exchange::v2_graph_http_exchange_atomicity_binding_cycles_and_restart().await
}

#[test]
fn discovery_constructor_is_public_only_and_sufficient_for_graph_clients() -> Result<()> {
    v2_exchange::discovery_constructor_is_public_only_and_sufficient_for_graph_clients()
}

#[tokio::test]
async fn v4_local_graph_issuance_is_atomic_with_the_global_verifier_replay_marker() -> Result<()> {
    graph_issuance::v4_local_graph_issuance_is_atomic_with_the_global_verifier_replay_marker().await
}

#[tokio::test]
async fn hmac_authorization_mutations_are_rejected_before_any_durable_state() -> Result<()> {
    graph_issuance::hmac_authorization_mutations_are_rejected_before_any_durable_state().await
}

#[tokio::test]
async fn graph_issuance_rejects_missing_signers_and_invalid_validity_without_authority_state(
) -> Result<()> {
    graph_issuance::graph_issuance_rejects_missing_signers_and_invalid_validity_without_authority_state().await
}

#[tokio::test]
async fn redis_time_rejects_well_formed_future_and_expired_signer_windows_without_mutation(
) -> Result<()> {
    graph_issuance::redis_time_rejects_well_formed_future_and_expired_signer_windows_without_mutation().await
}

#[test]
fn graph_issuance_result_requires_exact_quantity_digest_and_result_key() -> Result<()> {
    graph_issuance::graph_issuance_result_requires_exact_quantity_digest_and_result_key()
}

#[tokio::test]
async fn raw_http_recovery_survives_policy_disable_and_removal_without_sdk_state() -> Result<()> {
    graph_issuance::raw_http_recovery_survives_policy_disable_and_removal_without_sdk_state().await
}

#[tokio::test]
async fn cross_service_replay_authority_requires_the_same_redis_namespace() -> Result<()> {
    replay_authority::cross_service_replay_authority_requires_the_same_redis_namespace().await
}

#[tokio::test]
async fn v4_replay_authority_proof_and_staleness_gate_before_spend_mutation() -> Result<()> {
    replay_authority::v4_replay_authority_proof_and_staleness_gate_before_spend_mutation().await
}

#[tokio::test]
async fn retained_v4_scope_is_probed_after_policy_disable_and_removal() -> Result<()> {
    replay_authority::retained_v4_scope_is_probed_after_policy_disable_and_removal().await
}

#[tokio::test]
async fn actual_verifier_single_and_batch_gate_v4_before_replay_mutation() -> Result<()> {
    replay_authority::actual_verifier_single_and_batch_gate_v4_before_replay_mutation().await
}
