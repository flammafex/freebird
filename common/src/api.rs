// SPDX-License-Identifier: Apache-2.0 OR MIT

mod direct_social_graph_v1;
mod issuance;
mod key_discovery;
mod native_bearer_v7;
mod native_exchange_v3;
mod native_exchange_v4;
mod native_graph_issuance_v7;
mod native_graph_issuance_v8;
mod operation_status_v1;
mod replay_authority;
mod sybil;
mod verification;

pub use direct_social_graph_v1::{
    direct_social_graph_v1_attestation_digest, direct_social_graph_v1_evidence_digest,
    direct_social_graph_v1_holder_commitment, direct_social_graph_v1_jwks_kid_digest,
    direct_social_graph_v1_presentation_digest, direct_social_graph_v1_quota_nullifier,
    direct_social_graph_v1_request_binding_digest, direct_social_graph_v1_subject_binding,
    direct_social_graph_v1_subject_binding_transcript, DirectSocialGraphV1AttestRequest,
    DirectSocialGraphV1Attestation, DirectSocialGraphV1CloutEdge, DirectSocialGraphV1Error,
    DirectSocialGraphV1Jwk, DirectSocialGraphV1KeyState, DirectSocialGraphV1Keyset,
    DirectSocialGraphV1Presentation, DirectSocialGraphV1PresentationProof,
    DirectSocialGraphV1Proof, DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE,
    DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE_ID, DIRECT_SOCIAL_GRAPH_V1_ATTEST_REQUEST_PROFILE,
    DIRECT_SOCIAL_GRAPH_V1_ATTEST_REQUEST_PROFILE_ID, DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS,
    DIRECT_SOCIAL_GRAPH_V1_DOMAIN_ATTESTATION_DIGEST,
    DIRECT_SOCIAL_GRAPH_V1_DOMAIN_EVIDENCE_DIGEST, DIRECT_SOCIAL_GRAPH_V1_DOMAIN_HOLDER_COMMITMENT,
    DIRECT_SOCIAL_GRAPH_V1_DOMAIN_JWKS_KID, DIRECT_SOCIAL_GRAPH_V1_DOMAIN_PRESENTATION_DIGEST,
    DIRECT_SOCIAL_GRAPH_V1_DOMAIN_REQUEST_BINDING, DIRECT_SOCIAL_GRAPH_V1_DOMAIN_SUBJECT_BINDING,
    DIRECT_SOCIAL_GRAPH_V1_JWKS_MAX_STALE_SECS, DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE,
    DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE_ID, DIRECT_SOCIAL_GRAPH_V1_MAX_ATTESTATION_LIFETIME_SECS,
    DIRECT_SOCIAL_GRAPH_V1_MAX_PRESENTATION_LIFETIME_SECS,
    DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE, DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE_ID,
    DIRECT_SOCIAL_GRAPH_V1_QUOTA_PERIOD_SECS, DIRECT_SOCIAL_GRAPH_V1_QUOTA_SECS,
    DIRECT_SOCIAL_GRAPH_V1_VERSION,
};
pub use issuance::{
    BatchIssueReq, BatchIssueResp, ErrorResp, IssueReq, IssueResp, NativeBearerV7BatchIssueReq,
    NativeBearerV7BatchIssueResp, NativeBearerV7IssueReq, NativeBearerV7IssueResp, SybilInfo,
    TokenResult,
};
pub use key_discovery::{
    KeyDiscoveryResp, V7KeyDiscoveryResp, V7KeyDiscoveryRespV2, V7VoprfKeyInfo, VoprfKeyInfo,
};
pub use native_bearer_v7::{
    derive_native_bearer_v7_descriptor_id, validate_native_bearer_v7_discovery,
    validate_v7_canonical_id, validate_v7_identifier_namespace, NativeBearerV7KeyInfo,
    NATIVE_BEARER_V7_BLINDED_MESSAGE_B64_LEN, NATIVE_BEARER_V7_BLINDED_MESSAGE_LEN,
    NATIVE_BEARER_V7_DESCRIPTOR_ID_HEX_LEN, NATIVE_BEARER_V7_EXPONENT,
    NATIVE_BEARER_V7_FINGERPRINT_HEX_LEN, NATIVE_BEARER_V7_MAX_SPKI_BYTES,
    NATIVE_BEARER_V7_MAX_VALID_UNTIL, NATIVE_BEARER_V7_MODULUS_BITS, NATIVE_BEARER_V7_PROFILE_ID,
    NATIVE_BEARER_V7_SUITE, NATIVE_BEARER_V7_TOKEN_KEY_ID_HEX_LEN,
};
pub use native_exchange_v3::{
    derive_native_exchange_v3_descriptor_id, native_exchange_v3_ordered_root,
    native_exchange_v3_output_leaf, native_exchange_v3_output_proof,
    native_exchange_v3_source_leaf, native_exchange_v3_verify_output_proof,
    NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeExchangeV3Error,
    NativeExchangeV3Keyset, NativeExchangeV3Output, NativeExchangeV3Profile,
    NativeExchangeV3Receipt, NativeExchangeV3Request, NativeExchangeV3Result,
    NativeExchangeV3ResultOutput, NativeExchangeV3Slot, NativeExchangeV3Source,
    NativeExchangeV3Transition, EXCHANGE_LUA_MAX_EXACT_INTEGER, EXCHANGE_MAX_BUDGET_LIMIT,
    EXCHANGE_MAX_VALID_UNTIL, NATIVE_EXCHANGE_V3_DOMAIN_DESCRIPTOR,
    NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF, NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE,
    NATIVE_EXCHANGE_V3_DOMAIN_RECEIPT, NATIVE_EXCHANGE_V3_DOMAIN_REQUEST,
    NATIVE_EXCHANGE_V3_DOMAIN_REQUEST_OUTPUT_LEAF, NATIVE_EXCHANGE_V3_DOMAIN_RESULT,
    NATIVE_EXCHANGE_V3_DOMAIN_RESULT_OUTPUT_LEAF, NATIVE_EXCHANGE_V3_DOMAIN_SOURCE_LEAF,
    NATIVE_EXCHANGE_V3_MAX_ITEMS, NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_EXCHANGE_V3_QUANTITY,
    NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS, NATIVE_EXCHANGE_V3_SUITE, NATIVE_EXCHANGE_V3_VERSION,
};
pub use native_exchange_v4::{
    derive_native_exchange_v4_descriptor_id, derive_native_exchange_v4_graph_id,
    derive_native_exchange_v4_keyset_id, derive_native_exchange_v4_transition_id,
    native_exchange_v4_ordered_root, native_exchange_v4_output_leaf,
    native_exchange_v4_request_output_leaf, native_exchange_v4_result_output_leaf,
    native_exchange_v4_source_leaf, NativeExchangeV4Descriptor, NativeExchangeV4Discovery,
    NativeExchangeV4Error, NativeExchangeV4Output, NativeExchangeV4Profile,
    NativeExchangeV4Receipt, NativeExchangeV4ReceiptKeyMetadata, NativeExchangeV4ReceiptKeySet,
    NativeExchangeV4Request, NativeExchangeV4Result, NativeExchangeV4ResultOutput,
    NativeExchangeV4Slot, NativeExchangeV4Source, NativeExchangeV4Transition,
    EXCHANGE_V4_MAX_BUDGET_LIMIT, EXCHANGE_V4_MAX_VALID_UNTIL,
    NATIVE_EXCHANGE_V4_DOMAIN_DESCRIPTOR, NATIVE_EXCHANGE_V4_DOMAIN_EMPTY_LEAF,
    NATIVE_EXCHANGE_V4_DOMAIN_GRAPH, NATIVE_EXCHANGE_V4_DOMAIN_KEYSET,
    NATIVE_EXCHANGE_V4_DOMAIN_MERKLE_NODE, NATIVE_EXCHANGE_V4_DOMAIN_RECEIPT,
    NATIVE_EXCHANGE_V4_DOMAIN_REQUEST, NATIVE_EXCHANGE_V4_DOMAIN_REQUEST_OUTPUT_LEAF,
    NATIVE_EXCHANGE_V4_DOMAIN_RESULT, NATIVE_EXCHANGE_V4_DOMAIN_RESULT_OUTPUT_LEAF,
    NATIVE_EXCHANGE_V4_DOMAIN_SOURCE_LEAF, NATIVE_EXCHANGE_V4_DOMAIN_TRANSITION,
    NATIVE_EXCHANGE_V4_MAX_ITEMS, NATIVE_EXCHANGE_V4_PROFILE_ID, NATIVE_EXCHANGE_V4_QUANTITY,
    NATIVE_EXCHANGE_V4_RAW384_BYTES, NATIVE_EXCHANGE_V4_RECEIPT_KEY_ALGORITHM,
    NATIVE_EXCHANGE_V4_RECEIPT_KEY_PURPOSE, NATIVE_EXCHANGE_V4_RECEIPT_LIFETIME_SECS,
    NATIVE_EXCHANGE_V4_SUITE, NATIVE_EXCHANGE_V4_VERSION,
};
pub use native_graph_issuance_v7::{
    native_graph_issuance_v7_authorization_proof_digest, NativeGraphIssuanceV7Discovery,
    NativeGraphIssuanceV7Error, NativeGraphIssuanceV7Policy, NativeGraphIssuanceV7Request,
    NativeGraphIssuanceV7Result, NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_AUTHORIZATION_BINDING,
    NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_AUTHORIZATION_PROOF, NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_REQUEST,
    NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_RESULT, NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
    NATIVE_GRAPH_ISSUANCE_V7_QUANTITY, NATIVE_GRAPH_ISSUANCE_V7_VERSION,
};
pub use native_graph_issuance_v8::{
    derive_native_graph_issuance_v8_policy_id, native_graph_issuance_v8_owner_commitment_digest,
    native_graph_issuance_v8_owner_proof_digest, native_graph_issuance_v8_policy_id,
    native_graph_issuance_v8_replay_digest, native_graph_issuance_v8_request_digest,
    native_graph_issuance_v8_result_digest, AdmissionState, GraphIssuanceAdmissionStateV8,
    NativeGraphIssuanceV8AdmissionState, NativeGraphIssuanceV8Discovery,
    NativeGraphIssuanceV8Error, NativeGraphIssuanceV8Policy, NativeGraphIssuanceV8Request,
    NativeGraphIssuanceV8Result, NATIVE_GRAPH_ISSUANCE_V8_ADMISSION_PROFILE_ID,
    NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_OWNER_COMMITMENT, NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_OWNER_PROOF,
    NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_POLICY, NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REPLAY,
    NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REPLAY_IDENTITY, NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REQUEST,
    NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_RESULT, NATIVE_GRAPH_ISSUANCE_V8_EXPONENT,
    NATIVE_GRAPH_ISSUANCE_V8_MAX_ARTIFACT_BYTES, NATIVE_GRAPH_ISSUANCE_V8_MODULUS_BITS,
    NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID, NATIVE_GRAPH_ISSUANCE_V8_QUANTITY,
    NATIVE_GRAPH_ISSUANCE_V8_RAW384_BYTES, NATIVE_GRAPH_ISSUANCE_V8_RECOVERY_LIFETIME,
    NATIVE_GRAPH_ISSUANCE_V8_RECOVERY_LIFETIME_SECS, NATIVE_GRAPH_ISSUANCE_V8_SUITE,
    NATIVE_GRAPH_ISSUANCE_V8_VERSION,
};
pub use operation_status_v1::{
    decode_operation_id, decode_raw16, decode_raw32, decode_status_capability, encode_raw16,
    encode_raw32, operation_status_capability_digest, operation_status_capability_digest_hex,
    operation_status_capability_digest_raw, parse_hex32, parse_raw16, parse_raw32,
    status_capability_digest, validate_status_capability_digest, OperationStatusV1Error,
    OPERATION_STATUS_CAPABILITY_DOMAIN, OPERATION_STATUS_CAPABILITY_HEADER,
    OPERATION_STATUS_CAPABILITY_HEADER_NAME, OPERATION_STATUS_V1_VERSION, STATUS_CAPABILITY_HEADER,
};
pub use replay_authority::{
    decode_canonical_32, V4ReplayAuthorityDiscovery, V4_REPLAY_AUTHORITY_MAX_TOMBSTONES,
};
pub use sybil::{SybilProof, VouchProof};
pub use verification::{
    BatchVerifyReq, BatchVerifyResp, TokenToVerify, VerifierMetadataResp, VerifyReq, VerifyResp,
    VerifyResult,
};
