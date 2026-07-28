/**
 * Freebird SDK
 * Anonymous authentication using VOPRF (Verifiable Oblivious Pseudorandom Function).
 *
 * @module @freebird/sdk
 */

// Export the main client class
export { FreebirdClient } from './client.js';

// Export types needed for configuration and usage
export type {
  ClientConfig,
  IssuerMetadata,
  KeyDiscoveryMetadata,
  PublicKeyInfo,
  VerifierMetadata,
  IssueRequest,
  IssueResponse,
  PublicIssueRequest,
  PublicIssueResponse,
  ExchangeSlot,
  ExchangeRequestSource,
  ExchangeRequestOutput,
  ExchangeRequest,
  ExchangeResultOutput,
  ExchangeResult,
  ExchangeReceipt,
  ExchangeSuccessResponse,
  ExchangeReceiptKeyInfo,
  ExchangeTargetKeysetInfo,
  ExchangeDescriptorInfo,
  ExchangeDiscoveryMetadata,
  ExchangeErrorCode,
  ExchangePendingResponse,
  ExchangeErrorResponse,
  ExchangeCommittedOutcome,
  ExchangePendingOutcome,
  ExchangeErrorOutcome,
  ExchangeOutcome,
  GraphIssuancePolicyInfo,
  GraphIssuanceDiscoveryMetadata,
  GraphIssuanceReplayAuthorityDiscovery,
  GraphIssuanceRequest,
  GraphIssuanceResult,
  GraphIssuanceOutcome,
  GraphIssuanceRecoveryContext,
  FreebirdToken,
  SybilProof,
  // Export internal types that might be useful for debugging
  BlindState
} from './types.js';

// Optionally export low-level crypto for advanced use cases
// (e.g. if a user wants to manually blind/unblind without the client wrapper)
import * as voprf from './crypto/voprf.js';
import * as graphIssuance from './crypto/graph_issuance.js';
export const crypto = {
  blind: voprf.blind,
  finalize: voprf.finalize,
  buildScopeDigest: voprf.buildScopeDigest,
  buildPrivateTokenInput: voprf.buildPrivateTokenInput,
  buildRedemptionToken: voprf.buildRedemptionToken,
  parseRedemptionToken: voprf.parseRedemptionToken,
  tokenKeyIdFromSpki: voprf.tokenKeyIdFromSpki,
  tokenKeyIdToHex: voprf.tokenKeyIdToHex,
  tokenKeyIdFromHex: voprf.tokenKeyIdFromHex,
  buildPublicBearerMessage: voprf.buildPublicBearerMessage,
  buildPublicBearerPass: voprf.buildPublicBearerPass,
  parsePublicBearerPass: voprf.parsePublicBearerPass,
  graphIssuanceHmacAuthorizationTranscriptV2:
    graphIssuance.graphIssuanceHmacAuthorizationTranscriptV2,
  graphIssuanceHmacAuthorizationTagV2: graphIssuance.graphIssuanceHmacAuthorizationTagV2,
  buildGraphIssuanceHmacAuthorizationV2:
    graphIssuance.buildGraphIssuanceHmacAuthorizationV2,
  parseGraphIssuanceHmacAuthorizationV2:
    graphIssuance.parseGraphIssuanceHmacAuthorizationV2,
  verifyGraphIssuanceHmacAuthorizationV2:
    graphIssuance.verifyGraphIssuanceHmacAuthorizationV2,
  hmacAuthorizationTranscriptV2: graphIssuance.hmacAuthorizationTranscriptV2,
  hmacAuthorizationTagV2: graphIssuance.hmacAuthorizationTagV2,
  buildHmacAuthorizationV2: graphIssuance.buildHmacAuthorizationV2,
  parseHmacAuthorizationV2: graphIssuance.parseHmacAuthorizationV2,
  verifyHmacAuthorizationV2: graphIssuance.verifyHmacAuthorizationV2,
};

export {
  graphIssuanceHmacAuthorizationTranscriptV2,
  graphIssuanceHmacAuthorizationTagV2,
  buildGraphIssuanceHmacAuthorizationV2,
  parseGraphIssuanceHmacAuthorizationV2,
  verifyGraphIssuanceHmacAuthorizationV2,
  hmacAuthorizationTranscriptV2,
  hmacAuthorizationTagV2,
  buildHmacAuthorizationV2,
  parseHmacAuthorizationV2,
  verifyHmacAuthorizationV2,
} from './crypto/graph_issuance.js';
