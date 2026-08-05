/**
 * Freebird SDK
 * Anonymous authentication using VOPRF (Verifiable Oblivious Pseudorandom Function).
 *
 * @module @freebird/sdk
 */

// Export the main client class
export { FreebirdClient } from './client.js';

// Export protocol utilities for V2 exchange request assembly
export {
  generateOperationId,
  generateStatusCapability,
  exchangePasses,
} from './client/protocol.js';
export type { ExchangePassesOptions } from './client/protocol.js';

// Export the typed error hierarchy
export {
  FreebirdError,
  DiscoveryError,
  VerificationError,
  VerifierNotConfiguredError,
  ExchangeError,
  GraphIssuanceError,
  RateLimitedError,
  VerifierUnavailableError,
  InvalidTokenError,
  ReplayedTokenError,
  PollError,
  PollTimeoutError,
  PollAbortedError,
  BatchIssuanceError,
} from './errors.js';
export type { FreebirdErrorCode } from './errors.js';

// Export token persistence and polling helpers
export {
  MemoryTokenStore,
  StorageTokenStore,
  tokenId,
} from './client/token_store.js';
export type { StorageTokenStoreOptions } from './client/token_store.js';
export {
  pollExchangeStatus,
  pollGraphIssuanceStatus,
  pollUntilTerminal,
} from './client/poll.js';
export type { PollOptions } from './client/poll.js';
export {
  serializeGraphIssuanceRecoveryContext,
  deserializeGraphIssuanceRecoveryContext,
} from './client/graph_recovery.js';

// Proof-of-Work Sybil helpers (client-generable PoW only — never the
// server-keyed HMAC variants).
export {
  generateProofOfWork,
  verifyPow,
  buildIssueBinding,
  buildPublicIssueBinding,
  buildRenewBinding,
  buildBatchBinding,
} from './client/sybil.js';

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
  BatchIssueReq,
  BatchIssueResp,
  TokenResult,
  PublicBatchIssueReq,
  PublicBatchIssueResp,
  IssueTokensOptions,
  IssuePublicTokensOptions,
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
  TokenStore,
  SybilProof,
  VerifyReq,
  VerifyResp,
  TokenToVerify,
  BatchVerifyReq,
  VerifyResult,
  BatchVerifyResp,
  PublicBearerPass,
  RsaBlindState,
  IssuePublicTokenOptions,
  SybilConfigSummary,
  SybilModeSettings,
  TrustLevelSummary,
  // Export internal types that might be useful for debugging
  BlindState
} from './types.js';

// Optionally export low-level crypto for advanced use cases
// (e.g. if a user wants to manually blind/unblind without the client wrapper)
import * as voprf from './crypto/voprf.js';
import * as graphIssuance from './crypto/graph_issuance.js';
import * as rsa from './crypto/rsa.js';
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
  rsaBlind: rsa.rsaBlind,
  rsaUnblind: rsa.rsaUnblind,
  rsaVerify: rsa.rsaVerify,
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
