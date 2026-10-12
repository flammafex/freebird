/** @module @flammafex/freebird */

export { FreebirdClient } from './client.js';

export {
  FreebirdError,
  DiscoveryError,
  StalePublicKeyError,
  VerificationError,
  VerifierNotConfiguredError,
  RateLimitedError,
  VerifierUnavailableError,
  InvalidTokenError,
  ReplayedTokenError,
  BatchIssuanceError,
  BatchIssuanceInterruptedError,
} from './errors.js';
export type { PublicFreebirdErrorCode as FreebirdErrorCode } from './errors.js';

export { MemoryTokenStore, StorageTokenStore, tokenId } from './client/token_store.js';
export type { StorageTokenStoreOptions } from './client/token_store.js';

export {
  generateProofOfWork,
  verifyPow,
  buildIssueBinding,
  buildRenewBinding,
  buildBatchBinding,
} from './client/sybil.js';

export type {
  ClientConfig,
  IssuerMetadata,
  VerifierMetadata,
  IssueRequest,
  IssueResponse,
  BatchIssueReq,
  BatchIssueResp,
  TokenResult,
  IssueTokensOptions,
  FreebirdToken,
  TokenStore,
  SybilProof,
  SybilProofRequestContext,
  SybilProofFactory,
  VerifyReq,
  VerifyResp,
  TokenToVerify,
  BatchVerifyReq,
  VerifyResult,
  BatchVerifyResp,
  SybilConfigSummary,
  SybilModeSettings,
  TrustLevelSummary,
  BlindState,
} from './types.js';

import * as voprf from './crypto/voprf.js';

/** Low-level V4 VOPRF cryptographic helpers. */
export const crypto = {
  blind: voprf.blind,
  finalize: voprf.finalize,
  buildScopeDigest: voprf.buildScopeDigest,
  buildPrivateTokenInput: voprf.buildPrivateTokenInput,
  buildRedemptionToken: voprf.buildRedemptionToken,
  parseRedemptionToken: voprf.parseRedemptionToken,
};
