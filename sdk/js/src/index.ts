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
  buildNativeBearerV7IssueBinding,
  buildNativeBearerV7BatchBinding,
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
  V7CanonicalId,
  V7TokenKeyId,
  V7DescriptorId,
  V7SpkiFingerprint,
  V7Bytes32,
  V7OwnerCommitment,
  V7Nonce,
  V7Nullifier,
  V7MessageRandomizer,
  V7Amount,
  V7Raw384,
  V7KeyIdentity,
  V7KeyBinding,
  V7Body,
  V7Token,
  V7BlindState,
  V7DirectBinding,
  V7VoprfKeyInfo,
  V7NativeBearerKeyInfo,
  V7DirectKeyDiscovery,
  V7DirectRegistry,
  V7DirectRegistryEntry,
} from './types.js';
export type { V7BodyInput } from './crypto/native_bearer_v7.js';
export type {
  NativeBearerV7IssueOptions,
  NativeBearerV7BatchIssueOptions,
} from './client/native_bearer_v7.js';

import * as voprf from './crypto/voprf.js';
import * as nativeBearerV7 from './crypto/native_bearer_v7.js';

/** Low-level V4 and direct V7 cryptographic helpers. */
export const crypto = {
  blind: voprf.blind,
  finalize: voprf.finalize,
  buildScopeDigest: voprf.buildScopeDigest,
  buildPrivateTokenInput: voprf.buildPrivateTokenInput,
  buildRedemptionToken: voprf.buildRedemptionToken,
  parseRedemptionToken: voprf.parseRedemptionToken,
  nativeBearerV7: {
    bindingFromV7Discovery: nativeBearerV7.bindingFromV7Discovery,
    blindV7: nativeBearerV7.blindV7,
    buildV7Body: nativeBearerV7.buildV7Body,
    deriveV7Nullifier: nativeBearerV7.deriveV7Nullifier,
    directBindingFromDiscovery: nativeBearerV7.directBindingFromDiscovery,
    finalizeV7: nativeBearerV7.finalizeV7,
    parseV7Body: nativeBearerV7.parseV7Body,
    parseV7Token: nativeBearerV7.parseV7Token,
    serializeV7Token: nativeBearerV7.serializeV7Token,
    v7ApplicationDigest: nativeBearerV7.v7ApplicationDigest,
    v7ArtifactDigest: nativeBearerV7.v7ArtifactDigest,
    v7BodyTranscript: nativeBearerV7.v7BodyTranscript,
    verifyV7Token: nativeBearerV7.verifyV7Token,
  },
};
