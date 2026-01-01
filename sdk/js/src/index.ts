/**
 * Freebird SDK
 * Anonymous authentication using VOPRF (Verifiable Oblivious Pseudorandom Function).
 *
 * @module @freebird/sdk
 */

// Export the main client class
export { FreebirdClient } from './client';

// Export types needed for configuration and usage
export type {
  ClientConfig,
  IssuerMetadata,
  IssueRequest,
  IssueResponse,
  FreebirdToken,
  SybilProof,
  // Export internal types that might be useful for debugging
  BlindState
} from './types';

// Optionally export low-level crypto for advanced use cases
// (e.g. if a user wants to manually blind/unblind without the client wrapper)
import * as voprf from './crypto/voprf';
export const crypto = {
  blind: voprf.blind,
  finalize: voprf.finalize
};