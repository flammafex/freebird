// SPDX-License-Identifier: Apache-2.0 OR MIT

/**
 * V5 public-token issuance entry points.
 *
 * The implementation lives beside the V4 issuance code so legacy callers and
 * current-key callers share the same request-binding and rotation checks.
 * This small module gives protocol-focused consumers a stable import without
 * changing the existing package facade.
 */
export {
  issuePublicToken,
  issuePublicTokens,
  issueCurrentPublicToken,
  issueCurrentPublicTokens,
} from './issuance.js';
export type {
  IssuePublicTokenForCurrentKeyOptions,
  IssuePublicTokensForCurrentKeyOptions,
} from '../types.js';

// Descriptive aliases used by protocol-oriented callers.
export {
  issueCurrentPublicToken as issuePublicTokenForCurrentKey,
  issueCurrentPublicTokens as issuePublicTokensForCurrentKey,
} from './issuance.js';
