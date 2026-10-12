# Cryptographic Assumptions

This document records engineering assumptions behind the current token flows.
It is not a cryptographic proof, implementation review, or external audit.
Freebird is pre-1.0 and public deployments are experimental.

## V4 private-verification tokens

V4 uses a Freebird-specific, bespoke P-256 VOPRF-like construction. The design
relies on the expected hardness of the underlying elliptic-curve discrete-log
problem, the security of its hash and transcript functions, correct blinding
and unblinding, unpredictable client randomness, and protected issuer/key
material.

The construction is not RFC 9497 interoperable. Existing Freebird-specific
fixtures and negative tests are regression evidence for the implementation; they
are not RFC conformance vectors, a formal proof, or evidence of interoperability.

The privacy statement assumes that a blinded request does not reveal the client
secret input to an honest issuer through the protocol transcript, and that the
client's blinding/finalization steps are performed correctly. This assumption
does not survive a compromised client, malicious endpoint behavior, key
compromise, or correlation through external metadata.

## Shared assumptions

The V4 flow depends on:

- correct domain separation, scope, key identifiers, parsing, and validation;
- authentic issuer metadata and correct verifier configuration;
- secret-key confidentiality and safe key rotation/retention;
- secure random generation in clients and services;
- transport integrity and confidentiality for the deployment; and
- correct storage and atomicity for nullifiers and admission-proof replay state.

The project documentation does not claim resistance to a compromised issuer
key, compromised service host, malicious issuer, malicious verifier, or colluding
issuer/verifier.

## What these assumptions do not imply

Cryptographic validity does not imply unique-human identity, Sybil resistance,
browser privacy, timing privacy, metadata anonymity, tamper-evident logging, or
honest operator behavior. It also does not make the bespoke V4 construction
interoperable with RFC 9497 or another protocol.

Any future change to a primitive, wire format, nullifier derivation, or trust
boundary requires a separate security review and compatibility analysis. The
current documentation intentionally does not promise such future work.
