# Phase 0 crypto fixture provenance

Baseline commit: `ae3fdd28f562701d0867436101e597d71916da3b` (reviewed 2026-07-10).

## V4 Freebird VOPRF KAT

This is a regression vector for Freebird's bespoke construction, **not** an
RFC 9497 conformance vector. Inputs are context `freebird:v4`, input
`freebird-kat-input-v1`, and scalar
`0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`.

Generator: Python `3.14.5` standard-library reference implementation
of P-256 affine arithmetic, `expand_message_xmd(SHA-256)`, direct P-256
SSWU with `Z=-10`, and SHA-256 finalization. It used the Freebird domain
separators exactly: `P256_XMD:SHA-256_SSWU_RO_ || context` and
`VOPRF-P256-SHA256:Finalize || context || SEC1(W)`. The reviewed outputs are
`PK=02515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f`,
`H=025c29e31bfdb54db880f9ba48bee0a5c1b4e42ea5cb63c66c861b8cf7a85779fc`,
`W=037bc77427f26ea7e2dbd0da6561eac05959ec04376a87d63ea2edd52311f2c3d1`,
and `authenticator=dd13cf539fdaf86afa324f0b52be161a7c62612065ba4a42f047312f3e18241d`.

### V4 DLEQ/blinding proof KAT

The same independent Python reference generated this deterministic proof with
blinding scalar `41` and DLEQ proof scalar `42` (both left-padded to 32 bytes).
It uses `DLEQ-P256-v1 || freebird:v4` as the challenge domain separator and
the existing transcript order `G, Y, A, B, T1, T2`, each SEC1-compressed after
the four-byte big-endian domain-separator length. The exact outputs are
`A=0350974ec14559b8a2bf2dbbf39911dc709ae54f0e88fcb88ae7f9372eb78208e1`,
`B=030058b52352750a5ec11f6d63e897bc4fccc19141b317f238360e679a033b7a34`,
and proof
`773a7aace9b437d043df2dfdb690f33b86dd938ab85c8885aaf7026edbe1d036582bad3fc41f0ed1434e2e058e1dbcb096abe8a029bf2b7d6839261365bd6640`.

## V5 public bearer fixture

Generator: OpenSSL `3.6.2 7 Apr 2026`, independently of Freebird. A test-only
RSA-2048 key was generated with `openssl genpkey -algorithm RSA
-pkeyopt rsa_keygen_bits:2048`. Its standard RSA public-key DER was wrapped in
the RFC 4055 RSASSA-PSS SubjectPublicKeyInfo parameters required by the V5
suite: SHA-384 hash, MGF1(SHA-384), and salt length 48. That DER is the fixed
`SPKI_B64` fixture. The message was constructed externally as
`SHA-384("freebird:public-bearer-pass:v5" || 00 || 05 || nonce ||
SHA-256(SPKI) || len(issuer_id) || issuer_id)`, with nonce `20..3f` and issuer
`issuer:fixture:v5`. OpenSSL signed those 48 bytes using
`openssl dgst -sha384 -sign KEY -sigopt rsa_padding_mode:pss -sigopt
rsa_pss_saltlen:48`. It was independently checked with `openssl dgst -sha384
-verify PUBLIC_KEY -keyform DER -sigopt rsa_padding_mode:pss -sigopt
rsa_pss_saltlen:48`, which returned `Verified OK`. The fixed final signature,
complete pass, key ID, message,
and nullifier are embedded in `lib.rs` and are not calculated by the test.
Their exact values are key ID
`4257ffa80a19f072ff27b28d60747ed031b4b36c03fdc71252b3df6a5fe982f9`,
message
`2d1659912a7e91228969587ea710dc0655f4904eaef8c142e989021e15e88c93cf5b56eb0a250dca9134fc0d007c2db5`,
and nullifier `Cv6jUH48F6Mxadrp2vmUHYnqTxSA72E5IDtDOziRTJY`.

Independent generation check date: 2026-07-10. Maintainer reviewer: Project
maintainer (approved in implementation session, 2026-07-10).
The test verifies the fixed signature using Freebird only after asserting the
external fixture fields.
