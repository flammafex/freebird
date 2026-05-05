# Sybil Modes

Freebird's Sybil layer is an issuer admission system. It decides whether a
client may receive a blinded issuance response. It is not a universal bot
detection system and does not prove that a client is a unique human.

Configure the mode with `SYBIL_RESISTANCE`.

## Summary

| Mode | Best Use | Main Limit |
| --- | --- | --- |
| `none` | Local demos, trusted test environments. | No token-farming resistance. |
| `pow` | Low-friction cost increase. | Weak against cheap compute, botnets, and GPUs. |
| `rate_limit` | Operational throttling by observed client identity. | Weak against IP rotation and shared NATs. |
| `invitation` | Small communities with local trust. | Invite graphs can be farmed or socially attacked. |
| `webauthn` | Per-device/account admission with optional attestation. | Does not prove unique humans; attestation must be configured. |
| `progressive_trust` | Gradual quota increase for returning users. | Fresh identity farming is slowed, not prevented. |
| `proof_of_diversity` | Experimental diversity scoring. | Needs careful operator workflow and privacy review. |
| `multi_party_vouching` | Communities where trusted users can endorse others. | Requires admin curation of voucher set. |
| `combined` | Compose multiple mechanisms. | `or` mode is only as strong as the weakest mechanism. |

## Proof Of Work

`pow` requires clients to find a nonce such that:

```text
SHA256(input || nonce || timestamp)
```

has the configured number of leading zero bits.

The issuer now binds PoW proofs to issuance request context when the proof is
submitted to public issuance routes. For custom clients, the PoW `input` must
match the route-specific request binding.

Single V4 issuance:

```text
freebird:issue:v1:{issuer_id}:{blinded_element_b64}
```

Single V5 public issuance:

```text
freebird:public-issue:v1:{issuer_id}:{blinded_msg_b64}
```

Batch issuance:

```text
freebird:{route_scope}:v1:{issuer_id}:{count}:{digest}
```

where `route_scope` is `issue-batch` or `public-issue-batch`, and `digest` is
base64url without padding of the first 16 bytes of:

```text
SHA256(len_le_u64(element_0) || element_0 || ... || len_le_u64(element_n) || element_n)
```

Replay protection uses the configured Sybil replay store. The default store is
process-local memory. Use `SYBIL_REPLAY_STORE=redis` for restart-safe or
horizontally scaled issuers.

## Rate Limit

`rate_limit` uses server-observed request data instead of trusting a
caller-chosen identity. Depending on available headers and proxy settings, the
issuer derives the client identity from IP address and a hashed User-Agent
fingerprint.

Set `BEHIND_PROXY=true` only when a trusted reverse proxy supplies correct
forwarded headers. Otherwise clients may influence the apparent source address.

## Invitation

`invitation` allows a configured inviter to issue invite codes. Redeeming an
invite creates an invitee identity and consumes the invite.

Public issuance routes reject `RegisteredUser` as a shortcut proof. That proof
shape is kept for internal/admin compatibility, but it is not accepted as a
public issuance bypass.

## WebAuthn

`webauthn` requires users to register and authenticate with WebAuthn before
issuance. `WEBAUTHN_PROOF_SECRET` is required when WebAuthn is enabled.

Hardware/device attestation is available but policy-gated:

- `WEBAUTHN_REQUIRE_ATTESTATION=true` enables attestation enforcement during
  registration.
- `WEBAUTHN_ATTESTATION_POLICY` accepts `none`, `indirect`, `direct`, or
  `enterprise`.
- `WEBAUTHN_ALLOWED_AAGUIDS` can restrict registration to specific
  authenticator models.

Attestation can say something about the authenticator model or attestation
chain. It does not prove a unique human and does not prevent someone from using
multiple allowed devices.

WebAuthn gate proofs are rejected on replay through the configured Sybil replay
store. The default store is process-local memory. Use `SYBIL_REPLAY_STORE=redis`
for restart-safe and multi-node deployments.

## Progressive Trust

`progressive_trust` tracks returning user state and grants quotas according to
configured age, token count, and cooldown levels.

Proofs are checked against current server state and consumed by updating token
count and last-issuance time. This prevents stale progressive-trust proofs from
being reused.

Operators must set non-default salts and secrets for public deployments. Startup
rejects insecure default salts unless the corresponding insecure flag is
explicitly enabled.

## Proof Of Diversity

`proof_of_diversity` scores observed diversity signals and requires a minimum
score. It should be treated as experimental until the operator workflow, privacy
policy, and data-retention story are explicit for a deployment.

Do not market this as a human-uniqueness proof.

## Multi-Party Vouching

`multi_party_vouching` requires a configured number of trusted vouchers to vouch
for a user. Vouches expire and voucher cooldowns limit rapid endorsement.

Vouching proofs are rejected on replay through the configured Sybil replay
store. The default store is process-local memory. Use `SYBIL_REPLAY_STORE=redis`
for restart-safe and multi-node deployments.

## Replay Store

`pow`, `webauthn`, and `multi_party_vouching` record accepted proofs in the
Sybil replay store.

| Variable | Default | Notes |
| --- | --- | --- |
| `SYBIL_REPLAY_STORE` | `memory` | `memory` or `redis`. |
| `SYBIL_REPLAY_REDIS_URL` | none | Redis URL used when `SYBIL_REPLAY_STORE=redis`. Falls back to `REDIS_URL`. |
| `SYBIL_REPLAY_KEY_PREFIX` | `freebird:sybil:replay` | Redis key prefix. |

Use Redis for public issuers that may restart or run more than one instance.

## Combined Mode

`combined` composes mechanisms listed in `SYBIL_COMBINED_MECHANISMS`.

`SYBIL_COMBINED_MODE` controls the policy:

- `and`: every configured mechanism must pass
- `threshold`: at least `SYBIL_COMBINED_THRESHOLD` mechanisms must pass
- `or`: any one configured mechanism may pass

Use `or` for user-experience fallback only. It is not stronger than the weakest
enabled mechanism. For public admission control, prefer `and` or `threshold`
with at least one meaningful non-network signal.
