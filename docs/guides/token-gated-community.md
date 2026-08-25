# Token-gated community (conceptual)

This low-stakes example shows how a small test community might use a token as a
membership gate. It is a conceptual deployment pattern, not a complete
authorization, identity, moderation, or abuse-prevention system.

## Conceptual flow

1. An issuer admits a participant using the deployment's configured Sybil mode
   and issues a V4 private-verification token or an enabled V7 native bearer.
2. The community edge checks the token with `/v1/check` before allowing a
   session or a low-risk action.
3. For an action intended to be single-use, the edge calls `/v1/verify` and
   handles a replay rejection as a normal denial.
4. The application keeps authorization policy, moderation state, and rate
   limits separate from token verification.

Use `check` when validation must not spend the token; use `verify` only when the
operation is intentionally consuming. A valid token does not identify a person,
prove good behavior, or by itself authorize every action in a community.

## Demo boundaries

Run this only with synthetic users and a local or isolated deployment using the
[quick start](../quick-start.md). Keep `/admin` private and use a deliberate
Sybil configuration; `SYBIL_RESISTANCE=none` is for the local interface flow,
not a public issuer. For a real deployment, configure HTTPS, durable Redis,
persistent key material, and operational recovery as described in [Production
Deployment](../production-deployment.md).
