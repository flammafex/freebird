# Anonymous feedback (conceptual)

This is a low-stakes product sketch for experimenting with a one-time feedback
submission. It is **not an anonymous voting design** and does not claim that a
Freebird token alone hides network metadata, application logs, timing, or
operator knowledge.

## Conceptual flow

1. A test deployment issues a token to an eligible participant.
2. The feedback client keeps the token out of the feedback body and submits the
   feedback to the application over its normal authenticated transport.
3. The application calls verifier `/v1/check` to test possession without
   consuming the token while preparing a form response.
4. On accepted submission, the application calls `/v1/verify` once and records
   only the application result it actually needs.

`/v1/check` does not consume; `/v1/verify` consumes and rejects replay. This
   makes the token a one-use admission signal, not a vote-counting protocol.

## Deployment notes for a demo

Use the Docker Compose development flow in the [quick
start](../quick-start.md), keep the service local, and use synthetic feedback.
Do not put tokens, proofs, or private application data in logs. Decide in
advance what the application stores, because Freebird cannot undo correlation
introduced by an application database, IP log, browser identifier, or admin
workflow.

For a real privacy-sensitive system, perform a separate threat-model and legal
review. Do not describe this sketch as anonymous voting or as a guarantee of
unlinkability.
