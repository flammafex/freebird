# NIP-Freebird: Anonymous Authorization with Freebird Tokens

`draft` `optional` `author:freebird`

This draft defines a method for relays to challenge clients for authorization without requiring a persistent identity or payment.

## Motivation
Current relay protections (NIP-42, paid admission) require persistent identities or payment trails, which enables user tracking. This NIP allows relays to rate-limit or gate access based on anonymous tokens.

## Protocol Flow

The flow extends the standard `AUTH` command.

### 1. Connection & Challenge
When a client connects, the relay sends an auth challenge indicating it accepts Freebird tokens.

```json
["AUTH", "freebird:v1:challenge:<random-string>"]
```

### 2. Token Issuance (Out of Band)
The client recognizes the `freebird:v1` prefix. It connects to the Issuer URL
(known via relay metadata or configuration) and obtains either a V4 private
Freebird token scoped to the relay verifier, or a V5 public bearer pass accepted
by the relay.

### 3. Response
The client sends the token back to the relay using the `AUTH` command.

```json
["AUTH", {
  "kind": 22242,
  "content": "<base64url-encoded-Freebird-token>",
  "tags": [
    ["issuer", "https://issuer.example.com"],
    ["freebird_version", "4"]
  ]
}]
```

### 4. Verification
The relay submits the token to its Freebird verifier. If valid and not replayed,
the connection is authenticated.

```json
["OK", "event_id", true, "auth-success"]
```
