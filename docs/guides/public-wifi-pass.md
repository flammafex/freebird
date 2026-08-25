# Public Wi-Fi pass (conceptual)

This is a conceptual pass example for a lab or other low-stakes network
experiment. It is **not a production-ready public Wi-Fi deployment** and does
not guarantee subscriber anonymity, device privacy, fair access, or network
security.

## Conceptual flow

1. A test service issues a token to a participant under the selected token
   family and policy.
2. A captive-portal application calls `/v1/check` to validate possession
   without consuming the token while the portal completes its local flow.
3. The portal or gateway calls `/v1/verify` at the chosen one-time admission
   point, then applies its own session and network policy.
4. The gateway handles replay rejection without exposing token values in logs or
   query strings, and applies any separate session or network lifetime policy.

The verifier's check operation is non-consuming, while verify records the token
spend. The network controller, DHCP/DNS system, firewall, and accounting layer
remain outside Freebird and must be designed independently.

## Validity and expiration

V4 has no issuer-enforced token expiry. V7 validity comes from the signer and its
published discovery policy. A required expiration for a Wi-Fi pass must
therefore be a correctly configured V7 policy or be enforced externally by the
captive portal, gateway, or another application component; it is not a generic
Freebird expiration guarantee.

## Lab-only deployment notes

Use the local [quick start](../quick-start.md) and synthetic passes. Do not
bind the Compose ports to an untrusted interface or use the development memory
replay store for a real network. A public deployment needs HTTPS at the trusted
proxy, durable Redis replay protection, persistent keys, backups, monitoring,
and a review of captive-portal and network privacy properties; see [Production
Deployment](../production-deployment.md).
