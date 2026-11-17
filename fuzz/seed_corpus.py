#!/usr/bin/env python3
"""Recreate small, deterministic fuzz corpora from the checked-in RFC vectors."""

import base64
import json
from pathlib import Path

FUZZ = Path(__file__).resolve().parent
FIXTURES = FUZZ.parent / "common/test-fixtures/privacy-pass"
TARGETS = (
    "token_request",
    "token_response",
    "token",
    "token_challenge",
    "authorization_header",
    "public_key_spki",
    "secret_key_pkcs8",
)


def seed(target, name, data):
    directory = FUZZ / "corpus" / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def header(token):
    return b'PrivateToken token="' + base64.urlsafe_b64encode(token) + b'"'


def challenge(issuer, context, origins, token_type=b"\x00\x02"):
    return (
        token_type
        + len(issuer).to_bytes(2, "big")
        + issuer
        + bytes([len(context)])
        + context
        + len(origins).to_bytes(2, "big")
        + origins
    )


def main():
    for target in TARGETS:
        for name, data in {
            "empty": b"",
            "one-byte": b"\x00",
            "type-only": b"\x00\x02",
            "max-length-prefix": b"\x00\x02\xff\xff",
            "der-empty-sequence": b"\x30\x00",
            "der-indefinite-length": b"\x30\x80\x00\x00",
        }.items():
            seed(target, name, data)

    for path in sorted(FIXTURES.glob("*.json")):
        for vector in json.loads(path.read_text())["vectors"]:
            prefix = f"{path.stem}-{vector['vector']}"
            fields = {
                key: bytes.fromhex(value)
                for key, value in vector.items()
                if key != "vector"
            }
            for field, target in {
                "token_request": "token_request",
                "token_response": "token_response",
                "token": "token",
                "token_challenge": "token_challenge",
                "pkI": "public_key_spki",
                "skI": "secret_key_pkcs8",
            }.items():
                if field not in fields:
                    continue
                data = fields[field]
                seed(target, f"{prefix}-{field}", data)
                seed(target, f"{prefix}-{field}-truncated", data[:-1])
                seed(target, f"{prefix}-{field}-trailing", data + b"\x00")
                if field == "token":
                    seed("authorization_header", prefix, header(data))
                elif field == "skI":
                    # The RFC's hex field contains PEM; also seed its PKCS#8 DER.
                    der = base64.b64decode(
                        b"".join(line for line in data.splitlines() if not line.startswith(b"-")),
                        validate=True,
                    )
                    seed(target, f"{prefix}-pkcs8-der", der)
            if "issuer_name" in fields:
                seed(
                    "token_challenge",
                    prefix,
                    challenge(
                        fields["issuer_name"],
                        fields["redemption_context"],
                        fields["origin_info"],
                        fields["token_type"],
                    ),
                )
            # Retain the other decoded hex fields as malformed wire inputs too.
            for field in (
                "token_type", "issuer_name", "redemption_context", "origin_info",
                "nonce", "token_key_id", "token_authenticator_input", "blind", "salt",
            ):
                if field in fields:
                    seed("token", f"{prefix}-{field}", fields[field])
            if "token_authenticator_input" in fields:
                seed("token_request", prefix, fields["token_authenticator_input"])

    for target, length in (("token_request", 259), ("token_response", 256), ("token", 354)):
        wire = b"\x00\x02" + bytes(length - 2)
        seed(target, "zero-body", wire)
        seed(target, "wrong-type", b"\x00\x00" + wire[2:])
        seed(target, "too-short", wire[:-1])
        seed(target, "too-long", wire + b"\x00")
    for context in (b"", bytes(32)):
        for origins in (b"", b"origin.example", b"a.example,b.example"):
            seed(
                "token_challenge",
                f"handmade-{len(context)}-{len(origins)}",
                challenge(b"issuer.example", context, origins),
            )
    for name, value in {
        "zero-token": header(b"\x00\x02" + bytes(352)),
        "missing-token": b"PrivateToken ignored=yes",
        "unterminated-quote": b'PrivateToken token="',
        "escaped-quote": b'PrivateToken extra="a,b\\\"c", token="AA=="',
        "non-ascii": b"PrivateToken token=\xff",
        "crlf": b'PrivateToken token="AA=="\r\nX: y',
        "duplicate-token": b'PrivateToken token="AA==", TOKEN="AA=="',
    }.items():
        seed("authorization_header", name, value)

    size = sum(path.stat().st_size for path in (FUZZ / "corpus").glob("*/*"))
    assert size < 1_000_000, size
    print(f"Seed corpus: {size} bytes")


if __name__ == "__main__":
    main()
