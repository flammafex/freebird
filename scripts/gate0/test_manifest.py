"""Stdlib contract tests for the closed public Gate 0 manifest."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from validate_manifest import (
    MAX_JSON_BYTES,
    ManifestError,
    load_manifest,
    parse_json_bytes,
    validate_manifest,
)


ROOT = Path(__file__).resolve().parents[2]
PUBLIC_FIXTURE = ROOT / "common" / "test-fixtures" / "v7-graph-reference.json"
SCHEMA_PATH = ROOT / "scripts" / "gate0" / "manifest.schema.json"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sample_manifest() -> dict:
    fixture = json.loads(PUBLIC_FIXTURE.read_text(encoding="utf-8"))
    issuer_id = fixture["issuer_id"]
    verifier_id = "verifier:gate0-test"
    audience = "gate0-test"
    scope_transcript = (
        b"freebird:scope:v4"
        + bytes([len(verifier_id.encode("utf-8"))])
        + verifier_id.encode("utf-8")
        + bytes([len(audience.encode("utf-8"))])
        + audience.encode("utf-8")
    )
    receipt_public = bytes([0x17]) * 32
    receipt_key_id = hashlib.sha256(receipt_public).hexdigest()
    return {
        "version": "scarcity/freebird-gate0/v1",
        "run_id": "gate0-test-run",
        "issuer_origin": "http://127.0.0.1:21001",
        "verifier_origin": "http://127.0.0.1:21002",
        "issuer_id": issuer_id,
        "graph_issuer_id": issuer_id,
        "asset_id": "USD",
        "graph_policy_id": fixture["native_graph_issuance_v7"]["active_policies"][0]["policy_id"],
        "v4": {
            "credential_issuer_id": issuer_id,
            "kid": "YcWArFEd6LC_j5j_02XhSzvz",
            "public_key_b64": "A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW",
            "verifier_id": verifier_id,
            "audience": audience,
            "scope_digest_b64": b64url(hashlib.sha256(scope_transcript).digest()),
        },
        "replay_authority": {
            "authority_id": b64url(bytes([0x29]) * 32),
            "v4_scope_digest_tombstones": [b64url(hashlib.sha256(scope_transcript).digest())],
        },
        "receipt_keyset": {
            "issuer_id": issuer_id,
            "origin": "http://127.0.0.1:21001",
            "profile_id": "freebird/native-exchange/v3",
            "keys": [
                {
                    "key_id": receipt_key_id,
                    "algorithm": "Ed25519",
                    "purpose": "exchange_receipt_v7",
                    "public_key_b64": b64url(receipt_public),
                    "status": "active",
                    "valid_from": 1,
                    "valid_until": MAX_SAFE_INTEGER,
                }
            ],
        },
        "discovery_pins": {
            key: fixture[key]
            for key in (
                "native_bearer_v7",
                "native_bearer_v7_retained",
                "native_exchange_v7",
                "native_graph_issuance_v7",
            )
        },
        "sybil": {"type": "proof_of_work", "difficulty": 8},
    }


class Gate0ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = sample_manifest()

    def assert_rejected(self, mutate) -> None:
        candidate = copy.deepcopy(self.manifest)
        mutate(candidate)
        with self.assertRaises(ManifestError):
            validate_manifest(candidate)

    def test_public_u1_discovery_projection_is_a_valid_manifest(self) -> None:
        raw = json.dumps(self.manifest, separators=(",", ":")).encode("utf-8")
        validated = validate_manifest(parse_json_bytes(raw))
        self.assertEqual(validated["version"], "scarcity/freebird-gate0/v1")
        self.assertEqual(validated["graph_policy_id"], self.manifest["graph_policy_id"])

    def test_recursive_closed_shapes_reject_unknown_and_secret_bearing_members(self) -> None:
        mutations = [
            lambda m: m.__setitem__("redis_url", "redis://secret@127.0.0.1"),
            lambda m: m["v4"].__setitem__("secret_key", "not-public"),
            lambda m: m["replay_authority"].__setitem__("redis_password", "secret"),
            lambda m: m["receipt_keyset"]["keys"][0].__setitem__("private_key", "secret"),
            lambda m: m["discovery_pins"]["native_bearer_v7"].__setitem__("rsa_private_key", "secret"),
            lambda m: m["discovery_pins"]["native_exchange_v7"]["profile"].__setitem__("extra", True),
            lambda m: m["discovery_pins"]["native_graph_issuance_v7"]["active_policies"][0].__setitem__("holder_seed", "secret"),
            lambda m: m["sybil"].__setitem__("fallback", "insecure"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_duplicate_members_are_rejected_at_every_json_depth(self) -> None:
        raw = json.dumps(self.manifest, separators=(",", ":"))
        needle = '"run_id":"gate0-test-run"'
        self.assertIn(needle, raw)
        duplicate_top = raw.replace(needle, needle + ',"run_id":"gate0-test-run"', 1)
        with self.assertRaises(ManifestError):
            parse_json_bytes(duplicate_top.encode("utf-8"))

        duplicate_nested = b'{"outer":{"kid":"one","kid":"two"}}'
        with self.assertRaises(ManifestError):
            parse_json_bytes(duplicate_nested)

    def test_noncanonical_raw32_base64_and_hex_ids_are_rejected(self) -> None:
        self.assert_rejected(lambda m: m["v4"].__setitem__("scope_digest_b64", m["v4"]["scope_digest_b64"] + "="))
        self.assert_rejected(lambda m: m["replay_authority"].__setitem__("authority_id", m["replay_authority"]["authority_id"][:-1]))
        self.assert_rejected(lambda m: m.__setitem__("graph_policy_id", m["graph_policy_id"].upper()))
        self.assert_rejected(lambda m: m["discovery_pins"]["native_graph_issuance_v7"]["active_policies"][0].__setitem__("descriptor_id", "g" * 64))

    def test_inconsistent_public_identity_asset_scope_kid_and_receipt_pins_reject(self) -> None:
        self.assert_rejected(lambda m: m.__setitem__("graph_issuer_id", "issuer:other"))
        self.assert_rejected(lambda m: m["v4"].__setitem__("credential_issuer_id", "issuer:other"))
        self.assert_rejected(lambda m: m["discovery_pins"]["native_bearer_v7"].__setitem__("issuer_id", "issuer:other"))
        self.assert_rejected(lambda m: m["discovery_pins"]["native_graph_issuance_v7"]["active_policies"][0].__setitem__("asset_id", "EUR"))
        self.assert_rejected(lambda m: m["v4"].__setitem__("scope_digest_b64", b64url(bytes([0x55]) * 32)))
        self.assert_rejected(lambda m: m["v4"].__setitem__("kid", ""))
        self.assert_rejected(lambda m: m["receipt_keyset"]["keys"][0].__setitem__("key_id", "00" * 32))
        self.assert_rejected(lambda m: m["receipt_keyset"].__setitem__("origin", "http://127.0.0.1:21002"))
        self.assert_rejected(lambda m: m["replay_authority"].__setitem__("v4_scope_digest_tombstones", []))
        self.assert_rejected(lambda m: m.__setitem__("graph_policy_id", "00" * 32))

    def test_selected_policy_must_be_exactly_one_active_policy(self) -> None:
        graph = self.manifest["discovery_pins"]["native_graph_issuance_v7"]
        selected = graph["active_policies"][0]

        def retained_only(manifest):
            policies = manifest["discovery_pins"]["native_graph_issuance_v7"]
            policies["active_policies"] = []
            policies["retained_policies"] = [selected]

        self.assert_rejected(retained_only)
        self.assert_rejected(lambda m: m.__setitem__("graph_policy_id", "ab" * 32))

    def test_unselected_retained_policy_is_permitted_as_history(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        pins = candidate["discovery_pins"]
        exchange = pins["native_exchange_v7"]
        source_descriptor = copy.deepcopy(exchange["active_descriptors"][0])
        source_policy = copy.deepcopy(pins["native_graph_issuance_v7"]["active_policies"][0])
        historical_spki = bytes(range(1, 129))
        historical_spki_b64 = b64url(historical_spki)
        historical_fingerprint = hashlib.sha256(historical_spki).hexdigest()
        descriptor_id, token_key_id, keyset_id = "d" * 64, "e" * 64, "f" * 64
        source_descriptor.update({
            "descriptor_id": descriptor_id,
            "token_key_id": token_key_id,
            "pubkey_spki_b64": historical_spki_b64,
            "spki_fingerprint": historical_fingerprint,
        })
        exchange["retained_descriptors"].append(source_descriptor)
        exchange["retained_keysets"].append({
            "keyset_id": keyset_id,
            "profile_id": "freebird/native-exchange/v3",
            "descriptor_ids": [descriptor_id],
        })
        source_policy.update({
            "policy_id": "a" * 64,
            "keyset_id": keyset_id,
            "descriptor_id": descriptor_id,
            "token_key_id": token_key_id,
            "pubkey_spki_b64": historical_spki_b64,
            "spki_fingerprint": historical_fingerprint,
        })
        pins["native_graph_issuance_v7"]["retained_policies"].append(source_policy)
        self.assertIs(validate_manifest(candidate), candidate)

    def test_native_v4_kid_must_derive_from_public_pin(self) -> None:
        self.assertEqual(self.manifest["v4"]["kid"], "YcWArFEd6LC_j5j_02XhSzvz")
        self.assert_rejected(lambda m: m["v4"].__setitem__("kid", "unrelated-key-id"))

    def test_loopback_origins_must_be_distinct_high_ports(self) -> None:
        self.assert_rejected(lambda m: m.__setitem__("issuer_origin", "http://localhost:21001"))
        self.assert_rejected(lambda m: m.__setitem__("issuer_origin", "https://127.0.0.1:21001"))
        self.assert_rejected(lambda m: m.__setitem__("issuer_origin", "http://127.0.0.1:9999"))
        self.assert_rejected(lambda m: m.__setitem__("issuer_origin", "http://127.0.0.1:65536"))
        self.assert_rejected(lambda m: m.__setitem__("verifier_origin", m["issuer_origin"]))

    def test_pow_and_integer_precision_bounds_are_enforced(self) -> None:
        self.assert_rejected(lambda m: m["sybil"].__setitem__("difficulty", 0))
        self.assert_rejected(lambda m: m["sybil"].__setitem__("difficulty", 25))
        self.assert_rejected(lambda m: m["discovery_pins"]["native_bearer_v7"].__setitem__("amount_minor", 9_007_199_254_740_992))
        self.assert_rejected(lambda m: m["receipt_keyset"]["keys"][0].__setitem__("valid_until", 9_007_199_254_740_992))
        self.assert_rejected(lambda m: m["discovery_pins"]["native_graph_issuance_v7"]["active_policies"][0].__setitem__("quantity", True))
        self.assert_rejected(lambda m: m["discovery_pins"]["native_exchange_v7"].__setitem__("version", 3.0))

    def test_manifest_input_size_is_bounded(self) -> None:
        with self.assertRaises(ManifestError):
            parse_json_bytes(b" " * (MAX_JSON_BYTES + 1))

    def test_manifest_file_loader_uses_bounded_closed_parser(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(self.manifest), encoding="utf-8")
            self.assertEqual(load_manifest(path)["run_id"], "gate0-test-run")

    def test_schema_is_draft_2020_and_closes_every_object(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

        def visit(node) -> None:
            if type(node) is dict:
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False)
                for child in node.values():
                    visit(child)
            elif type(node) is list:
                for child in node:
                    visit(child)

        visit(schema)


if __name__ == "__main__":
    unittest.main()
