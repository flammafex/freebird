#!/usr/bin/env python3
"""Bounded stdlib validation for the public Scarcity Gate 0 manifest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

VERSION = "scarcity/freebird-gate0/v1"
DIRECT_PROFILE = "scarcity/native-bearer/v7"
EXCHANGE_PROFILE = "freebird/native-exchange/v3"
GRAPH_PROFILE = "freebird/native-graph-issuance/v7"
SUITE = "RSABSSA-SHA384-PSS-Randomized-V7"
RECEIPT_PURPOSE = "exchange_receipt_v7"
MAX_JSON_BYTES = 4_000_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_U64 = (1 << 64) - 1
MAX_ITEMS = 64

TOP_FIELDS = {
    "version", "run_id", "issuer_origin", "verifier_origin", "issuer_id",
    "graph_issuer_id", "asset_id", "graph_policy_id", "v4", "replay_authority",
    "receipt_keyset", "discovery_pins", "sybil",
}
V4_FIELDS = {
    "credential_issuer_id", "kid", "public_key_b64", "verifier_id", "audience",
    "scope_digest_b64",
}
REPLAY_FIELDS = {"authority_id", "v4_scope_digest_tombstones"}
RECEIPT_SET_FIELDS = {"issuer_id", "origin", "profile_id", "keys"}
RECEIPT_KEY_FIELDS = {
    "key_id", "algorithm", "purpose", "public_key_b64", "status", "valid_from",
    "valid_until",
}
DISCOVERY_PIN_FIELDS = {
    "native_bearer_v7", "native_bearer_v7_retained", "native_exchange_v7",
    "native_graph_issuance_v7",
}
DIRECT_FIELDS = {
    "profile_id", "issuer_id", "descriptor_id", "token_key_id", "asset_id",
    "amount_minor", "suite", "modulus_bits", "exponent", "pubkey_spki_b64",
    "spki_fingerprint", "valid_from", "valid_until",
}
EXCHANGE_FIELDS = {
    "version", "profile", "active_descriptors", "retained_descriptors",
    "active_keysets", "retained_keysets", "transitions",
}
EXCHANGE_PROFILE_FIELDS = {
    "version", "profile_id", "graph_id", "suite", "modulus_bits", "exponent",
}
EXCHANGE_DESCRIPTOR_FIELDS = DIRECT_FIELDS
KEYSET_FIELDS = {"keyset_id", "profile_id", "descriptor_ids"}
SLOT_FIELDS = {"descriptor_id", "keyset_id", "slot_id", "quantity"}
TRANSITION_FIELDS = {
    "transition_id", "profile_id", "source_keyset_id", "target_keyset_id",
    "source_slots", "output_slots",
}
GRAPH_FIELDS = {"version", "profile_id", "active_policies", "retained_policies"}
POLICY_FIELDS = {
    "policy_id", "profile_id", "graph_id", "keyset_id", "descriptor_id", "token_key_id",
    "issuer_id", "asset_id", "amount_minor", "suite", "modulus_bits", "exponent",
    "quantity", "pubkey_spki_b64", "spki_fingerprint", "valid_from", "valid_until",
}
SYBIL_FIELDS = {"type", "difficulty"}
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TEXT_RE = re.compile(r"^[\x21-\x7e]+$")
ORIGIN_RE = re.compile(
    r"^http://127\.0\.0\.1:(?:[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
)


class ManifestError(ValueError):
    """A public manifest failed closed validation."""


def _reject_constant(_value: str) -> None:
    raise ManifestError("non-finite JSON number is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("duplicate JSON object member")
        result[key] = value
    return result


def parse_json_bytes(data: bytes | bytearray | memoryview) -> Any:
    raw = bytes(data)
    if len(raw) > MAX_JSON_BYTES:
        raise ManifestError("manifest exceeds the input size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ManifestError("manifest is not bounded valid UTF-8 JSON") from error


def load_manifest(path: str | Path) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_JSON_BYTES + 1)
    except OSError as error:
        raise ManifestError("manifest file could not be read") from error
    return validate_manifest(parse_json_bytes(data))


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ManifestError(f"{label}: unknown or missing member")
    return value


def _text(value: Any, label: str, maximum: int = 128) -> str:
    if type(value) is not str:
        raise ManifestError(f"{label}: invalid bounded text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ManifestError(f"{label}: invalid bounded text") from error
    if not 1 <= len(encoded) <= maximum:
        raise ManifestError(f"{label}: invalid bounded text")
    if not value.isascii() or TEXT_RE.fullmatch(value) is None:
        raise ManifestError(f"{label}: expected printable ASCII text")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or HEX32_RE.fullmatch(value) is None:
        raise ManifestError(f"{label}: expected canonical lowercase raw32 hex")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int = MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ManifestError(f"{label}: integer outside the safe permitted range")
    return value


def _constant_integer(value: Any, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise ManifestError(f"{label}: unsupported integer constant")


def _origin(value: Any, label: str) -> tuple[str, int]:
    if type(value) is not str or ORIGIN_RE.fullmatch(value) is None:
        raise ManifestError(f"{label}: expected high-loopback HTTP origin")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ManifestError(f"{label}: invalid loopback port") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port is None
        or not 20_000 <= port <= 65_535
        or value != f"http://127.0.0.1:{port}"
    ):
        raise ManifestError(f"{label}: non-canonical loopback origin")
    return value, port


def _decode_b64(value: Any, length: int, label: str) -> bytes:
    if type(value) is not str or B64URL_RE.fullmatch(value) is None:
        raise ManifestError(f"{label}: expected unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, base64.binascii.Error) as error:
        raise ManifestError(f"{label}: invalid base64url") from error
    if len(decoded) != length or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ManifestError(f"{label}: non-canonical fixed-width base64url")
    return decoded


def _decode_spki(value: Any, label: str) -> bytes:
    if type(value) is not str or not 1 <= len(value) <= 5462 or B64URL_RE.fullmatch(value) is None:
        raise ManifestError(f"{label}: invalid bounded canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, base64.binascii.Error) as error:
        raise ManifestError(f"{label}: invalid base64url") from error
    if not 1 <= len(decoded) <= 4096 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ManifestError(f"{label}: non-canonical SPKI encoding")
    return decoded


def _parse_amount(value: Any, label: str) -> int:
    if type(value) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None:
        raise ManifestError(f"{label}: expected canonical positive decimal string")
    amount = int(value)
    if amount > MAX_U64:
        raise ManifestError(f"{label}: amount exceeds u64")
    return amount


def _validate_direct(record: Any, issuer_id: str, asset_id: str, seen: set[str], label: str) -> None:
    item = _object(record, DIRECT_FIELDS, label)
    if item["profile_id"] != "scarcity/native-bearer/v7" or item["issuer_id"] != issuer_id:
        raise ManifestError(f"{label}: issuer or direct profile mismatch")
    if _text(item["asset_id"], f"{label}.asset_id") != asset_id:
        raise ManifestError(f"{label}: asset mismatch")
    ids = [_identifier(item[field], f"{label}.{field}") for field in ("descriptor_id", "token_key_id", "spki_fingerprint")]
    if len(set(ids)) != len(ids) or any(value in seen for value in ids):
        raise ManifestError(f"{label}: direct key identity collision")
    seen.update(ids)
    if item["suite"] != SUITE:
        raise ManifestError(f"{label}: unsupported direct RSA suite parameters")
    _constant_integer(item["modulus_bits"], 3072, f"{label}.modulus_bits")
    _constant_integer(item["exponent"], 65537, f"{label}.exponent")
    _integer(item["amount_minor"], f"{label}.amount_minor", 1, MAX_SAFE_INTEGER)
    valid_from = _integer(item["valid_from"], f"{label}.valid_from", 1)
    valid_until = _integer(item["valid_until"], f"{label}.valid_until", 2)
    if valid_from >= valid_until:
        raise ManifestError(f"{label}: invalid direct validity interval")
    spki = _decode_spki(item["pubkey_spki_b64"], f"{label}.pubkey_spki_b64")
    fingerprint = hashlib.sha256(spki).hexdigest()
    if fingerprint != item["spki_fingerprint"]:
        raise ManifestError(f"{label}: SPKI fingerprint mismatch")


def _validate_exchange(exchange_value: Any, issuer_id: str, asset_id: str) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    exchange = _object(exchange_value, EXCHANGE_FIELDS, "discovery_pins.native_exchange_v7")
    _constant_integer(exchange["version"], 3, "native_exchange_v7.version")
    profile = _object(exchange["profile"], EXCHANGE_PROFILE_FIELDS, "native_exchange_v7.profile")
    if (
        profile["profile_id"] != EXCHANGE_PROFILE
        or profile["suite"] != SUITE
    ):
        raise ManifestError("native_exchange_v7.profile: unsupported exchange profile")
    _constant_integer(profile["version"], 3, "native_exchange_v7.profile.version")
    _constant_integer(profile["modulus_bits"], 3072, "native_exchange_v7.profile.modulus_bits")
    _constant_integer(profile["exponent"], 65537, "native_exchange_v7.profile.exponent")
    graph_id = _identifier(profile["graph_id"], "native_exchange_v7.profile.graph_id")

    descriptors: dict[str, dict[str, Any]] = {}
    reserved_ids: set[str] = set()
    reserved_keys: set[str] = set()
    reserved_fingerprints: set[str] = set()
    for group_name in ("active_descriptors", "retained_descriptors"):
        group = exchange[group_name]
        if type(group) is not list or len(group) > MAX_ITEMS:
            raise ManifestError(f"native_exchange_v7.{group_name}: invalid array")
        for index, descriptor_value in enumerate(group):
            label = f"native_exchange_v7.{group_name}[{index}]"
            descriptor = _object(descriptor_value, EXCHANGE_DESCRIPTOR_FIELDS, label)
            descriptor_id = _identifier(descriptor["descriptor_id"], f"{label}.descriptor_id")
            token_key_id = _identifier(descriptor["token_key_id"], f"{label}.token_key_id")
            fingerprint_id = _identifier(descriptor["spki_fingerprint"], f"{label}.spki_fingerprint")
            if len({descriptor_id, token_key_id, fingerprint_id}) != 3:
                raise ManifestError(f"{label}: colliding exchange key identifiers")
            if (
                descriptor_id in reserved_ids
                or token_key_id in reserved_keys
                or fingerprint_id in reserved_fingerprints
            ):
                raise ManifestError(f"{label}: duplicate exchange descriptor identity")
            reserved_ids.add(descriptor_id)
            reserved_keys.add(token_key_id)
            reserved_fingerprints.add(fingerprint_id)
            if descriptor["profile_id"] != EXCHANGE_PROFILE or descriptor["issuer_id"] != issuer_id:
                raise ManifestError(f"{label}: issuer or exchange profile mismatch")
            if _text(descriptor["asset_id"], f"{label}.asset_id") != asset_id:
                raise ManifestError(f"{label}: asset mismatch")
            _parse_amount(descriptor["amount_minor"], f"{label}.amount_minor")
            if descriptor["suite"] != SUITE:
                raise ManifestError(f"{label}: unsupported exchange RSA suite parameters")
            _constant_integer(descriptor["modulus_bits"], 3072, f"{label}.modulus_bits")
            _constant_integer(descriptor["exponent"], 65537, f"{label}.exponent")
            valid_from = _integer(descriptor["valid_from"], f"{label}.valid_from", 0)
            valid_until = _integer(descriptor["valid_until"], f"{label}.valid_until", 1)
            if valid_from >= valid_until:
                raise ManifestError(f"{label}: invalid exchange validity interval")
            spki = _decode_spki(descriptor["pubkey_spki_b64"], f"{label}.pubkey_spki_b64")
            if hashlib.sha256(spki).hexdigest() != fingerprint_id:
                raise ManifestError(f"{label}: SPKI fingerprint mismatch")
            descriptors[descriptor_id] = descriptor

    keysets: dict[str, dict[str, Any]] = {}
    for group_name in ("active_keysets", "retained_keysets"):
        group = exchange[group_name]
        if type(group) is not list or len(group) > MAX_ITEMS:
            raise ManifestError(f"native_exchange_v7.{group_name}: invalid array")
        for index, keyset_value in enumerate(group):
            label = f"native_exchange_v7.{group_name}[{index}]"
            keyset = _object(keyset_value, KEYSET_FIELDS, label)
            keyset_id = _identifier(keyset["keyset_id"], f"{label}.keyset_id")
            ids = keyset["descriptor_ids"]
            if (
                keyset["profile_id"] != EXCHANGE_PROFILE
                or type(ids) is not list
                or not 1 <= len(ids) <= MAX_ITEMS
                or any(type(value) is not str for value in ids)
                or len(set(ids)) != len(ids)
            ):
                raise ManifestError(f"{label}: invalid keyset fields")
            for descriptor_id in ids:
                _identifier(descriptor_id, f"{label}.descriptor_ids")
                if descriptor_id not in descriptors:
                    raise ManifestError(f"{label}: references missing descriptor")
            if keyset_id in keysets:
                raise ManifestError(f"{label}: duplicate keyset ID")
            keysets[keyset_id] = keyset

    transition_ids: set[str] = set()
    transitions = exchange["transitions"]
    if type(transitions) is not list or len(transitions) > MAX_ITEMS:
        raise ManifestError("native_exchange_v7.transitions: invalid array")
    for index, transition_value in enumerate(transitions):
        label = f"native_exchange_v7.transitions[{index}]"
        transition = _object(transition_value, TRANSITION_FIELDS, label)
        transition_id = _identifier(transition["transition_id"], f"{label}.transition_id")
        source_id = _identifier(transition["source_keyset_id"], f"{label}.source_keyset_id")
        target_id = _identifier(transition["target_keyset_id"], f"{label}.target_keyset_id")
        if (
            transition["profile_id"] != EXCHANGE_PROFILE
            or source_id == target_id
            or source_id not in keysets
            or target_id not in keysets
        ):
            raise ManifestError(f"{label}: invalid transition keyset binding")
        slot_ids: set[str] = set()
        descriptor_members: set[str] = set()
        for slot_field, keyset_id in (("source_slots", source_id), ("output_slots", target_id)):
            slots = transition[slot_field]
            if type(slots) is not list or not 1 <= len(slots) <= MAX_ITEMS:
                raise ManifestError(f"{label}.{slot_field}: invalid slot array")
            allowed_descriptors = set(keysets[keyset_id]["descriptor_ids"])
            for slot_index, slot_value in enumerate(slots):
                slot_label = f"{label}.{slot_field}[{slot_index}]"
                slot = _object(slot_value, SLOT_FIELDS, slot_label)
                descriptor_id = _identifier(slot["descriptor_id"], f"{slot_label}.descriptor_id")
                actual_keyset_id = _identifier(slot["keyset_id"], f"{slot_label}.keyset_id")
                slot_id = _text(slot["slot_id"], f"{slot_label}.slot_id")
                if (
                    actual_keyset_id != keyset_id
                    or descriptor_id not in allowed_descriptors
                    or type(slot["quantity"]) is not int
                    or slot["quantity"] != 1
                    or slot_id in slot_ids
                    or descriptor_id in descriptor_members
                ):
                    raise ManifestError(f"{slot_label}: invalid or duplicate slot membership")
                slot_ids.add(slot_id)
                descriptor_members.add(descriptor_id)
        if len(transition["source_slots"]) + len(transition["output_slots"]) > MAX_ITEMS:
            raise ManifestError(f"{label}: too many total slots")
        if transition_id in transition_ids:
            raise ManifestError(f"{label}: duplicate transition ID")
        transition_ids.add(transition_id)

    return descriptors, keysets


def _validate_graph(
    graph_value: Any,
    graph_issuer_id: str,
    asset_id: str,
    exchange_graph_id: str,
    descriptors: dict[str, dict[str, Any]],
    keysets: dict[str, dict[str, Any]],
    pinned_policy_id: str,
) -> None:
    graph = _object(graph_value, GRAPH_FIELDS, "discovery_pins.native_graph_issuance_v7")
    _constant_integer(graph["version"], 7, "native_graph_issuance_v7.version")
    if graph["profile_id"] != GRAPH_PROFILE:
        raise ManifestError("native_graph_issuance_v7: unsupported graph profile")
    policy_ids: set[str] = set()
    graph_token_ids: set[str] = set()
    selected_active_count = 0
    for group_name in ("active_policies", "retained_policies"):
        group = graph[group_name]
        if type(group) is not list or len(group) > MAX_ITEMS:
            raise ManifestError(f"native_graph_issuance_v7.{group_name}: invalid array")
        for index, policy_value in enumerate(group):
            label = f"native_graph_issuance_v7.{group_name}[{index}]"
            policy = _object(policy_value, POLICY_FIELDS, label)
            policy_id = _identifier(policy["policy_id"], f"{label}.policy_id")
            graph_id = _identifier(policy["graph_id"], f"{label}.graph_id")
            keyset_id = _identifier(policy["keyset_id"], f"{label}.keyset_id")
            descriptor_id = _identifier(policy["descriptor_id"], f"{label}.descriptor_id")
            token_key_id = _identifier(policy["token_key_id"], f"{label}.token_key_id")
            policy_fingerprint = _identifier(policy["spki_fingerprint"], f"{label}.spki_fingerprint")
            if len({descriptor_id, token_key_id, policy_fingerprint}) != 3:
                raise ManifestError(f"{label}: colliding graph token/descriptor/fingerprint IDs")
            if policy["profile_id"] != GRAPH_PROFILE or graph_id != exchange_graph_id:
                raise ManifestError(f"{label}: graph profile or graph ID mismatch")
            if policy["issuer_id"] != graph_issuer_id:
                raise ManifestError(f"{label}: graph issuer mismatch")
            if _text(policy["asset_id"], f"{label}.asset_id") != asset_id:
                raise ManifestError(f"{label}: asset mismatch")
            if policy["suite"] != SUITE:
                raise ManifestError(f"{label}: unsupported graph policy parameters")
            _constant_integer(policy["modulus_bits"], 3072, f"{label}.modulus_bits")
            _constant_integer(policy["exponent"], 65537, f"{label}.exponent")
            _constant_integer(policy["quantity"], 1, f"{label}.quantity")
            _parse_amount(policy["amount_minor"], f"{label}.amount_minor")
            valid_from = _integer(policy["valid_from"], f"{label}.valid_from", 0)
            valid_until = _integer(policy["valid_until"], f"{label}.valid_until", 1)
            if valid_from >= valid_until:
                raise ManifestError(f"{label}: invalid graph policy validity interval")
            descriptor = descriptors.get(descriptor_id)
            keyset = keysets.get(keyset_id)
            if descriptor is None or keyset is None or descriptor_id not in keyset["descriptor_ids"]:
                raise ManifestError(f"{label}: missing descriptor, keyset, or membership")
            spki = _decode_spki(policy["pubkey_spki_b64"], f"{label}.pubkey_spki_b64")
            fingerprint = policy_fingerprint
            if hashlib.sha256(spki).hexdigest() != fingerprint:
                raise ManifestError(f"{label}: graph SPKI fingerprint mismatch")
            descriptor_fields = (
                ("issuer_id", graph_issuer_id),
                ("token_key_id", token_key_id),
                ("asset_id", asset_id),
                ("amount_minor", policy["amount_minor"]),
                ("suite", policy["suite"]),
                ("modulus_bits", policy["modulus_bits"]),
                ("exponent", policy["exponent"]),
                ("pubkey_spki_b64", policy["pubkey_spki_b64"]),
                ("spki_fingerprint", fingerprint),
                ("valid_from", valid_from),
                ("valid_until", valid_until),
            )
            if any(descriptor[field] != value for field, value in descriptor_fields):
                raise ManifestError(f"{label}: graph policy does not exactly reference its exchange descriptor")
            if policy_id in policy_ids or token_key_id in graph_token_ids:
                raise ManifestError(f"{label}: duplicate graph policy or signer role")
            policy_ids.add(policy_id)
            graph_token_ids.add(token_key_id)
            if group_name == "active_policies" and policy_id == pinned_policy_id:
                selected_active_count += 1
    if selected_active_count != 1:
        raise ManifestError("graph_policy_id must select exactly one active graph policy")


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = _object(value, TOP_FIELDS, "manifest")
    if manifest["version"] != VERSION:
        raise ManifestError("unsupported manifest version")
    run_id = manifest["run_id"]
    if type(run_id) is not str or RUN_ID_RE.fullmatch(run_id) is None:
        raise ManifestError("run_id: invalid bounded identifier")
    issuer_origin, issuer_port = _origin(manifest["issuer_origin"], "issuer_origin")
    verifier_origin, verifier_port = _origin(manifest["verifier_origin"], "verifier_origin")
    if issuer_port == verifier_port:
        raise ManifestError("issuer_origin and verifier_origin must use distinct ports")
    issuer_id = _text(manifest["issuer_id"], "issuer_id")
    graph_issuer_id = _text(manifest["graph_issuer_id"], "graph_issuer_id")
    if graph_issuer_id != issuer_id:
        raise ManifestError("graph_issuer_id must equal the pinned Freebird issuer_id")
    asset_id = _text(manifest["asset_id"], "asset_id")
    policy_id = _identifier(manifest["graph_policy_id"], "graph_policy_id")

    v4 = _object(manifest["v4"], V4_FIELDS, "v4")
    credential_issuer_id = _text(v4["credential_issuer_id"], "v4.credential_issuer_id")
    if credential_issuer_id != issuer_id:
        raise ManifestError("v4.credential_issuer_id must equal the pinned Freebird issuer_id")
    _text(v4["kid"], "v4.kid", 255)
    public_key = _decode_b64(v4["public_key_b64"], 33, "v4.public_key_b64")
    if public_key[0] not in (2, 3):
        raise ManifestError("v4.public_key_b64: expected compressed P-256 public key form")
    derived_kid_prefix = base64.urlsafe_b64encode(
        hashlib.sha256(b"freebird:issuer:pk:" + public_key).digest()
    ).decode("ascii").rstrip("=")[:24]
    if not v4["kid"].startswith(derived_kid_prefix):
        raise ManifestError("v4.kid does not match the native public-key identifier prefix")
    verifier_id = _text(v4["verifier_id"], "v4.verifier_id", 255)
    audience = _text(v4["audience"], "v4.audience", 255)
    scope_digest = _decode_b64(v4["scope_digest_b64"], 32, "v4.scope_digest_b64")
    scope_transcript = (
        b"freebird:scope:v4"
        + bytes([len(verifier_id.encode("utf-8"))])
        + verifier_id.encode("utf-8")
        + bytes([len(audience.encode("utf-8"))])
        + audience.encode("utf-8")
    )
    if hashlib.sha256(scope_transcript).digest() != scope_digest:
        raise ManifestError("v4.scope_digest_b64 does not match verifier_id and audience")

    replay = _object(manifest["replay_authority"], REPLAY_FIELDS, "replay_authority")
    _decode_b64(replay["authority_id"], 32, "replay_authority.authority_id")
    tombstones = replay["v4_scope_digest_tombstones"]
    if type(tombstones) is not list or len(tombstones) > MAX_ITEMS:
        raise ManifestError("replay_authority.v4_scope_digest_tombstones: invalid bounded array")
    decoded_tombstones = [
        _decode_b64(item, 32, f"replay_authority.v4_scope_digest_tombstones[{index}]")
        for index, item in enumerate(tombstones)
    ]
    if len(set(decoded_tombstones)) != len(decoded_tombstones):
        raise ManifestError("replay_authority contains duplicate scope tombstones")
    if scope_digest not in decoded_tombstones:
        raise ManifestError("replay-authority tombstones do not retain the V4 scope pin")

    receipt = _object(manifest["receipt_keyset"], RECEIPT_SET_FIELDS, "receipt_keyset")
    if (
        receipt["issuer_id"] != issuer_id
        or receipt["origin"] != issuer_origin
        or receipt["profile_id"] != EXCHANGE_PROFILE
    ):
        raise ManifestError("receipt keyset issuer, origin, or profile pin mismatch")
    keys = receipt["keys"]
    if type(keys) is not list or not 1 <= len(keys) <= MAX_ITEMS:
        raise ManifestError("receipt_keyset.keys: invalid bounded array")
    receipt_ids: set[str] = set()
    active_count = 0
    for index, key_value in enumerate(keys):
        label = f"receipt_keyset.keys[{index}]"
        key = _object(key_value, RECEIPT_KEY_FIELDS, label)
        key_id = _identifier(key["key_id"], f"{label}.key_id")
        if key["algorithm"] != "Ed25519" or key["purpose"] != "exchange_receipt_v7":
            raise ManifestError(f"{label}: wrong receipt algorithm or purpose")
        if key["status"] not in ("active", "retained"):
            raise ManifestError(f"{label}: invalid receipt key status")
        if key["status"] == "active":
            active_count += 1
        public = _decode_b64(key["public_key_b64"], 32, f"{label}.public_key_b64")
        if hashlib.sha256(public).hexdigest() != key_id:
            raise ManifestError(f"{label}.key_id does not identify its public key")
        valid_from = _integer(key["valid_from"], f"{label}.valid_from", 1)
        valid_until = _integer(key["valid_until"], f"{label}.valid_until", 2)
        if valid_from >= valid_until:
            raise ManifestError(f"{label}: invalid receipt validity interval")
        if key_id in receipt_ids:
            raise ManifestError("receipt keyset contains duplicate key IDs")
        receipt_ids.add(key_id)
    if active_count != 1:
        raise ManifestError("receipt keyset must contain exactly one active key")

    pins = _object(manifest["discovery_pins"], DISCOVERY_PIN_FIELDS, "discovery_pins")
    registry_ids: set[str] = set()
    _validate_direct(pins["native_bearer_v7"], issuer_id, asset_id, registry_ids, "native_bearer_v7")
    retained_direct = pins["native_bearer_v7_retained"]
    if type(retained_direct) is not list or len(retained_direct) > MAX_ITEMS:
        raise ManifestError("native_bearer_v7_retained: invalid bounded array")
    for index, direct in enumerate(retained_direct):
        _validate_direct(direct, issuer_id, asset_id, registry_ids, f"native_bearer_v7_retained[{index}]")
    descriptors, keysets = _validate_exchange(pins["native_exchange_v7"], issuer_id, asset_id)
    for descriptor in descriptors.values():
        for identity_field in ("descriptor_id", "token_key_id", "spki_fingerprint"):
            value = descriptor[identity_field]
            if value in registry_ids:
                raise ManifestError("direct and exchange discovery signer identities collide")
            registry_ids.add(value)
    exchange_graph_id = pins["native_exchange_v7"]["profile"]["graph_id"]
    _validate_graph(
        pins["native_graph_issuance_v7"],
        graph_issuer_id,
        asset_id,
        exchange_graph_id,
        descriptors,
        keysets,
        policy_id,
    )

    sybil = _object(manifest["sybil"], SYBIL_FIELDS, "sybil")
    if sybil["type"] != "proof_of_work":
        raise ManifestError("sybil.type: only bounded proof_of_work is permitted")
    _integer(sybil["difficulty"], "sybil.difficulty", 1, 24)
    return manifest


def validate_manifest_bytes(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    return validate_manifest(parse_json_bytes(data))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="public Gate 0 JSON manifest")
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as error:
        print(f"manifest rejected: {error}", file=sys.stderr)
        return 2
    print(f"public manifest contract valid: run_id={manifest['run_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
