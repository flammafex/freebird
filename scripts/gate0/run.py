#!/usr/bin/env python3
"""Private, opt-in supervisor for the local Freebird Gate 0 fixture."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from validate_manifest import load_manifest

MAX_PRIVATE_JSON = 128_000
MAX_MANIFEST_BYTES = 4_000_000
PRIVATE_VERSION = "freebird/gate0-private-fixture/v1"
ENV_VERSION = "freebird/gate0-private-env/v1"
AUTHORITY_KEY = b"freebird:v4-replay-authority:v1:id"
EXPECTED_FILES = frozenset({
    "manifest.json", "fixture.private.json", "issuer.env.json", "verifier.env.json",
    "v4.key", "v7-direct.der", "v7-direct.json", "v7-exchange-source.der",
    "v7-exchange-source.json", "v7-exchange-target.der", "v7-exchange-target.json",
    "v7-registry.json", "v7-extra-signers.json", "exchange.json", "graph.json",
    "receipt.key", "receipt.json",
})
EXPECTED_DIRS = frozenset({"runtime", "runtime/issuer", "runtime/verifier", "runtime/redis", "logs"})
ISSUER_FIXED = {
    "FREEBIRD_ENV": "production", "FREEBIRD_UNSAFE_DEVELOPMENT_MODE": "false",
    "ALLOW_UNSAFE_V4_ROTATION": "false", "REQUIRE_TLS": "false", "BEHIND_PROXY": "false",
    "HSM_ENABLE": "false", "NATIVE_BEARER_V7_ENABLE": "true",
    "NATIVE_EXCHANGE_V7_ENABLE": "true", "NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME": "2592000",
    "NATIVE_GRAPH_ISSUANCE_V7_ENABLE": "true", "NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION": "v4_local",
    "SYBIL_RESISTANCE": "pow", "SYBIL_POW_DIFFICULTY": "8",
    "SYBIL_REPLAY_STORE": "redis",
}
ISSUER_REQUIRED = frozenset({
    "BIND_ADDR", "ISSUER_ID", "ADMIN_API_KEY", "ISSUER_SK_PATH", "KEY_ROTATION_STATE_PATH",
    "AUDIT_LOG_PATH", "NATIVE_BEARER_V7_SK_PATH", "NATIVE_BEARER_V7_METADATA_PATH",
    "NATIVE_BEARER_V7_REGISTRY_PATH", "NATIVE_BEARER_V7_PROFILE_ID",
    "NATIVE_BEARER_V7_DESCRIPTOR_ID", "NATIVE_BEARER_V7_TOKEN_KEY_ID",
    "NATIVE_BEARER_V7_ASSET_ID", "NATIVE_BEARER_V7_AMOUNT_MINOR", "NATIVE_BEARER_V7_VALIDITY",
    "NATIVE_V7_SIGNER_CONFIG_PATHS", "NATIVE_EXCHANGE_V7_DISCOVERY_PATH",
    "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH", "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH",
    "NATIVE_EXCHANGE_V7_REDIS_URL", "NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH",
    "NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID", "NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE",
    "NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64", "SYBIL_PROGRESSIVE_TRUST_SALT",
    "SYBIL_PROOF_OF_DIVERSITY_SALT", "SYBIL_MULTI_PARTY_VOUCHING_SALT", "SYBIL_REPLAY_REDIS_URL",
})
ISSUER_ALLOWED = ISSUER_REQUIRED | ISSUER_FIXED.keys()
VERIFIER_FIXED = {
    "VERIFIER_ENV": "production", "VERIFIER_ALLOW_UNSAFE": "false",
    "IN_MEMORY_REPLAY_STORE": "false", "VERIFIER_ACCEPTED_TOKEN_VERSIONS": "v4,v7",
    "REFRESH_INTERVAL_MIN": "1", "VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL": "2s",
    "VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS": "10s", "REQUIRE_TLS": "false", "BEHIND_PROXY": "false",
}
VERIFIER_REQUIRED = frozenset({
    "BIND_ADDR", "ADMIN_API_KEY", "REDIS_URL", "ISSUER_URLS", "VERIFIER_KEYRING_B64",
    "VERIFIER_ID", "VERIFIER_AUDIENCE", "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS",
})
VERIFIER_ALLOWED = VERIFIER_REQUIRED | VERIFIER_FIXED.keys()
PATH_FILES = {
    "ISSUER_SK_PATH": "v4.key", "NATIVE_BEARER_V7_SK_PATH": "v7-direct.der",
    "NATIVE_BEARER_V7_METADATA_PATH": "v7-direct.json", "NATIVE_BEARER_V7_REGISTRY_PATH": "v7-registry.json",
    "NATIVE_EXCHANGE_V7_DISCOVERY_PATH": "exchange.json",
    "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH": "receipt.key",
    "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH": "receipt.json",
    "NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH": "graph.json",
}
MAX_OUTPUT_BYTES = 2_000_000


class Gate0Error(Exception):
    """A redacted, safe-to-report handoff or process failure."""


def _no_constant(_value: str) -> None:
    raise Gate0Error("non-finite JSON value")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Gate0Error("duplicate JSON member")
        result[key] = value
    return result


def parse_closed_json(data: bytes, limit: int = MAX_PRIVATE_JSON) -> Any:
    if not data or len(data) > limit:
        raise Gate0Error("JSON size is outside the permitted bound")
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique_object,
                          parse_constant=_no_constant)
    except Gate0Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise Gate0Error("invalid bounded UTF-8 JSON") from None


def _exact_obj(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise Gate0Error(f"invalid closed {label}")
    return value


def _mode(path: Path, expected: int, want_dir: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise Gate0Error("fixture path is absent or unreadable") from None
    if stat.S_ISLNK(info.st_mode) or (not stat.S_ISDIR(info.st_mode) if want_dir else not stat.S_ISREG(info.st_mode)):
        raise Gate0Error("fixture path has an unexpected file type")
    if stat.S_IMODE(info.st_mode) != expected:
        raise Gate0Error("fixture path permissions are not private")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise Gate0Error("fixture path is not owned by the invoking user")
    return info


def _canonical_root(value: str) -> Path:
    raw = Path(value)
    if not raw.is_absolute() or "\0" in value:
        raise Gate0Error("fixture root must be absolute")
    # Check each component, not only the leaf, to reject symlink aliases.
    cursor = Path(raw.anchor)
    for part in raw.parts[1:]:
        cursor = cursor / part
        try:
            item = cursor.lstat()
        except OSError:
            raise Gate0Error("fixture root path is absent") from None
        if stat.S_ISLNK(item.st_mode):
            raise Gate0Error("fixture root path contains a symlink")
    normalized = Path(os.path.normpath(value))
    if normalized != raw or raw.resolve(strict=True) != raw:
        raise Gate0Error("fixture root must use its canonical absolute path")
    _mode(raw, 0o700, True)
    return raw


def _read_private(root: Path, name: str, max_size: int = MAX_PRIVATE_JSON) -> bytes:
    if name not in EXPECTED_FILES:
        raise Gate0Error("fixture references an unapproved filename")
    path = root / name
    info = _mode(path, 0o600, False)
    if info.st_size < 1 or info.st_size > max_size:
        raise Gate0Error("fixture file size is outside the permitted bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600:
                raise Gate0Error("fixture file changed type or permissions")
            chunks: list[bytes] = []
            total = 0
            while total <= max_size:
                chunk = os.read(fd, min(65_536, max_size + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total != opened.st_size or total > max_size:
                raise Gate0Error("fixture file changed or exceeds its size bound")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except Gate0Error:
        raise
    except OSError:
        raise Gate0Error("fixture file could not be read safely") from None


def _walk_fixed_tree(root: Path) -> None:
    for relative in EXPECTED_DIRS:
        _mode(root / relative, 0o700, True)
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        for entry in dirs:
            candidate = base / entry
            if candidate.is_symlink():
                raise Gate0Error("fixture tree contains a symlink")
            actual_dirs.add(candidate.relative_to(root).as_posix())
        for entry in files:
            candidate = base / entry
            if candidate.is_symlink():
                raise Gate0Error("fixture tree contains a symlink")
            relative = candidate.relative_to(root).as_posix()
            if relative.startswith("runtime/") or relative.startswith("logs/"):
                # Those directories must be empty before launch/validation. Runtime
                # products are deliberately not treated as fixture inputs.
                raise Gate0Error("fixture runtime or log directory is not empty")
            actual_files.add(relative)
    if actual_files != EXPECTED_FILES or actual_dirs != EXPECTED_DIRS:
        raise Gate0Error("fixture tree does not match the frozen retained layout")
    for name in EXPECTED_FILES:
        _mode(root / name, 0o600, False)


def _canonical_b64(raw: Any, size: int, label: str) -> bytes:
    if type(raw) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+", raw):
        raise Gate0Error(f"invalid {label} encoding")
    try:
        value = base64.urlsafe_b64decode(raw + "=" * ((4 - len(raw) % 4) % 4))
    except (ValueError, base64.binascii.Error):
        raise Gate0Error(f"invalid {label} encoding") from None
    if len(value) != size or base64.urlsafe_b64encode(value).decode().rstrip("=") != raw:
        raise Gate0Error(f"invalid {label} width or encoding")
    return value


NATIVE_SIGNER_FIELDS = {
    "profile_id", "issuer_id", "descriptor_id", "token_key_id", "asset_id", "amount_minor",
    "suite", "modulus_bits", "exponent", "pubkey_spki_b64", "spki_fingerprint", "valid_from", "valid_until",
}


def _native_signer_metadata(value: Any, expected: dict[str, Any], *, exchange: bool) -> None:
    record = _exact_obj(value, NATIVE_SIGNER_FIELDS, "native signer metadata")
    for field in ("profile_id", "issuer_id", "descriptor_id", "token_key_id", "asset_id", "suite",
                  "pubkey_spki_b64", "spki_fingerprint"):
        if type(record[field]) is not str:
            raise Gate0Error("native signer metadata has invalid text field types")
    for field in ("amount_minor", "modulus_bits", "exponent", "valid_from", "valid_until"):
        if type(record[field]) is not int:
            raise Gate0Error("native signer metadata has invalid integer field types")
    projected = dict(record)
    if exchange:
        if record["amount_minor"] <= 0:
            raise Gate0Error("native exchange signer amount is outside its permitted range")
        # Rust native metadata carries u64 amount as an integer; the public
        # exchange descriptor contract intentionally carries canonical decimal text.
        projected["amount_minor"] = str(record["amount_minor"])
    if projected != expected:
        raise Gate0Error("native signer metadata differs from public signer pins")


def _url_for_origin(origin: str) -> tuple[str, int]:
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise Gate0Error("manifest contains an invalid loopback service origin")
    return origin, parsed.port


def _path_value(root: Path, value: str, expected_relative: str | None = None) -> Path:
    if "\0" in value:
        raise Gate0Error("private path contains NUL")
    path = Path(value)
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise Gate0Error("private config path is not canonical and absolute")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        raise Gate0Error("private config path escapes the fixture root") from None
    if expected_relative is not None and relative != expected_relative:
        raise Gate0Error("private config path does not match its fixed fixture filename")
    cursor = root
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.exists() or cursor.is_symlink():
            item = cursor.lstat()
            if stat.S_ISLNK(item.st_mode):
                raise Gate0Error("private config path contains a symlink")
    return path


def _load_env(root: Path, filename: str, role: str, run_id: str,
              allowed: set[str], required: frozenset[str], fixed: dict[str, str]) -> dict[str, str]:
    item = _exact_obj(parse_closed_json(_read_private(root, filename)),
                      {"version", "run_id", "role", "env"}, f"{role} environment envelope")
    if item["version"] != ENV_VERSION or item["run_id"] != run_id or item["role"] != role:
        raise Gate0Error(f"{role} environment envelope identity mismatch")
    env = item["env"]
    if type(env) is not dict or not required.issubset(env) or not set(env).issubset(allowed):
        raise Gate0Error(f"{role} environment names do not match the fixed allowlist")
    if any(type(key) is not str or type(value) is not str or "\0" in key or "\0" in value for key, value in env.items()):
        raise Gate0Error(f"{role} environment values must be NUL-free strings")
    if any(env.get(key) != value for key, value in fixed.items()):
        raise Gate0Error(f"{role} environment has unsafe fixed settings")
    return dict(env)


def validate_fixture(root_value: str) -> "ValidatedFixture":
    root = _canonical_root(root_value)
    _walk_fixed_tree(root)
    marker = _exact_obj(parse_closed_json(_read_private(root, "fixture.private.json")), {
        "version", "run_id", "manifest_file", "manifest_sha256_hex", "issuer_env_file",
        "verifier_env_file", "redis",
    }, "private fixture marker")
    if marker["version"] != PRIVATE_VERSION or marker["manifest_file"] != "manifest.json" or \
       marker["issuer_env_file"] != "issuer.env.json" or marker["verifier_env_file"] != "verifier.env.json":
        raise Gate0Error("private fixture marker has an unsupported version or filename")
    if type(marker["run_id"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", marker["run_id"]):
        raise Gate0Error("private fixture marker run ID is invalid")
    if type(marker["manifest_sha256_hex"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", marker["manifest_sha256_hex"]):
        raise Gate0Error("private fixture manifest digest is invalid")
    manifest_bytes = _read_private(root, "manifest.json", MAX_MANIFEST_BYTES)
    if hashlib.sha256(manifest_bytes).hexdigest() != marker["manifest_sha256_hex"]:
        raise Gate0Error("public manifest digest does not match the private marker")
    # The approved G0.1 loader is the authority for the public closed schema,
    # duplicate members, public-only fields, encodings, and cross-pins.
    try:
        manifest = load_manifest(root / "manifest.json")
    except Exception:
        raise Gate0Error("public manifest failed the approved G0.1 validator") from None
    if manifest["run_id"] != marker["run_id"]:
        raise Gate0Error("public/private fixture run IDs differ")
    redis = _exact_obj(marker["redis"], {"host", "port", "database"}, "private Redis pin")
    if redis["host"] != "127.0.0.1" or type(redis["database"]) is not int or redis["database"] != 0 or \
       type(redis["port"]) is not int or not 20_000 <= redis["port"] <= 65_535:
        raise Gate0Error("private Redis pin is not loopback DB 0 on a high port")
    issuer_origin, issuer_port = _url_for_origin(manifest["issuer_origin"])
    verifier_origin, verifier_port = _url_for_origin(manifest["verifier_origin"])
    ports = [issuer_port, verifier_port, redis["port"]]
    if len(set(ports)) != len(ports):
        raise Gate0Error("issuer, verifier, and Redis ports must be distinct")
    redis_url = f"redis://127.0.0.1:{redis['port']}/0"
    issuer_env = _load_env(root, "issuer.env.json", "issuer", marker["run_id"], set(ISSUER_ALLOWED), ISSUER_REQUIRED, ISSUER_FIXED)
    verifier_env = _load_env(root, "verifier.env.json", "verifier", marker["run_id"], set(VERIFIER_ALLOWED), VERIFIER_REQUIRED, VERIFIER_FIXED)
    expected_issuer = f"127.0.0.1:{issuer_port}"
    expected_verifier = f"127.0.0.1:{verifier_port}"
    if issuer_env["BIND_ADDR"] != expected_issuer or verifier_env["BIND_ADDR"] != expected_verifier:
        raise Gate0Error("service bind addresses differ from public pinned origins")
    if issuer_env["ISSUER_ID"] != manifest["issuer_id"] or issuer_env["NATIVE_EXCHANGE_V7_REDIS_URL"] != redis_url or \
       issuer_env["SYBIL_REPLAY_REDIS_URL"] != redis_url or verifier_env["REDIS_URL"] != redis_url:
        raise Gate0Error("issuer or Redis configuration differs from public/private pins")
    v4 = manifest["v4"]
    if issuer_env["NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID"] != v4["verifier_id"] or \
       issuer_env["NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE"] != v4["audience"] or \
       verifier_env["VERIFIER_ID"] != v4["verifier_id"] or verifier_env["VERIFIER_AUDIENCE"] != v4["audience"] or \
       verifier_env["ISSUER_URLS"] != issuer_origin + "/.well-known/issuer" or \
       verifier_env["VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS"] != issuer_origin:
        raise Gate0Error("V4 issuer/verifier scope pins are inconsistent")
    pins = manifest["discovery_pins"]
    direct = pins["native_bearer_v7"]
    if issuer_env["NATIVE_BEARER_V7_PROFILE_ID"] != direct["profile_id"] or \
       issuer_env["NATIVE_BEARER_V7_DESCRIPTOR_ID"] != direct["descriptor_id"] or \
       issuer_env["NATIVE_BEARER_V7_TOKEN_KEY_ID"] != direct["token_key_id"] or \
       issuer_env["NATIVE_BEARER_V7_ASSET_ID"] != direct["asset_id"] or \
       issuer_env["NATIVE_BEARER_V7_AMOUNT_MINOR"] != str(direct["amount_minor"]):
        raise Gate0Error("direct V7 signer configuration differs from public pins")
    graph_policy = next((p for p in pins["native_graph_issuance_v7"]["active_policies"]
                         if p["policy_id"] == manifest["graph_policy_id"]), None)
    exchange = pins["native_exchange_v7"]
    exchange_source = next((d for d in exchange["active_descriptors"]
                            if graph_policy is not None and d["descriptor_id"] == graph_policy["descriptor_id"]), None)
    if graph_policy is None or exchange_source is None or graph_policy["token_key_id"] != exchange_source["token_key_id"]:
        raise Gate0Error("active graph policy does not reference its pinned exchange signer")
    # Parse both keyring JSON-text values without ever echoing either value.
    issuer_ring = parse_closed_json(issuer_env["NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64"].encode(), 16_384)
    verifier_ring = parse_closed_json(verifier_env["VERIFIER_KEYRING_B64"].encode(), 16_384)
    kid = v4["kid"]
    try:
        issuer_secret = _canonical_b64(issuer_ring[manifest["issuer_id"]][kid], 32, "issuer V4 keyring")
        verifier_secret = _canonical_b64(verifier_ring[kid], 32, "verifier V4 keyring")
    except (KeyError, TypeError):
        raise Gate0Error("V4 keyring does not match public issuer/KID pins") from None
    if set(issuer_ring) != {manifest["issuer_id"]} or set(issuer_ring[manifest["issuer_id"]]) != {kid} or \
       set(verifier_ring) != {kid} or issuer_secret != verifier_secret:
        raise Gate0Error("issuer and verifier V4 keyrings do not match the pinned key")
    if _read_private(root, "v4.key", 4096) != issuer_secret:
        raise Gate0Error("locally provisioned V4 scalar does not match private keyring material")

    path_env: list[tuple[dict[str, str], str, str]] = [
        (issuer_env, name, relative) for name, relative in PATH_FILES.items()
    ]
    path_env += [(issuer_env, "KEY_ROTATION_STATE_PATH", "runtime/issuer/rotation.json"),
                 (issuer_env, "AUDIT_LOG_PATH", "logs/issuer-audit.json")]
    for env, name, relative in path_env:
        _path_value(root, env[name], relative)
    signer_paths = issuer_env["NATIVE_V7_SIGNER_CONFIG_PATHS"].split(",")
    if len(signer_paths) != 1:
        raise Gate0Error("native signer config path list differs from the fixed fixture")
    _path_value(root, signer_paths[0], "v7-extra-signers.json")
    signer_configs = parse_closed_json(_read_private(root, "v7-extra-signers.json"))
    if type(signer_configs) is not list or len(signer_configs) != len(exchange["active_descriptors"]):
        raise Gate0Error("native exchange signer configuration count differs from public discovery")
    for index, (config, descriptor) in enumerate(zip(signer_configs, exchange["active_descriptors"], strict=True)):
        config = _exact_obj(config, {"sk_path", "metadata_path", "registry_path", "profile_id", "descriptor_id",
                                    "token_key_id", "asset_id", "amount_minor", "validity_secs"}, "V7 signer config")
        _path_value(root, config["sk_path"], f"v7-exchange-{'source' if index == 0 else 'target'}.der")
        _path_value(root, config["metadata_path"], f"v7-exchange-{'source' if index == 0 else 'target'}.json")
        _path_value(root, config["registry_path"], "v7-registry.json")
        if config["profile_id"] != descriptor["profile_id"] or config["descriptor_id"] != descriptor["descriptor_id"] or \
           config["token_key_id"] != descriptor["token_key_id"] or config["asset_id"] != descriptor["asset_id"] or \
           str(config["amount_minor"]) != descriptor["amount_minor"] or config["validity_secs"] != 86_400:
            raise Gate0Error("native exchange signer config differs from public descriptor pins")
    runtime_files = {
        root / "v7-direct.json": direct,
        root / "exchange.json": exchange,
        root / "graph.json": pins["native_graph_issuance_v7"],
    }
    for index, descriptor in enumerate(exchange["active_descriptors"]):
        signer_name = "source" if index == 0 else "target"
        runtime_files[root / f"v7-exchange-{signer_name}.json"] = descriptor
    for path, expected in runtime_files.items():
        try:
            document = parse_closed_json(_read_private(root, path.name))
        except Gate0Error:
            raise
        if path.name == "v7-direct.json":
            _native_signer_metadata(document, direct, exchange=False)
        elif path.name.startswith("v7-exchange-"):
            _native_signer_metadata(document, expected, exchange=True)
        elif document != expected:
            raise Gate0Error("exchange/graph config differs from public pins")
    receipt_path = root / "receipt.json"
    receipt = parse_closed_json(_read_private(root, receipt_path.name))
    active = next(k for k in manifest["receipt_keyset"]["keys"] if k["status"] == "active")
    receipt_fields = {"key_id", "algorithm", "purpose", "public_key_b64", "valid_from", "valid_until"}
    receipt = _exact_obj(receipt, receipt_fields, "native receipt metadata")
    public_receipt = {key: value for key, value in active.items() if key != "status"}
    if any(type(receipt[field]) is not str for field in ("key_id", "algorithm", "purpose", "public_key_b64")) or \
       any(type(receipt[field]) is not int for field in ("valid_from", "valid_until")) or receipt != public_receipt:
        raise Gate0Error("active receipt metadata differs from its public pin")
    return ValidatedFixture(root, manifest, issuer_env, verifier_env, redis["port"], issuer_port, verifier_port)


class ValidatedFixture:
    def __init__(self, root: Path, manifest: dict[str, Any], issuer_env: dict[str, str],
                 verifier_env: dict[str, str], redis_port: int, issuer_port: int, verifier_port: int):
        self.root = root
        self.manifest = manifest
        self.issuer_env = issuer_env
        self.verifier_env = verifier_env
        self.redis_port = redis_port
        self.issuer_port = issuer_port
        self.verifier_port = verifier_port


def _binary(value: str, label: str) -> str:
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise Gate0Error(f"{label} executable must be an absolute canonical path")
    try:
        info = path.lstat()
    except OSError:
        raise Gate0Error(f"{label} executable is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise Gate0Error(f"{label} executable is not executable")
    return str(path)


def _minimal_env(root: Path, home: Path) -> dict[str, str]:
    return {"PATH": os.defpath, "HOME": str(home), "TMPDIR": str(home)}


def _process_env(root: Path, home_name: str, fixture_env: dict[str, str]) -> dict[str, str]:
    home = root / "runtime" / home_name
    return _minimal_env(root, home) | fixture_env


def _child_umask() -> None:
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})
    os.umask(0o077)


def _port_available(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", port))
    except OSError:
        raise Gate0Error("a pinned loopback port is occupied") from None
    finally:
        sock.close()


def _redis_encode(parts: Sequence[bytes]) -> bytes:
    return b"*" + str(len(parts)).encode() + b"\r\n" + b"".join(
        b"$" + str(len(part)).encode() + b"\r\n" + part + b"\r\n" for part in parts)


def _redis_read(stream: socket.socket, max_bulk: int = 1_000_000) -> Any:
    def line() -> bytes:
        out = bytearray()
        while len(out) <= 4096:
            byte = stream.recv(1)
            if not byte:
                raise Gate0Error("Redis connection closed unexpectedly")
            out.extend(byte)
            if out.endswith(b"\r\n"):
                return bytes(out[:-2])
        raise Gate0Error("Redis response line exceeds limit")
    prefix = stream.recv(1)
    if prefix == b"+": return line()
    if prefix == b"-": raise Gate0Error("Redis returned an error response")
    if prefix == b":": return int(line())
    if prefix == b"$":
        length = int(line())
        if length == -1: return None
        if not 0 <= length <= max_bulk: raise Gate0Error("Redis bulk response exceeds limit")
        chunks = bytearray()
        while len(chunks) < length + 2:
            chunk = stream.recv(length + 2 - len(chunks))
            if not chunk: raise Gate0Error("Redis response ended early")
            chunks.extend(chunk)
        if chunks[-2:] != b"\r\n": raise Gate0Error("Redis bulk response framing is invalid")
        return bytes(chunks[:-2])
    if prefix == b"*":
        count = int(line())
        if not 0 <= count <= 64: raise Gate0Error("Redis array response exceeds limit")
        return [_redis_read(stream, max_bulk) for _ in range(count)]
    raise Gate0Error("Redis response type is unsupported")


def _redis_on_socket(sock: socket.socket, *parts: bytes) -> Any:
    sock.sendall(_redis_encode(parts))
    return _redis_read(sock)


def redis_command(port: int, *parts: bytes, timeout: float = 1.0) -> Any:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        return _redis_on_socket(sock, *parts)


def _redis_info_fields(value: Any) -> dict[str, str]:
    if type(value) is not bytes:
        raise Gate0Error("Redis INFO response is malformed")
    fields: dict[str, str] = {}
    try:
        for line in value.decode("ascii", "strict").splitlines():
            if line and not line.startswith("#") and ":" in line:
                key, content = line.split(":", 1)
                fields[key] = content
    except UnicodeDecodeError:
        raise Gate0Error("Redis INFO response is malformed") from None
    return fields


def _assert_owned_redis(sock: socket.socket, expected_pid: int, alive: Callable[[], None]) -> None:
    server = _redis_info_fields(_redis_on_socket(sock, b"INFO", b"server"))
    if server.get("process_id") != str(expected_pid):
        raise Gate0Error("Redis listener PID does not match the owned child")
    persistence = _redis_info_fields(_redis_on_socket(sock, b"INFO", b"persistence"))
    if persistence.get("aof_enabled") != "1":
        raise Gate0Error("owned Redis does not report AOF enabled")
    config = _redis_on_socket(sock, b"CONFIG", b"GET", b"appendfsync")
    if config != [b"appendfsync", b"always"]:
        raise Gate0Error("owned Redis appendfsync is not always")
    alive()


def provision_owned_redis(port: int, expected_pid: int, manifest: dict[str, Any],
                          alive: Callable[[], None], connect: Callable[..., socket.socket] | None = None) -> None:
    # Keep ownership checks, preflight, SET NX, and readback on one TCP peer.
    # A foreign listener cannot inherit this already-established connection.
    connect_socket = connect or socket.create_connection
    with connect_socket(("127.0.0.1", port), timeout=1.0) as sock:
        sock.settimeout(1.0)
        _assert_owned_redis(sock, expected_pid, alive)
        if _redis_on_socket(sock, b"SELECT", b"0") != b"OK" or _redis_on_socket(sock, b"DBSIZE") != 0:
            raise Gate0Error("owned Redis DB 0 was not empty before authority provisioning")
        authority = _canonical_b64(manifest["replay_authority"]["authority_id"], 32, "authority ID")
        if _redis_on_socket(sock, b"GET", AUTHORITY_KEY) is not None:
            raise Gate0Error("owned Redis authority key already exists")
        _assert_owned_redis(sock, expected_pid, alive)
        if _redis_on_socket(sock, b"SET", AUTHORITY_KEY, authority, b"NX") != b"OK":
            raise Gate0Error("raw replay authority provisioning failed without overwrite")
        if _redis_on_socket(sock, b"GET", AUTHORITY_KEY) != authority:
            raise Gate0Error("raw replay authority readback differs")


class Supervisor:
    TERM_GRACE_SECONDS = 2.0
    KILL_GRACE_SECONDS = 2.0

    def __init__(self, fixture: ValidatedFixture, timeout: float, popen: Callable[..., subprocess.Popen] = subprocess.Popen):
        self.fixture = fixture
        self.timeout = timeout
        self.popen = popen
        self.children: list[subprocess.Popen] = []
        self.owned_pgids: list[int] = []
        self.logs: list[Any] = []
        self.child_logs: dict[int, Path] = {}
        self.cleaned = False
        self.redis_child: subprocess.Popen | None = None
        self.issuer_child: subprocess.Popen | None = None
        self.verifier_child: subprocess.Popen | None = None
        self.redis_server_bin: str | None = None
        self.issuer_bin: str | None = None
        self.verifier_bin: str | None = None

    def _spawn(self, name: str, argv: Sequence[str], env: dict[str, str], *, log_name: str | None = None) -> subprocess.Popen:
        filename = log_name if log_name is not None else name
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", filename):
            raise Gate0Error("private process log name is invalid")
        log_path = self.fixture.root / "logs" / f"{filename}.log"
        try:
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            log = os.fdopen(fd, "wb", buffering=0)
        except OSError:
            raise Gate0Error("private process log could not be created") from None
        self.logs.append(log)
        if os.name != "posix" or not hasattr(signal, "pthread_sigmask"):
            raise Gate0Error("owned process-group supervision requires POSIX signal masking")
        blocked = {signal.SIGINT, signal.SIGTERM}
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            child = self.popen(list(argv), cwd=self.fixture.root, env=env, stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, shell=False, close_fds=True,
                               preexec_fn=_child_umask, start_new_session=True)
            self.children.append(child)
            # start_new_session makes the child PID its unique SID and PGID.
            self.owned_pgids.append(child.pid)
            self.child_logs[child.pid] = log_path
        except Exception:
            raise Gate0Error(f"{name} child failed to start") from None
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
        return child

    def _alive(self, child: subprocess.Popen, name: str) -> None:
        if child.poll() is not None:
            raise Gate0Error(f"{name} child exited during startup")

    def _wait_until(self, check: Callable[[], bool], child: subprocess.Popen, label: str) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self._alive(child, label)
            try:
                if check(): return
            except Exception:
                pass
            time.sleep(0.1)
        raise Gate0Error(f"{label} readiness deadline expired")

    def _http_json(self, port: int, route: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.75)
        try:
            conn.request("GET", route, headers={"Connection": "close", **(headers or {})})
            response = conn.getresponse()
            if response.status != 200:
                return response.status, None
            body = response.read(MAX_OUTPUT_BYTES + 1)
            if len(body) > MAX_OUTPUT_BYTES:
                return response.status, None
            return response.status, parse_closed_json(body, MAX_OUTPUT_BYTES)
        finally:
            conn.close()

    def _issuer_is_ready(self) -> bool:
        f = self.fixture
        status, ready = self._http_json(f.issuer_port, "/readyz")
        if status != 200 or type(ready) is not dict or ready != {"status": "ready"}:
            return False
        status, issuer_doc = self._http_json(f.issuer_port, "/.well-known/issuer")
        v4 = f.manifest["v4"]
        if status != 200 or not isinstance(issuer_doc, dict) or issuer_doc.get("issuer_id") != f.manifest["issuer_id"]:
            return False
        voprf = issuer_doc.get("voprf")
        if not isinstance(voprf, dict) or voprf.get("kid") != v4["kid"] or voprf.get("pubkey") != v4["public_key_b64"]:
            return False
        status, metadata = self._http_json(f.issuer_port, "/.well-known/keys")
        pins = f.manifest["discovery_pins"]
        return status == 200 and isinstance(metadata, dict) and metadata.get("issuer_id") == f.manifest["issuer_id"] and all(
            metadata.get(key) == value for key, value in pins.items())

    def start_owned_services(self, redis_bin: str, issuer_bin: str, verifier_bin: str,
                             initial_verifier_log: str = "verifier") -> None:
        if self.children or self.cleaned:
            raise Gate0Error("owned services can only be started once")
        f = self.fixture
        redis_bin = _binary(redis_bin, "Redis")
        issuer_bin = _binary(issuer_bin, "issuer")
        verifier_bin = _binary(verifier_bin, "verifier")
        self.redis_server_bin, self.issuer_bin, self.verifier_bin = redis_bin, issuer_bin, verifier_bin
        # Refuse to adopt or disturb any process already bound to a requested port.
        for port in (f.redis_port, f.issuer_port, f.verifier_port): _port_available(port)
        redis_dir = f.root / "runtime/redis"
        if any(redis_dir.iterdir()): raise Gate0Error("owned Redis data directory is not empty")
        redis_env = _minimal_env(f.root, f.root / "runtime/redis")
        redis = self._spawn("redis", [redis_bin, "--bind", "127.0.0.1", "--port", str(f.redis_port),
            "--protected-mode", "yes", "--dir", str(redis_dir), "--dbfilename", "dump.rdb",
            "--appendonly", "yes", "--appendfilename", "appendonly.aof", "--appendfsync", "always",
            "--daemonize", "no", "--save", "", "--logfile", ""], redis_env)
        self.redis_child = redis
        self._wait_until(lambda: redis_command(f.redis_port, b"PING", timeout=0.4) == b"PONG", redis, "Redis")
        provision_owned_redis(f.redis_port, redis.pid, f.manifest, lambda: self._alive(redis, "Redis"))

        issuer = self._spawn("issuer", [issuer_bin], _process_env(f.root, "issuer", f.issuer_env))
        self.issuer_child = issuer
        self._wait_until(self._issuer_is_ready, issuer, "issuer")
        verifier = self.start_verifier_database(0, initial_verifier_log)
        self._wait_until(self.verifier_ready, verifier, "verifier")

    def verifier_ready(self) -> bool:
        status, body = self._http_json(self.fixture.verifier_port, "/ready")
        return status == 200 and type(body) is dict and body.get("status") == "ready"

    def verifier_environment_for_database(self, database: int) -> dict[str, str]:
        if database not in (0, 1):
            raise Gate0Error("verifier database restart is not permitted")
        env = dict(self.fixture.verifier_env)
        env["REDIS_URL"] = f"redis://127.0.0.1:{self.fixture.redis_port}/{database}"
        if set(env) != set(self.fixture.verifier_env) or any(
            env[key] != value for key, value in self.fixture.verifier_env.items() if key != "REDIS_URL"
        ):
            raise Gate0Error("verifier restart changed more than its Redis database")
        return env

    def assert_owned_database_empty(self, database: int) -> None:
        child = self.redis_child
        if database not in (0, 1) or child is None:
            raise Gate0Error("owned Redis database is unavailable")
        self._alive(child, "Redis")
        try:
            with socket.create_connection(("127.0.0.1", self.fixture.redis_port), timeout=1.0) as sock:
                sock.settimeout(1.0)
                _assert_owned_redis(sock, child.pid, lambda: self._alive(child, "Redis"))
                if _redis_on_socket(sock, b"SELECT", str(database).encode()) != b"OK" or \
                   _redis_on_socket(sock, b"DBSIZE") != 0:
                    raise Gate0Error("owned Redis negative-control database is not empty")
                self._alive(child, "Redis")
        except Gate0Error:
            raise
        except Exception:
            raise Gate0Error("owned Redis database preflight failed") from None

    def start_verifier_database(self, database: int, log_name: str) -> subprocess.Popen:
        if self.verifier_bin is None:
            raise Gate0Error("owned verifier binary is unavailable")
        if self.redis_child is None or self.issuer_child is None:
            raise Gate0Error("owned Redis and issuer must remain running during verifier controls")
        self._alive(self.redis_child, "Redis")
        self._alive(self.issuer_child, "issuer")
        env = self.verifier_environment_for_database(database)
        if self.verifier_child is not None:
            self._stop_owned_child(self.verifier_child)
        self._alive(self.redis_child, "Redis")
        self._alive(self.issuer_child, "issuer")
        child = self._spawn("verifier", [self.verifier_bin],
                            _process_env(self.fixture.root, "verifier", env), log_name=log_name)
        self.verifier_child = child
        return child

    def run_owned_driver(self, argv: Sequence[str], timeout: float, log_name: str = "driver") -> tuple[int, Path]:
        if not argv or not Path(argv[0]).is_absolute() or not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600:
            raise Gate0Error("driver argv or deadline is invalid")
        driver_bin = _binary(argv[0], "driver")
        for child, label in ((self.redis_child, "Redis"), (self.issuer_child, "issuer"),
                             (self.verifier_child, "verifier")):
            if child is None:
                raise Gate0Error("owned services are not all running")
            self._alive(child, label)
        driver_proc = self._spawn("driver", [driver_bin, *argv[1:]],
                                  _minimal_env(self.fixture.root, self.fixture.root / "runtime/verifier"),
                                  log_name=log_name)
        log_path = self.child_logs[driver_proc.pid]
        deadline = time.monotonic() + timeout
        while True:
            for child, label in ((self.redis_child, "Redis"), (self.issuer_child, "issuer"),
                                 (self.verifier_child, "verifier")):
                if child is None:
                    raise Gate0Error("owned service stopped during driver execution")
                self._alive(child, label)
            try:
                if log_path.stat().st_size > MAX_PRIVATE_JSON:
                    raise Gate0Error("caller driver output exceeds the private bound")
            except OSError:
                raise Gate0Error("caller driver output is unavailable") from None
            try:
                result = driver_proc.wait(timeout=min(0.1, max(0.0, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    raise Gate0Error("caller driver deadline expired") from None
        if result != 0:
            raise Gate0Error("caller driver reported failure")
        if log_path.stat().st_size > MAX_PRIVATE_JSON:
            raise Gate0Error("caller driver output exceeds the private bound")
        return result, log_path

    def run(self, redis_bin: str, issuer_bin: str, verifier_bin: str, driver: Sequence[str], driver_timeout: float) -> int:
        if not driver or not Path(driver[0]).is_absolute():
            raise Gate0Error("driver must be an explicit absolute executable argv supplied by the caller")
        self.start_owned_services(redis_bin, issuer_bin, verifier_bin)
        result, _log_path = self.run_owned_driver(driver, driver_timeout)
        return result

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _terminate_owned_groups(self, groups: Sequence[int], children: Sequence[subprocess.Popen]) -> None:
        cleanup_failed = False
        for pgid in reversed(groups):
            try: os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError: pass
            except OSError: cleanup_failed = True
        term_deadline = time.monotonic() + self.TERM_GRACE_SECONDS
        while time.monotonic() < term_deadline and any(self._group_exists(pgid) for pgid in groups):
            for child in children: child.poll()
            time.sleep(0.05)
        for pgid in reversed(groups):
            if self._group_exists(pgid):
                try: os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError: pass
                except OSError: cleanup_failed = True
        kill_deadline = time.monotonic() + self.KILL_GRACE_SECONDS
        while time.monotonic() < kill_deadline and any(self._group_exists(pgid) for pgid in groups):
            for child in children: child.poll()
            time.sleep(0.05)
        for child in children:
            if child.poll() is None:
                try: child.wait(timeout=0.1)
                except subprocess.TimeoutExpired: cleanup_failed = True
        if any(self._group_exists(pgid) for pgid in groups): cleanup_failed = True
        if cleanup_failed:
            raise Gate0Error("owned process-group termination could not be confirmed")
        removed = set(groups)
        self.owned_pgids = [pgid for pgid in self.owned_pgids if pgid not in removed]

    def _stop_owned_child(self, child: subprocess.Popen) -> None:
        pgid = child.pid
        if pgid not in self.owned_pgids:
            if child.poll() is None: raise Gate0Error("owned process group is not tracked")
            return
        self._terminate_owned_groups([pgid], [child])
        if self.verifier_child is child: self.verifier_child = None

    def cleanup(self) -> None:
        if self.cleaned:
            return
        if os.name != "posix":
            raise Gate0Error("cannot guarantee cleanup without POSIX process groups")
        blocked = {signal.SIGINT, signal.SIGTERM}
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            self._terminate_owned_groups(tuple(self.owned_pgids), tuple(self.children))
        finally:
            for log in self.logs:
                try: log.close()
                except OSError: pass
            self.cleaned = True
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)


def _positive_timeout(value: str) -> float:
    try: result = float(value)
    except ValueError: raise argparse.ArgumentTypeError("must be a positive number") from None
    if not 0 < result <= 3600: raise argparse.ArgumentTypeError("must be in (0, 3600]")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--fixture-dir", required=True)
    parser.add_argument("--redis-server-bin")
    parser.add_argument("--issuer-bin")
    parser.add_argument("--verifier-bin")
    parser.add_argument("--timeout", type=_positive_timeout, default=45.0)
    parser.add_argument("--driver-timeout", type=_positive_timeout, default=180.0)
    parser.add_argument("driver_argv", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    supervisor: Supervisor | None = None
    try:
        fixture = validate_fixture(args.fixture_dir)
        print("G0.2 validation: passed (public manifest and closed private handoff)")
        if args.validate_only:
            return 0
        if not args.redis_server_bin or not args.issuer_bin or not args.verifier_bin:
            raise Gate0Error("run mode requires explicit Redis, issuer, and verifier executable paths")
        redis_bin = _binary(args.redis_server_bin, "Redis")
        issuer_bin = _binary(args.issuer_bin, "issuer")
        verifier_bin = _binary(args.verifier_bin, "verifier")
        driver = list(args.driver_argv)
        if driver and driver[0] == "--": driver = driver[1:]
        supervisor = Supervisor(fixture, args.timeout)
        old_handlers: dict[int, Any] = {}
        def signal_handler(signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt(f"signal {signum}")
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_handlers[sig] = signal.signal(sig, signal_handler)
        try:
            result = supervisor.run(redis_bin, issuer_bin, verifier_bin, driver, args.driver_timeout)
        finally:
            supervisor.cleanup()
            for sig, handler in old_handlers.items(): signal.signal(sig, handler)
        print("G0.2 process run: completed (this is not replay-health or Gate 0 proof)")
        return result
    except (Gate0Error, KeyboardInterrupt):
        if supervisor is not None: supervisor.cleanup()
        print("G0.2 supervisor: failed safely; details withheld", file=sys.stderr)
        return 2
    except Exception:
        if supervisor is not None: supervisor.cleanup()
        print("G0.2 supervisor: failed safely; details withheld", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
