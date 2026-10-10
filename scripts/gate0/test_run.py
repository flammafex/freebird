#!/usr/bin/env python3
"""stdlib-only synthetic tests for the private Gate 0 process supervisor."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run  # noqa: E402

COMMON_FIXTURE = HERE.parent.parent / "common/test-fixtures/v7-graph-reference.json"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def make_root(parent: Path, name: str = "fixture") -> Path:
    root = parent / name
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    for relative in sorted(run.EXPECTED_DIRS, key=lambda value: value.count("/")):
        (root / relative).mkdir(mode=0o700)
        os.chmod(root / relative, 0o700)

    source = json.loads(COMMON_FIXTURE.read_text())
    pins = {name: source[name] for name in (
        "native_bearer_v7", "native_bearer_v7_retained", "native_exchange_v7", "native_graph_issuance_v7")}
    issuer_id = "issuer:test"
    public_v4 = "A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"
    kid = "YcWArFEd6LC_j5j_02XhSzvz-test"
    verifier_id = "gate0-v4-verifier"
    audience = "gate0-v4-audience"
    scope = hashlib.sha256(b"freebird:scope:v4" + bytes([len(verifier_id)]) + verifier_id.encode() +
                           bytes([len(audience)]) + audience.encode()).digest()
    receipt_public = bytes(range(32))
    manifest = {
        "version": "scarcity/freebird-gate0/v1", "run_id": "test-run.1",
        "issuer_origin": "http://127.0.0.1:24001", "verifier_origin": "http://127.0.0.1:24002",
        "issuer_id": issuer_id, "graph_issuer_id": issuer_id, "asset_id": "USD",
        "graph_policy_id": pins["native_graph_issuance_v7"]["active_policies"][0]["policy_id"],
        "v4": {"credential_issuer_id": issuer_id, "kid": kid, "public_key_b64": public_v4,
               "verifier_id": verifier_id, "audience": audience, "scope_digest_b64": b64(scope)},
        "replay_authority": {"authority_id": b64(bytes(range(32, 64))),
                             "v4_scope_digest_tombstones": [b64(scope)]},
        "receipt_keyset": {"issuer_id": issuer_id, "origin": "http://127.0.0.1:24001",
            "profile_id": "freebird/native-exchange/v3", "keys": [{
                "key_id": hashlib.sha256(receipt_public).hexdigest(), "algorithm": "Ed25519",
                "purpose": "exchange_receipt_v7", "public_key_b64": b64(receipt_public),
                "status": "active", "valid_from": 1, "valid_until": 9_000_000_000,
            }]},
        "discovery_pins": pins,
        "sybil": {"type": "proof_of_work", "difficulty": 8},
    }
    secret = b64(bytes(range(32)))
    signer_configs = []
    signer_metadata = {}
    for name, descriptor in zip(("source", "target"), pins["native_exchange_v7"]["active_descriptors"]):
        signer_configs.append({
            "sk_path": str(root / f"v7-exchange-{name}.der"),
            "metadata_path": str(root / f"v7-exchange-{name}.json"),
            "registry_path": str(root / "v7-registry.json"),
            "profile_id": descriptor["profile_id"], "descriptor_id": descriptor["descriptor_id"],
            "token_key_id": descriptor["token_key_id"], "asset_id": descriptor["asset_id"],
            "amount_minor": 42, "validity_secs": 86_400,
        })
        signer_metadata[name] = descriptor
    issuer_env = {
        "BIND_ADDR": "127.0.0.1:24001", "ISSUER_ID": issuer_id, "ADMIN_API_KEY": "private-admin",
        "ISSUER_SK_PATH": str(root / "v4.key"), "KEY_ROTATION_STATE_PATH": str(root / "runtime/issuer/rotation.json"),
        "AUDIT_LOG_PATH": str(root / "logs/issuer-audit.json"), "NATIVE_BEARER_V7_ENABLE": "true",
        "NATIVE_BEARER_V7_SK_PATH": str(root / "v7-direct.der"),
        "NATIVE_BEARER_V7_METADATA_PATH": str(root / "v7-direct.json"),
        "NATIVE_BEARER_V7_REGISTRY_PATH": str(root / "v7-registry.json"),
        "NATIVE_BEARER_V7_PROFILE_ID": pins["native_bearer_v7"]["profile_id"],
        "NATIVE_BEARER_V7_DESCRIPTOR_ID": pins["native_bearer_v7"]["descriptor_id"],
        "NATIVE_BEARER_V7_TOKEN_KEY_ID": pins["native_bearer_v7"]["token_key_id"],
        "NATIVE_BEARER_V7_ASSET_ID": "USD", "NATIVE_BEARER_V7_AMOUNT_MINOR": "42",
        "NATIVE_BEARER_V7_VALIDITY": "1d", "NATIVE_V7_SIGNER_CONFIG_PATHS": str(root / "v7-extra-signers.json"),
        "NATIVE_EXCHANGE_V7_DISCOVERY_PATH": str(root / "exchange.json"),
        "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH": str(root / "receipt.key"),
        "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH": str(root / "receipt.json"),
        "NATIVE_EXCHANGE_V7_REDIS_URL": "redis://127.0.0.1:24003/0",
        "NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH": str(root / "graph.json"),
        "NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID": verifier_id,
        "NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE": audience,
        "NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64": json.dumps({issuer_id: {kid: secret}}),
        "SYBIL_PROGRESSIVE_TRUST_SALT": "salt-a", "SYBIL_PROOF_OF_DIVERSITY_SALT": "salt-b",
        "SYBIL_MULTI_PARTY_VOUCHING_SALT": "salt-c",
        "SYBIL_REPLAY_REDIS_URL": "redis://127.0.0.1:24003/0",
    } | run.ISSUER_FIXED
    verifier_env = {
        "BIND_ADDR": "127.0.0.1:24002", "ADMIN_API_KEY": "private-admin-v",
        "REDIS_URL": "redis://127.0.0.1:24003/0", "ISSUER_URLS": manifest["issuer_origin"] + "/.well-known/issuer",
        "VERIFIER_KEYRING_B64": json.dumps({kid: secret}), "VERIFIER_ID": verifier_id,
        "VERIFIER_AUDIENCE": audience, "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS": manifest["issuer_origin"],
    } | run.VERIFIER_FIXED
    artifacts = {
        "manifest.json": json.dumps(manifest, separators=(",", ":")).encode(),
        "v4.key": bytes(range(32)), "v7-direct.der": b"private direct key",
        "v7-direct.json": json.dumps(pins["native_bearer_v7"]).encode(),
        "v7-exchange-source.der": b"private exchange source",
        "v7-exchange-source.json": json.dumps({**signer_metadata["source"], "amount_minor": 42}).encode(),
        "v7-exchange-target.der": b"private exchange target",
        "v7-exchange-target.json": json.dumps({**signer_metadata.get("target", {}), "amount_minor": 42}).encode(),
        "v7-registry.json": b"{}", "v7-extra-signers.json": json.dumps(signer_configs).encode(),
        "exchange.json": json.dumps(pins["native_exchange_v7"]).encode(),
        "graph.json": json.dumps(pins["native_graph_issuance_v7"]).encode(),
        "receipt.key": b"private receipt key",
        "receipt.json": json.dumps({key: value for key, value in manifest["receipt_keyset"]["keys"][0].items()
                                     if key != "status"}).encode(),
    }
    for filename, contents in artifacts.items():
        (root / filename).write_bytes(contents)
        os.chmod(root / filename, 0o600)
    for filename, role, env in (("issuer.env.json", "issuer", issuer_env),
                                ("verifier.env.json", "verifier", verifier_env)):
        envelope = {"version": run.ENV_VERSION, "run_id": manifest["run_id"], "role": role, "env": env}
        (root / filename).write_text(json.dumps(envelope, separators=(",", ":")))
        os.chmod(root / filename, 0o600)
    digest = hashlib.sha256(artifacts["manifest.json"]).hexdigest()
    marker = {"version": run.PRIVATE_VERSION, "run_id": manifest["run_id"],
              "manifest_file": "manifest.json", "manifest_sha256_hex": digest,
              "issuer_env_file": "issuer.env.json", "verifier_env_file": "verifier.env.json",
              "redis": {"host": "127.0.0.1", "port": 24003, "database": 0}}
    (root / "fixture.private.json").write_text(json.dumps(marker, separators=(",", ":")))
    os.chmod(root / "fixture.private.json", 0o600)
    return root


class HandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = make_root(Path(self.temp.name).resolve())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_valid_synthetic_handoff_and_validate_only_are_offline(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        self.assertEqual(fixture.redis_port, 24003)
        with mock.patch.object(run.socket, "socket", side_effect=AssertionError("network attempted")), \
             mock.patch.object(run.socket, "create_connection", side_effect=AssertionError("network attempted")), \
             mock.patch.object(run.subprocess, "Popen", side_effect=AssertionError("child attempted")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run.main(["--validate-only", "--fixture-dir", str(self.root)]), 0)
        self.assertIn("passed", output.getvalue())

    def test_duplicate_marker_member_and_bad_digest_fail_closed(self) -> None:
        marker_path = self.root / "fixture.private.json"
        marker_path.write_text('{"version":"a","version":"b"}')
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))
        other = make_root(self.root.parent, "fixture-bad-digest")
        marker_path = other / "fixture.private.json"
        marker = json.loads(marker_path.read_text()); marker["manifest_sha256_hex"] = "0" * 64
        marker_path.write_text(json.dumps(marker)); os.chmod(marker_path, 0o600)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(other))

    def test_unknown_environment_key_and_nul_are_rejected(self) -> None:
        path = self.root / "issuer.env.json"
        envelope = json.loads(path.read_text())
        envelope["env"]["LD_PRELOAD"] = "hostile"
        path.write_text(json.dumps(envelope)); os.chmod(path, 0o600)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))

    def test_native_exchange_metadata_projects_only_integer_amount(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        native_path = self.root / "v7-exchange-source.json"
        native = json.loads(native_path.read_text())
        self.assertIs(type(native["amount_minor"]), int)
        for mutation in (
            lambda item: item.__setitem__("amount_minor", 43),
            lambda item: item.__setitem__("amount_minor", "42"),
            lambda item: item.__setitem__("unexpected", "field"),
        ):
            root = make_root(self.root.parent, f"native-bad-{len(list(self.root.parent.iterdir()))}")
            target = root / "v7-exchange-source.json"
            changed = json.loads(target.read_text()); mutation(changed)
            target.write_text(json.dumps(changed)); os.chmod(target, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(root))
        self.assertEqual(fixture.manifest["run_id"], "test-run.1")

    def test_issuer_metadata_url_is_exact_and_sybil_replay_must_be_owned_redis(self) -> None:
        path = self.root / "verifier.env.json"
        original = json.loads(path.read_text())
        for url in ("http://127.0.0.1:24001", "http://127.0.0.1:24001/wrong", "http://127.0.0.1:24002/.well-known/issuer"):
            envelope = json.loads(json.dumps(original)); envelope["env"]["ISSUER_URLS"] = url
            path.write_text(json.dumps(envelope)); os.chmod(path, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))
        path.write_text(json.dumps(original)); os.chmod(path, 0o600)
        envelope = json.loads(json.dumps(original))
        envelope["env"]["VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS"] = "http://127.0.0.1:24001/.well-known/issuer"
        path.write_text(json.dumps(envelope)); os.chmod(path, 0o600)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))
        path.write_text(json.dumps(original)); os.chmod(path, 0o600)
        issuer_path = self.root / "issuer.env.json"
        issuer = json.loads(issuer_path.read_text())
        for value in (None, "memory", "redis://127.0.0.1:24003/1", "redis://127.0.0.1:24002/0"):
            envelope = json.loads(json.dumps(issuer))
            if value is None:
                del envelope["env"]["SYBIL_REPLAY_STORE"]
            else:
                envelope["env"]["SYBIL_REPLAY_STORE"] = value
            issuer_path.write_text(json.dumps(envelope)); os.chmod(issuer_path, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))
        for value in (None, "redis://127.0.0.1:24003/1", "redis://127.0.0.1:24002/0"):
            envelope = json.loads(json.dumps(issuer))
            if value is None:
                del envelope["env"]["SYBIL_REPLAY_REDIS_URL"]
            else:
                envelope["env"]["SYBIL_REPLAY_REDIS_URL"] = value
            issuer_path.write_text(json.dumps(envelope)); os.chmod(issuer_path, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))

    def test_receipt_metadata_is_exact_six_public_fields(self) -> None:
        receipt_path = self.root / "receipt.json"
        original = json.loads(receipt_path.read_text())
        for field, changed in (("key_id", "0" * 64), ("algorithm", "other"), ("purpose", "other"),
                               ("public_key_b64", b64(bytes([7]) * 32)), ("valid_from", 2), ("valid_until", 3)):
            receipt = json.loads(json.dumps(original)); receipt[field] = changed
            receipt_path.write_text(json.dumps(receipt)); os.chmod(receipt_path, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root),)
        for invalid in (
            {key: value for key, value in original.items() if key != "valid_until"},
            original | {"status": "active"},
        ):
            receipt_path.write_text(json.dumps(invalid)); os.chmod(receipt_path, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))

    def test_native_exchange_signer_wrong_amount_type_and_unknown_field_rejected(self) -> None:
        path = self.root / "v7-exchange-source.json"
        original = json.loads(path.read_text())
        for amount in (43, "42", True):
            native = json.loads(json.dumps(original)); native["amount_minor"] = amount
            path.write_text(json.dumps(native)); os.chmod(path, 0o600)
            with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))
        native = json.loads(json.dumps(original)); native["new_field"] = "ignored?"
        path.write_text(json.dumps(native)); os.chmod(path, 0o600)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))

    def test_failure_diagnostic_never_echoes_private_env_values(self) -> None:
        path = self.root / "issuer.env.json"
        envelope = json.loads(path.read_text())
        envelope["env"]["NOT_ALLOWED"] = "private-admin"
        path.write_text(json.dumps(envelope)); os.chmod(path, 0o600)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = run.main(["--validate-only", "--fixture-dir", str(self.root)])
        self.assertEqual(result, 2)
        self.assertNotIn("private-admin", stderr.getvalue())

    def test_secret_bearing_public_manifest_addition_is_rejected(self) -> None:
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text()); manifest["private_key"] = "must-not-leak"
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        path.write_bytes(raw); os.chmod(path, 0o600)
        marker_path = self.root / "fixture.private.json"
        marker = json.loads(marker_path.read_text()); marker["manifest_sha256_hex"] = hashlib.sha256(raw).hexdigest()
        marker_path.write_text(json.dumps(marker)); os.chmod(marker_path, 0o600)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))

    def test_symlink_and_permission_fail_closed(self) -> None:
        target = self.root / "manifest.json"
        saved = self.root / "manifest.saved"
        target.rename(saved); target.symlink_to(saved)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))
        target.unlink(); saved.rename(target); os.chmod(target, 0o644)
        with self.assertRaises(run.Gate0Error): run.validate_fixture(str(self.root))

    def test_inherited_hostile_environment_is_not_forwarded(self) -> None:
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "bad", "LD_PRELOAD": "bad",
                                          "FREEBIRD_ALLOW_INSECURE_FALLBACK": "true", "PATH": "/evil"}, clear=True):
            child_env = run._process_env(self.root, "issuer", {"ISSUER_ID": "safe"})
        self.assertEqual(child_env["PATH"], os.defpath)
        self.assertEqual(child_env["ISSUER_ID"], "safe")
        self.assertFalse({"HTTP_PROXY", "LD_PRELOAD", "FREEBIRD_ALLOW_INSECURE_FALLBACK"} & child_env.keys())

    def test_occupied_port_is_detected_without_disturbing_listener(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0)); listener.listen()
        port = listener.getsockname()[1]
        try:
            with self.assertRaises(run.Gate0Error): run._port_available(port)
            self.assertGreaterEqual(listener.fileno(), 0)
        finally:
            listener.close()

    def test_child_start_failure_and_cleanup_only_track_owned_handles(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        supervisor = run.Supervisor(fixture, 0.01, popen=mock.Mock(side_effect=OSError("private error")))
        with self.assertRaises(run.Gate0Error):
            supervisor._spawn("redis", ["/fake/redis"], {})
        self.assertEqual(supervisor.children, [])
        supervisor.cleanup()

    def test_keyboard_interrupt_run_path_cleans_up_supervisor(self) -> None:
        fake = Path(self.temp.name).resolve() / "fake-bin"
        pid_file = Path(self.temp.name).resolve() / "descendant.pid"
        fake.write_text("#!/usr/bin/python3\nimport subprocess,sys\n"
                        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                        "open(sys.argv[1],'w').write(str(child.pid))\nraise KeyboardInterrupt()\n")
        fake.chmod(0o700)
        captured_children = []
        def interrupt_after_spawn(supervisor, *_args):
            child = supervisor._spawn("issuer", [str(fake), str(pid_file)], run._minimal_env(self.root, self.root))
            captured_children.append(child)
            deadline = __import__("time").monotonic() + 2
            while not pid_file.exists() and __import__("time").monotonic() < deadline:
                __import__("time").sleep(0.01)
            raise KeyboardInterrupt()
        with mock.patch.object(run.Supervisor, "run", autospec=True, side_effect=interrupt_after_spawn), \
             contextlib.redirect_stderr(io.StringIO()):
            result = run.main(["--run", "--fixture-dir", str(self.root), "--redis-server-bin", str(fake),
                               "--issuer-bin", str(fake), "--verifier-bin", str(fake), "--", str(fake)])
        self.assertEqual(result, 2)
        self.assertTrue(captured_children)
        self.assertIsNotNone(captured_children[0].poll())

    def test_fake_child_binary_exit_and_deadline_are_reaped(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        exited = Path(self.temp.name).resolve() / "fake-exit"
        exited.write_text("#!/usr/bin/python3\nraise SystemExit(23)\n")
        exited.chmod(0o700)
        supervisor = run.Supervisor(fixture, 2.0)
        child = supervisor._spawn("redis", [str(exited)], run._minimal_env(self.root, self.root))
        import time
        deadline = time.monotonic() + 2
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        with self.assertRaises(run.Gate0Error): supervisor._alive(child, "fake child")
        supervisor.cleanup()

        sleeper = Path(self.temp.name).resolve() / "fake-sleeper"
        sleeper.write_text("#!/usr/bin/python3\nimport time; time.sleep(30)\n")
        sleeper.chmod(0o700)
        supervisor = run.Supervisor(fixture, 0.01)
        child = supervisor._spawn("issuer", [str(sleeper)], run._minimal_env(self.root, self.root))
        with self.assertRaises(run.Gate0Error): supervisor._wait_until(lambda: False, child, "fake issuer")
        supervisor.cleanup()
        self.assertIsNotNone(child.poll())

    def test_cleanup_kills_descendant_after_direct_parent_exits(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        pid_file = Path(self.temp.name).resolve() / "descendant.pid"
        parent = Path(self.temp.name).resolve() / "fake-parent"
        parent.write_text("#!/usr/bin/python3\nimport subprocess,sys\n"
                          "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                          "open(sys.argv[1],'w').write(str(child.pid))\n")
        parent.chmod(0o700)
        supervisor = run.Supervisor(fixture, 1.0)
        process = supervisor._spawn("redis", [str(parent), str(pid_file)], run._minimal_env(self.root, self.root))
        deadline = __import__("time").monotonic() + 2
        while (process.poll() is None or not pid_file.exists()) and __import__("time").monotonic() < deadline:
            __import__("time").sleep(0.01)
        self.assertIsNotNone(process.poll())
        descendant = int(pid_file.read_text())
        supervisor.cleanup()
        deadline = __import__("time").monotonic() + 2
        while __import__("time").monotonic() < deadline:
            try: os.kill(descendant, 0)
            except ProcessLookupError: break
            __import__("time").sleep(0.02)
        with self.assertRaises(ProcessLookupError): os.kill(descendant, 0)

    def test_unconfirmed_owned_group_cleanup_is_reported(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        supervisor = run.Supervisor(fixture, 0.01)
        supervisor.TERM_GRACE_SECONDS = 0.01; supervisor.KILL_GRACE_SECONDS = 0.01
        supervisor.owned_pgids = [99123]
        with mock.patch.object(run.os, "killpg"), mock.patch.object(supervisor, "_group_exists", return_value=True):
            with self.assertRaises(run.Gate0Error): supervisor.cleanup()

    def test_issuer_readiness_requires_readyz_v4_pins_and_v7_discovery(self) -> None:
        fixture = run.validate_fixture(str(self.root))
        supervisor = run.Supervisor(fixture, 0.1)
        manifest = fixture.manifest
        v4_doc = {"issuer_id": manifest["issuer_id"], "voprf": {
            "kid": manifest["v4"]["kid"], "pubkey": manifest["v4"]["public_key_b64"]}}
        keys_doc = {"issuer_id": manifest["issuer_id"], **manifest["discovery_pins"]}

        def response(route, wrong_v4=False, not_ready=False):
            if route == "/healthz": return 200, {"status": "alive"}
            if route == "/readyz": return (503, {"status": "not_ready"}) if not_ready else (200, {"status": "ready"})
            if route == "/.well-known/issuer":
                if wrong_v4: return 200, {**v4_doc, "voprf": {**v4_doc["voprf"], "kid": "other"}}
                return 200, v4_doc
            if route == "/.well-known/keys": return 200, keys_doc
            raise AssertionError("unexpected readiness route")

        with mock.patch.object(supervisor, "_http_json", side_effect=lambda _port, route: response(route, not_ready=True)):
            self.assertFalse(supervisor._issuer_is_ready())
        with mock.patch.object(supervisor, "_http_json", side_effect=lambda _port, route: response(route, wrong_v4=True)):
            self.assertFalse(supervisor._issuer_is_ready())
        with mock.patch.object(supervisor, "_http_json", side_effect=lambda _port, route: response(route)):
            self.assertTrue(supervisor._issuer_is_ready())


class FakeRedisSocket:
    def __init__(self, redis: "FakeRedis"):
        self.redis = redis
        self.output = b""
        self.response = b""

    def __enter__(self): return self
    def __exit__(self, *_args): return None
    def settimeout(self, _timeout): pass
    def sendall(self, request: bytes):
        self.redis.requests.append(request)
        parts = request.split(b"\r\n")
        count = int(parts[0][1:]); values = []
        cursor = 1
        for _ in range(count):
            length = int(parts[cursor][1:]); cursor += 1
            values.append(parts[cursor][:length]); cursor += 1
        command = values[0].upper()
        if command == b"SELECT": self.response = b"+OK\r\n"
        elif command == b"DBSIZE": self.response = b":0\r\n"
        elif command == b"INFO":
            if values[1] == b"server":
                body = f"# Server\r\nprocess_id:{self.redis.process_id}\r\n".encode()
            else:
                body = f"# Persistence\r\naof_enabled:{self.redis.aof_enabled}\r\n".encode()
            self.response = b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n"
        elif command == b"CONFIG":
            body = b"*2\r\n$11\r\nappendfsync\r\n$" + str(len(self.redis.appendfsync)).encode() + b"\r\n" + self.redis.appendfsync + b"\r\n"
            self.response = body
        elif command == b"GET":
            value = self.redis.values.get(values[1])
            self.response = b"$-1\r\n" if value is None else b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"
        elif command == b"SET":
            self.redis.set_args = values
            if values[1] in self.redis.values: self.response = b"$-1\r\n"
            else:
                self.redis.values[values[1]] = values[2]; self.response = b"+OK\r\n"
        else: raise AssertionError("unexpected fake Redis command")
    def recv(self, amount: int) -> bytes:
        result, self.response = self.response[:amount], self.response[amount:]
        return result


class FakeRedis:
    def __init__(self, process_id=321, aof_enabled=1, appendfsync=b"always"):
        self.values = {}; self.requests = []; self.set_args = []
        self.process_id = process_id; self.aof_enabled = aof_enabled; self.appendfsync = appendfsync


class RedisTests(unittest.TestCase):
    def test_authority_uses_raw32_set_nx_and_byte_readback(self) -> None:
        redis = FakeRedis()
        with mock.patch.object(run.socket, "create_connection", side_effect=lambda *_a, **_k: FakeRedisSocket(redis)):
            manifest = {"replay_authority": {"authority_id": b64(bytes(range(32)))}}
            run.provision_owned_redis(24003, redis.process_id, manifest, lambda: None,
                                      connect=lambda *_a, **_k: FakeRedisSocket(redis))
        self.assertEqual(redis.set_args, [b"SET", run.AUTHORITY_KEY, bytes(range(32)), b"NX"])
        self.assertEqual(redis.values[run.AUTHORITY_KEY], bytes(range(32)))

    def test_existing_authority_is_never_overwritten(self) -> None:
        redis = FakeRedis(); redis.values[run.AUTHORITY_KEY] = b"x" * 32
        with mock.patch.object(run.socket, "create_connection", side_effect=lambda *_a, **_k: FakeRedisSocket(redis)):
            with self.assertRaises(run.Gate0Error):
                run.provision_owned_redis(24003, redis.process_id,
                    {"replay_authority": {"authority_id": b64(bytes(32))}}, lambda: None,
                    connect=lambda *_a, **_k: FakeRedisSocket(redis))
        self.assertEqual(redis.values[run.AUTHORITY_KEY], b"x" * 32)

    def test_foreign_pong_pid_or_bad_aof_fails_before_any_set(self) -> None:
        for redis in (FakeRedis(process_id=999), FakeRedis(aof_enabled=0), FakeRedis(appendfsync=b"everysec")):
            with self.subTest():
                with mock.patch.object(run.os, "killpg") as killpg, \
                     mock.patch.object(run.socket, "create_connection", side_effect=lambda *_a, _redis=redis, **_k: FakeRedisSocket(_redis)):
                    with self.assertRaises(run.Gate0Error):
                        run.provision_owned_redis(24003, 321,
                            {"replay_authority": {"authority_id": b64(bytes(32))}}, lambda: None,
                            connect=lambda *_a, _redis=redis, **_k: FakeRedisSocket(_redis))
                killpg.assert_not_called()
                self.assertEqual(redis.set_args, [])
                self.assertNotIn(run.AUTHORITY_KEY, redis.values)

    def test_ownership_recheck_before_set_and_abort_if_process_dies(self) -> None:
        redis = FakeRedis()
        checks = 0
        def alive() -> None:
            nonlocal checks
            checks += 1
            if checks >= 2: raise run.Gate0Error("owned Redis exited")
        with mock.patch.object(run.socket, "create_connection", side_effect=lambda *_a, **_k: FakeRedisSocket(redis)):
            with self.assertRaises(run.Gate0Error):
                run.provision_owned_redis(24003, redis.process_id,
                    {"replay_authority": {"authority_id": b64(bytes(32))}}, alive,
                    connect=lambda *_a, **_k: FakeRedisSocket(redis))
        self.assertEqual(redis.set_args, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
