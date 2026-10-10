#!/usr/bin/env python3
"""stdlib-only synthetic lifecycle tests for the G0.4 evidence coordinator."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import test_run
import evidence
import run


class FakeChild:
    def poll(self): return None


class FakeSupervisor:
    def __init__(self, fixture, _timeout=1.0, *, replay_failures=None, missing_trust=False, driver_failure=False,
                 trust_mutation=None):
        self.fixture = fixture
        self.verifier_env = dict(fixture.verifier_env)
        self.verifier_child = FakeChild()
        self.redis_child = FakeChild()
        self.issuer_child = FakeChild()
        self.database = 0
        self.generations = []
        self.empty_database_checks = []
        self.driver_argv = []
        self.admin_headers = []
        self.cleanup_called = False
        self.replay_failures = replay_failures or [evidence.REPLAY_FAILURE]
        self.missing_trust = missing_trust
        self.driver_failure = driver_failure
        self.trust_mutation = trust_mutation or {}
        self.detail_route_accessed = False
        self.log_root = fixture.root.parent / "fake-child-logs"
        self.log_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.log_root, 0o700)

    def start_owned_services(self, redis_bin, issuer_bin, verifier_bin, initial_verifier_log="verifier"):
        self.binaries = (redis_bin, issuer_bin, verifier_bin)
        self.database = 0
        self.generations.append((0, initial_verifier_log))

    def assert_owned_database_empty(self, database):
        self.empty_database_checks.append(database)

    def start_verifier_database(self, database, log_name):
        self.database = database
        self.generations.append((database, log_name))
        self.verifier_child = FakeChild()
        self.verifier_env = dict(self.fixture.verifier_env)
        self.verifier_env["REDIS_URL"] = f"redis://127.0.0.1:{self.fixture.redis_port}/{database}"
        return self.verifier_child

    def verifier_ready(self): return self.database == 0

    def _http_json(self, _port, route, headers=None):
        if headers is not None:
            self.admin_headers.append(dict(headers))
        if route == "/ready":
            return (200, {"status": "ready"}) if self.database == 0 else (503, None)
        if route == "/admin/readiness":
            if self.database == 0:
                return 200, {"status": "ready", "failures": []}
            return 200, {"status": "not_ready", "failures": list(self.replay_failures)}
        if route == "/admin/issuers":
            pins = self.fixture.manifest["discovery_pins"]
            ids = [pins["native_bearer_v7"]["token_key_id"]]
            ids.extend(item["token_key_id"] for item in pins["native_bearer_v7_retained"])
            ids.extend(item["token_key_id"] for item in pins["native_exchange_v7"]["active_descriptors"])
            ids.extend(item["token_key_id"] for item in pins["native_exchange_v7"]["retained_descriptors"])
            issuer = {"issuer_id": self.fixture.manifest["issuer_id"], "kid": self.fixture.manifest["v4"]["kid"],
                "public_key_count": 0 if self.missing_trust else len(set(ids)),
                "pubkey_preview": self.fixture.manifest["v4"]["public_key_b64"][:16], "age_secs": 1}
            issuer.update(self.trust_mutation)
            return 200, {"issuers": [issuer], "total": 1}
        if route.startswith("/admin/issuers/"):
            self.detail_route_accessed = True
            return 404, None
        return 404, None

    def run_owned_driver(self, argv, _timeout, log_name):
        if self.driver_failure:
            raise run.Gate0Error("private driver error")
        self.driver_argv.append((list(argv), log_name))
        path = self.log_root / f"{log_name}.log"
        stage = "spend_absent" if log_name == "spend-absence-check" else "current"
        path.write_text(json.dumps({"run_id": self.fixture.manifest["run_id"], "stage": stage}) + "\n")
        os.chmod(path, 0o600)
        return 0, path

    def cleanup(self):
        self.cleanup_called = True


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.fixture_root = test_run.make_root(self.base, "fixture")
        self.fixture = run.validate_fixture(str(self.fixture_root))
        self.workspace = self.base / "scarcity-workspace"
        self.workspace.mkdir(mode=0o700)
        os.chmod(self.workspace, 0o700)
        self.node = self.base / "node-fake"
        self.node.write_text("#!/usr/bin/python3\n")
        self.node.chmod(0o700)
        self.driver = self.base / "gate0-driver.js"
        self.driver.write_text("// synthetic compiled driver fixture\n")
        os.chmod(self.driver, 0o600)
        self.bins = (str(self.node), str(self.node), str(self.node), str(self.node), str(self.driver))

    def tearDown(self): self.temp.cleanup()

    def coordinator(self, supervisor, **options):
        return evidence.coordinate_evidence(
            supervisor, self.bins[0], self.bins[1], self.bins[2], self.bins[3], self.bins[4],
            str(self.workspace), **options,
        )

    def test_success_baseline_wrong_db_restore_current_and_exact_spend_absence(self):
        supervisor = FakeSupervisor(self.fixture)
        report = self.coordinator(supervisor)
        self.assertEqual(report["run_id"], self.fixture.manifest["run_id"])
        self.assertTrue(all(report["assertions"].values()))
        self.assertEqual(supervisor.empty_database_checks, [1])
        self.assertEqual(supervisor.generations, [
            (0, "verifier-db0-initial"), (1, "verifier-db1-negative"), (0, "verifier-db0-restored"),
        ])
        self.assertEqual(supervisor.verifier_env["REDIS_URL"], f"redis://127.0.0.1:{self.fixture.redis_port}/0")
        self.assertEqual([name for _, name in supervisor.generations], list(dict.fromkeys(name for _, name in supervisor.generations)))
        self.assertTrue(all(headers.get("x-admin-key") == self.fixture.verifier_env["ADMIN_API_KEY"]
                            for headers in supervisor.admin_headers))
        self.assertFalse(supervisor.detail_route_accessed, "coordinator uses supported issuer-list route only")
        self.assertEqual(len(supervisor.driver_argv), 2)
        first, second = supervisor.driver_argv
        manifest_path = str(self.fixture_root / "manifest.json")
        self.assertEqual(first[0], [str(self.node), str(self.driver), manifest_path, str(self.workspace)])
        self.assertEqual(second[0], [str(self.node), str(self.driver), "spend-absent", manifest_path,
                                     str(self.workspace), f"redis://127.0.0.1:{self.fixture.redis_port}/0"])
        self.assertNotIn(self.fixture.verifier_env["ADMIN_API_KEY"], json.dumps(report))

    def test_wrong_db_must_fail_for_replay_authority_only(self):
        supervisor = FakeSupervisor(self.fixture, replay_failures=["replay store is unreachable"])
        clock = [0.0]
        def now():
            clock[0] += 0.1
            return clock[0]
        with self.assertRaises(evidence.EvidenceError):
            self.coordinator(supervisor, wrong_db_timeout=0.5, monotonic=now, sleep=lambda _delay: None)
        self.assertEqual(supervisor.database, 1)
        self.assertEqual(supervisor.generations[-1], (1, "verifier-db1-negative"))

    def test_missing_loaded_trust_fails_baseline(self):
        supervisor = FakeSupervisor(self.fixture, missing_trust=True)
        clock = [0.0]
        def now():
            clock[0] += 0.1
            return clock[0]
        with self.assertRaises(evidence.EvidenceError):
            self.coordinator(supervisor, readiness_timeout=0.5, monotonic=now, sleep=lambda _delay: None)

    def test_issuer_list_pins_count_age_and_identity_fail_closed(self):
        mutations = (
            {"kid": "wrong"},
            {"pubkey_preview": "wrong"},
            {"public_key_count": 999},
            {"age_secs": 121},
            {"issuer_id": "issuer:other"},
        )
        for mutation in mutations:
            with self.subTest(field=next(iter(mutation))):
                supervisor = FakeSupervisor(self.fixture, trust_mutation=mutation)
                self.assertFalse(evidence._issuer_trust_loaded(supervisor))
                self.assertFalse(supervisor.detail_route_accessed)

    def test_main_cleans_owned_supervisor_and_emits_only_closed_assertion_report(self):
        supervisors = []
        def factory(fixture, timeout):
            supervisor = FakeSupervisor(fixture, timeout)
            supervisors.append(supervisor)
            return supervisor
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(stderr):
            result = evidence.main([
                "--fixture-dir", str(self.fixture_root), "--redis-server-bin", str(self.node),
                "--issuer-bin", str(self.node), "--verifier-bin", str(self.node), "--node-bin", str(self.node),
                "--scarcity-driver-js", str(self.driver), "--scarcity-workspace", str(self.workspace),
            ], supervisor_factory=factory)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        report = json.loads(stdout.getvalue())
        self.assertEqual(set(report), {"run_id", "assertions"})
        self.assertEqual(set(report["assertions"]), {
            "initial_db0_empty_authority_preseeded", "baseline_probe_ready_and_trust_loaded",
            "wrong_db_replay_specific_nonready_trust_loaded", "db0_probe_ready_and_trust_restored",
            "scarcity_driver_current", "exact_spend_marker_absent_after_check", "owned_process_cleanup_confirmed",
        })
        self.assertTrue(all(report["assertions"].values()))
        self.assertTrue(supervisors[0].cleanup_called)
        self.assertNotIn(self.fixture.verifier_env["ADMIN_API_KEY"], stdout.getvalue())

    def test_driver_failure_is_redacted_and_triggers_owned_cleanup(self):
        supervisors = []
        def factory(fixture, timeout):
            supervisor = FakeSupervisor(fixture, timeout, driver_failure=True)
            supervisors.append(supervisor)
            return supervisor
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(stderr):
            result = evidence.main([
                "--fixture-dir", str(self.fixture_root), "--redis-server-bin", str(self.node),
                "--issuer-bin", str(self.node), "--verifier-bin", str(self.node), "--node-bin", str(self.node),
                "--scarcity-driver-js", str(self.driver), "--scarcity-workspace", str(self.workspace),
            ], supervisor_factory=factory)
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(self.fixture.verifier_env["ADMIN_API_KEY"], stderr.getvalue())
        self.assertTrue(supervisors[0].cleanup_called)

    def test_workspace_must_be_empty_canonical_and_separate_from_fixture(self):
        (self.workspace / "occupied").write_text("x")
        fake = FakeSupervisor(self.fixture)
        with self.assertRaises(evidence.EvidenceError): self.coordinator(fake)
        (self.workspace / "occupied").unlink()
        with self.assertRaises(evidence.EvidenceError):
            evidence._workspace_root(str(self.fixture_root), self.fixture_root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
