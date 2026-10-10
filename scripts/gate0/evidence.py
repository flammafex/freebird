#!/usr/bin/env python3
"""Run the private G0.4 evidence sequence using only owned local processes."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Sequence

import run

MAX_CHILD_REPORT_BYTES = 16_384
WRONG_DB_DEADLINE_SECONDS = 20.0
READY_DEADLINE_SECONDS = 45.0
REPLAY_FAILURE = "replay authority is unavailable or stale"


class EvidenceError(Exception):
    """Safe evidence-coordinator failure without child/private details."""


def _fail() -> None:
    raise EvidenceError("G0.4 evidence sequence failed safely")


def _exact(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail()
    return value


def _workspace_root(value: str, fixture_root: Path) -> Path:
    try:
        root = Path(value)
        canonical = run._canonical_root(value)
        if canonical != root or any(root.iterdir()):
            _fail()
        if root == fixture_root or root.is_relative_to(fixture_root) or fixture_root.is_relative_to(root):
            _fail()
        return root
    except Exception:
        _fail()


def _compiled_js(value: str) -> str:
    try:
        path = Path(value)
        info = path.lstat()
        if not path.is_absolute() or path.resolve(strict=True) != path or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail()
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            _fail()
        return str(path)
    except Exception:
        _fail()


def _admin_get(supervisor: run.Supervisor, route: str) -> tuple[int, Any]:
    try:
        admin_key = supervisor.fixture.verifier_env["ADMIN_API_KEY"]
        return supervisor._http_json(supervisor.fixture.verifier_port, route, {"x-admin-key": admin_key})
    except Exception:
        return 0, None


def _issuer_trust_loaded(supervisor: run.Supervisor) -> bool:
    fixture = supervisor.fixture
    issuer_id = fixture.manifest["issuer_id"]
    status, value = _admin_get(supervisor, "/admin/issuers")
    if status != 200 or type(value) is not dict or set(value) != {"issuers", "total"}:
        return False
    issuers = value.get("issuers")
    if type(value.get("total")) is not int or value["total"] != 1 or type(issuers) is not list or len(issuers) != 1:
        return False
    issuer = issuers[0]
    if type(issuer) is not dict or set(issuer) != {"issuer_id", "kid", "public_key_count", "pubkey_preview", "age_secs"} or \
       issuer.get("issuer_id") != issuer_id:
        return False
    v4 = fixture.manifest["v4"]
    if issuer.get("kid") != v4["kid"] or issuer.get("pubkey_preview") != v4["public_key_b64"][:16]:
        return False
    age = issuer.get("age_secs")
    if type(age) is not int or age < 0 or age > 120:
        return False
    pins = fixture.manifest["discovery_pins"]
    expected = {pins["native_bearer_v7"]["token_key_id"]}
    expected.update(item["token_key_id"] for item in pins["native_bearer_v7_retained"])
    exchange = pins["native_exchange_v7"]
    expected.update(item["token_key_id"] for item in exchange["active_descriptors"])
    expected.update(item["token_key_id"] for item in exchange["retained_descriptors"])
    selected_graph_key = next((policy["token_key_id"] for policy in pins["native_graph_issuance_v7"]["active_policies"]
                               if policy["policy_id"] == fixture.manifest["graph_policy_id"]), None)
    return selected_graph_key is not None and selected_graph_key in expected and \
        type(issuer.get("public_key_count")) is int and issuer["public_key_count"] == len(expected)


def _readiness(supervisor: run.Supervisor) -> tuple[int, dict[str, Any] | None]:
    return _admin_get(supervisor, "/admin/readiness")


def _baseline_ready(supervisor: run.Supervisor) -> bool:
    if not supervisor.verifier_ready():
        return False
    status, report = _readiness(supervisor)
    if status != 200 or type(report) is not dict or set(report) != {"status", "failures"}:
        return False
    return report["status"] == "ready" and report["failures"] == [] and _issuer_trust_loaded(supervisor)


def _wait_for(supervisor: run.Supervisor, predicate: Callable[[], bool], timeout: float,
              monotonic: Callable[[], float], sleep: Callable[[float], None]) -> bool:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if any(getattr(supervisor, name, None) is None or getattr(supervisor, name).poll() is not None
               for name in ("redis_child", "issuer_child", "verifier_child")):
            return False
        try:
            if predicate():
                return True
        except Exception:
            pass
        sleep(0.1)
    return False


def _wrong_db_replay_failure(supervisor: run.Supervisor) -> bool:
    public_status, _ = supervisor._http_json(supervisor.fixture.verifier_port, "/ready")
    if public_status == 200:
        return False
    admin_status, report = _readiness(supervisor)
    if admin_status != 200 or type(report) is not dict or set(report) != {"status", "failures"}:
        return False
    failures = report["failures"]
    return report["status"] == "not_ready" and failures == [REPLAY_FAILURE] and _issuer_trust_loaded(supervisor)


def _closed_child_stage(log_path: Path, run_id: str, stage: str) -> None:
    try:
        info = log_path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or \
           (hasattr(os, "getuid") and info.st_uid != os.getuid()) or info.st_size < 1 or info.st_size > MAX_CHILD_REPORT_BYTES:
            _fail()
        data = log_path.read_bytes()
        value = run.parse_closed_json(data, MAX_CHILD_REPORT_BYTES)
        result = _exact(value, {"run_id", "stage"})
        if result["run_id"] != run_id or result["stage"] != stage:
            _fail()
    except Exception:
        _fail()


def coordinate_evidence(supervisor: run.Supervisor, redis_bin: str, issuer_bin: str, verifier_bin: str,
                        node_bin: str, driver_js: str, workspace_root: str,
                        *, readiness_timeout: float = READY_DEADLINE_SECONDS,
                        wrong_db_timeout: float = WRONG_DB_DEADLINE_SECONDS,
                        driver_timeout: float = 240.0,
                        monotonic: Callable[[], float] = time.monotonic,
                        sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    fixture = supervisor.fixture
    workspace = _workspace_root(workspace_root, fixture.root)
    node_bin = run._binary(node_bin, "Node")
    driver_js = _compiled_js(driver_js)
    supervisor.start_owned_services(redis_bin, issuer_bin, verifier_bin, initial_verifier_log="verifier-db0-initial")
    if not _wait_for(supervisor, lambda: _baseline_ready(supervisor), readiness_timeout, monotonic, sleep):
        _fail()
    initial_loaded = _issuer_trust_loaded(supervisor)
    if not initial_loaded:
        _fail()

    # DB 1 is a distinct, initially empty namespace on the same owned Redis process.
    supervisor.assert_owned_database_empty(1)
    supervisor.start_verifier_database(1, "verifier-db1-negative")
    if not _wait_for(supervisor, lambda: _wrong_db_replay_failure(supervisor), wrong_db_timeout, monotonic, sleep):
        _fail()
    wrong_db_loaded = _issuer_trust_loaded(supervisor)
    if not wrong_db_loaded:
        _fail()

    supervisor.start_verifier_database(0, "verifier-db0-restored")
    if not _wait_for(supervisor, lambda: _baseline_ready(supervisor), readiness_timeout, monotonic, sleep):
        _fail()
    restored_loaded = _issuer_trust_loaded(supervisor)
    if not restored_loaded:
        _fail()

    fixture_manifest = str(fixture.root / "manifest.json")
    driver_argv = [node_bin, driver_js, fixture_manifest, str(workspace)]
    driver_exit, driver_log = supervisor.run_owned_driver(driver_argv, driver_timeout, "scarcity-driver")
    if driver_exit != 0:
        _fail()
    _closed_child_stage(driver_log, fixture.manifest["run_id"], "current")

    redis_url = f"redis://127.0.0.1:{fixture.redis_port}/0"
    spend_argv = [node_bin, driver_js, "spend-absent", fixture_manifest, str(workspace), redis_url]
    spend_exit, spend_log = supervisor.run_owned_driver(spend_argv, driver_timeout, "spend-absence-check")
    if spend_exit != 0:
        _fail()
    _closed_child_stage(spend_log, fixture.manifest["run_id"], "spend_absent")
    return {
        "run_id": fixture.manifest["run_id"],
        "assertions": {
            "initial_db0_empty_authority_preseeded": True,
            "baseline_probe_ready_and_trust_loaded": initial_loaded,
            "wrong_db_replay_specific_nonready_trust_loaded": wrong_db_loaded,
            "db0_probe_ready_and_trust_restored": restored_loaded,
            "scarcity_driver_current": True,
            "exact_spend_marker_absent_after_check": True,
        },
    }


def _positive_timeout(value: str) -> float:
    try: result = float(value)
    except ValueError: raise argparse.ArgumentTypeError("must be a positive number") from None
    if not 0 < result <= 3600: raise argparse.ArgumentTypeError("must be in (0, 3600]")
    return result


def main(argv: Sequence[str] | None = None, supervisor_factory: Callable[..., run.Supervisor] = run.Supervisor) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", required=True)
    parser.add_argument("--redis-server-bin", required=True)
    parser.add_argument("--issuer-bin", required=True)
    parser.add_argument("--verifier-bin", required=True)
    parser.add_argument("--node-bin", required=True)
    parser.add_argument("--scarcity-driver-js", required=True)
    parser.add_argument("--scarcity-workspace", required=True)
    parser.add_argument("--timeout", type=_positive_timeout, default=45.0)
    parser.add_argument("--negative-timeout", type=_positive_timeout, default=WRONG_DB_DEADLINE_SECONDS)
    args = parser.parse_args(argv)
    supervisor: run.Supervisor | None = None
    old_handlers: dict[int, Any] = {}
    try:
        fixture = run.validate_fixture(args.fixture_dir)
        workspace = _workspace_root(args.scarcity_workspace, fixture.root)
        node_bin = run._binary(args.node_bin, "Node")
        redis_bin = run._binary(args.redis_server_bin, "Redis")
        issuer_bin = run._binary(args.issuer_bin, "issuer")
        verifier_bin = run._binary(args.verifier_bin, "verifier")
        driver_js = _compiled_js(args.scarcity_driver_js)
        supervisor = supervisor_factory(fixture, args.timeout)
        def signal_handler(_signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt()
        for sig in (run.signal.SIGINT, run.signal.SIGTERM):
            old_handlers[sig] = run.signal.signal(sig, signal_handler)
        report = coordinate_evidence(supervisor, redis_bin, issuer_bin, verifier_bin, node_bin, driver_js, str(workspace),
                                     readiness_timeout=args.timeout, wrong_db_timeout=args.negative_timeout)
        supervisor.cleanup()
        report["assertions"]["owned_process_cleanup_confirmed"] = True
        supervisor = None
        print(json.dumps(report, separators=(",", ":")))
        return 0
    except Exception:
        if supervisor is not None:
            try: supervisor.cleanup()
            except Exception: pass
        print("G0.4 evidence: failed safely; private details withheld", file=sys.stderr)
        return 2
    finally:
        for sig, handler in old_handlers.items():
            try: run.signal.signal(sig, handler)
            except Exception: pass


if __name__ == "__main__":
    raise SystemExit(main())
