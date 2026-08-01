#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT

import contextlib
import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_gate", ROOT / "scripts/release-gate.py")
assert SPEC and SPEC.loader
release_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_gate
SPEC.loader.exec_module(release_gate)

SHA = "a" * 40
REQUIRED = release_gate.REQUIRED_CHECKS


class MockResponse:
    def __init__(self, payload):
        self.stream = io.StringIO(json.dumps(payload))

    def __enter__(self):
        return self.stream

    def __exit__(self, *_args):
        self.stream.close()


class MockAPI:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.urls = []

    def __call__(self, request, *, timeout):
        self.urls.append((request.full_url, timeout))
        response = next(self.responses)
        if isinstance(response, BaseException):
            raise response
        return MockResponse(response)


def check(name, status="completed", conclusion: str | None = "success", run_id=1):
    return {
        "id": run_id,
        "name": name,
        "head_sha": SHA,
        "status": status,
        "conclusion": conclusion,
    }


def payload(*runs):
    return {"check_runs": list(runs)}


class ReleaseGateTests(unittest.TestCase):
    def run_gate(self, responses, *, timeout=45, interval=15):
        api = MockAPI(responses)
        now = [0.0]
        sleeps = []

        def clock():
            return now[0]

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = release_gate.run_gate(
                SHA,
                REQUIRED,
                "owner/repository",
                "test-token",
                "https://api.example.test",
                poll_interval=interval,
                timeout=timeout,
                urlopen=api,
                sleeper=sleep,
                clock=clock,
            )
        return result, api, sleeps, stdout.getvalue(), stderr.getvalue()

    def test_immediate_all_success(self):
        result, api, sleeps, output, error = self.run_gate(
            [payload(*(check(name, run_id=index + 1) for index, name in enumerate(REQUIRED)))]
        )
        self.assertEqual(result, 0)
        self.assertEqual(sleeps, [])
        self.assertIn("release gate passed", output)
        self.assertEqual(error, "")
        self.assertIn(f"/commits/{SHA}/check-runs?per_page=100&page=1", api.urls[0][0])

    def test_missing_queued_in_progress_then_success(self):
        result, _api, sleeps, output, _error = self.run_gate(
            [
                payload(),
                payload(*(check(name, "queued", None, index + 1) for index, name in enumerate(REQUIRED))),
                payload(*(check(name, "in_progress", None, index + 1) for index, name in enumerate(REQUIRED))),
                payload(*(check(name, run_id=index + 10) for index, name in enumerate(REQUIRED))),
            ],
            timeout=60,
        )
        self.assertEqual(result, 0)
        self.assertEqual(sleeps, [15, 15, 15])
        self.assertEqual(output.count("release gate state"), 4)

    def test_terminal_failure_fails_without_waiting(self):
        runs = [check(name, run_id=index + 1) for index, name in enumerate(REQUIRED)]
        runs[1] = check("test", conclusion="failure", run_id=99)
        result, _api, sleeps, _output, error = self.run_gate([payload(*runs)])
        self.assertEqual(result, 1)
        self.assertEqual(sleeps, [])
        self.assertIn("required checks failed", error)
        self.assertIn("test", error)

    def test_timeout_is_bounded(self):
        result, api, sleeps, output, error = self.run_gate([payload()] * 5, timeout=30)
        self.assertEqual(result, 1)
        self.assertEqual(sleeps, [15, 15])
        self.assertEqual(len(api.urls), 2)
        self.assertEqual(output.count("release gate state"), 2)
        self.assertIn("timed out", error)

    def test_api_and_malformed_failures_are_fail_closed(self):
        cases = [
            [urllib.error.URLError("unavailable")],
            [{"not_check_runs": []}],
            [payload({"name": "build"})],
        ]
        for responses in cases:
            with self.subTest(response=responses[0]):
                result, _api, sleeps, _output, error = self.run_gate(responses)
                self.assertEqual(result, 1)
                self.assertEqual(sleeps, [])
                self.assertIn("fail closed", error)

    def test_duplicate_names_select_newest_run_deterministically(self):
        runs = [check(name, run_id=index + 10) for index, name in enumerate(REQUIRED)]
        runs.extend(
            [
                check("build", run_id=2),
                check("build", conclusion="failure", run_id=20),
            ]
        )
        result, _api, sleeps, _output, error = self.run_gate([payload(*runs)])
        self.assertEqual(result, 1)
        self.assertEqual(sleeps, [])
        self.assertIn("build", error)
        self.assertEqual(release_gate.newest_runs(runs, ("build",))["build"]["id"], 20)

    def test_workflow_fetches_main_and_checks_tag_lineage_before_gate(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        fetch = workflow.index('"refs/heads/main:refs/remotes/origin/main"')
        lineage = workflow.index("git merge-base --is-ancestor")
        gate = workflow.index("python3 scripts/release-gate.py")
        self.assertLess(fetch, lineage)
        self.assertLess(lineage, gate)
        self.assertIn('"refs/tags/${TAG}:refs/tags/${TAG}"', workflow)
        self.assertIn('git rev-parse "refs/tags/${TAG}^{commit}"', workflow)
        self.assertIn("timeout-minutes: 50", workflow)
        for name in REQUIRED:
            self.assertIn(name, workflow)


if __name__ == "__main__":
    unittest.main()
