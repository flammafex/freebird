#!/usr/bin/env python3
"""Fail closed unless the required checks passed for one exact commit."""

# SPDX-License-Identifier: Apache-2.0 OR MIT

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any


REQUIRED_CHECKS = (
    "build",
    "test",
    "feature-tests",
    "lint",
    "security",
    "javascript-sdk",
    "repository-hygiene",
    "compose-smoke",
)
DEFAULT_POLL_INTERVAL_SECONDS = 15
DEFAULT_TIMEOUT_SECONDS = 45 * 60
MIN_POLL_INTERVAL_SECONDS = 15
MAX_POLL_INTERVAL_SECONDS = 30
MIN_TIMEOUT_SECONDS = 45 * 60
MAX_TIMEOUT_SECONDS = 60 * 60
API_REQUEST_TIMEOUT_SECONDS = 30
MAX_PAGES = 100
SHA_RE = re.compile(r"[0-9a-fA-F]{40}\Z")
PENDING_STATUSES = {"queued", "in_progress", "requested", "waiting", "pending"}


class ReleaseGateError(Exception):
    """An API or response error that must fail the release gate."""


class PollDeadlineExceeded(Exception):
    """The bounded polling deadline elapsed while fetching check runs."""


def _validate_run(run: Any, sha: str) -> dict[str, Any]:
    if not isinstance(run, dict):
        raise ReleaseGateError("release gate API returned a malformed check run")

    name = run.get("name")
    run_id = run.get("id")
    status = run.get("status")
    conclusion = run.get("conclusion")
    head_sha = run.get("head_sha")
    if not isinstance(name, str) or not name or not isinstance(run_id, int) or isinstance(run_id, bool):
        raise ReleaseGateError("release gate API returned a malformed check run")
    if run_id <= 0:
        raise ReleaseGateError("release gate API returned a malformed check run")
    if (
        not isinstance(status, str)
        or status not in PENDING_STATUSES | {"completed"}
        or (conclusion is not None and not isinstance(conclusion, str))
        or not isinstance(head_sha, str)
        or head_sha.lower() != sha.lower()
    ):
        raise ReleaseGateError("release gate API returned a malformed check run")
    if status == "completed" and conclusion is None:
        raise ReleaseGateError("release gate API returned a completed check without a conclusion")
    if status != "completed" and conclusion is not None:
        raise ReleaseGateError("release gate API returned a pending check with a conclusion")
    return run


def _request_json(
    url: str,
    token: str,
    *,
    timeout: float,
    urlopen: Callable[..., Any],
) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "freebird-release-gate",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if not isinstance(status, int) or status != 200:
                raise ReleaseGateError(f"release gate API returned HTTP status {status}")
            return json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        raise ReleaseGateError(f"release gate API failure: {error}") from error


def fetch_check_runs(
    api: str,
    repository: str,
    token: str,
    sha: str,
    *,
    urlopen: Callable[..., Any] | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] | None = None,
) -> list[dict[str, Any]]:
    """Fetch and validate every check-run page for ``sha``."""

    urlopen = urlopen or urllib.request.urlopen
    clock = clock or time.monotonic
    encoded_repository = urllib.parse.quote(repository, safe="/")
    runs: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        if deadline is not None:
            remaining = deadline - clock()
            if remaining <= 0:
                raise PollDeadlineExceeded
            request_timeout = min(API_REQUEST_TIMEOUT_SECONDS, max(0.1, remaining))
        else:
            request_timeout = API_REQUEST_TIMEOUT_SECONDS
        url = (
            f"{api.rstrip('/')}/repos/{encoded_repository}/commits/{sha}/check-runs"
            f"?per_page=100&page={page}"
        )
        payload = _request_json(url, token, timeout=request_timeout, urlopen=urlopen)
        if not isinstance(payload, dict) or not isinstance(payload.get("check_runs"), list):
            raise ReleaseGateError("release gate API returned malformed check_runs")
        page_runs = [_validate_run(run, sha) for run in payload["check_runs"]]
        runs.extend(page_runs)
        if len(page_runs) < 100:
            return runs
        if page == MAX_PAGES:
            raise ReleaseGateError("release gate exceeded pagination safety limit")
    raise ReleaseGateError("release gate pagination failed")


def newest_runs(runs: Iterable[dict[str, Any]], required: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Select the newest check run by GitHub's monotonically increasing run ID."""

    required_set = set(required)
    selected: dict[str, dict[str, Any]] = {}
    for run in runs:
        name = run["name"]
        if name not in required_set:
            continue
        previous = selected.get(name)
        if previous is None or run["id"] > previous["id"]:
            selected[name] = run
        elif run["id"] == previous["id"] and run != previous:
            raise ReleaseGateError("release gate API returned conflicting duplicate check runs")
    return selected


def _state_text(run: dict[str, Any] | None) -> str:
    if run is None:
        return "missing"
    conclusion = run["conclusion"] or "-"
    return f"{run['status']}/{conclusion} (run {run['id']})"


def report_states(sha: str, required: Iterable[str], selected: dict[str, dict[str, Any]]) -> None:
    states = "; ".join(f"{name}={_state_text(selected.get(name))}" for name in required)
    print(f"release gate state for {sha}: {states}")


def run_gate(
    sha: str,
    required: tuple[str, ...],
    repository: str,
    token: str,
    api: str,
    *,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] | None = None,
    clock: Callable[[], float] | None = None,
) -> int:
    """Poll until all required checks pass or the gate fails closed."""

    sleeper = sleeper or time.sleep
    clock = clock or time.monotonic
    deadline = clock() + timeout
    while True:
        try:
            runs = fetch_check_runs(
                api,
                repository,
                token,
                sha,
                urlopen=urlopen,
                deadline=deadline,
                clock=clock,
            )
            selected = newest_runs(runs, required)
        except PollDeadlineExceeded:
            print(f"release gate timed out while fetching checks for {sha}", file=sys.stderr)
            return 1
        except ReleaseGateError as error:
            print(f"{error} (fail closed)", file=sys.stderr)
            return 1

        report_states(sha, required, selected)
        failed = [
            name
            for name in required
            if selected.get(name) is not None
            and selected[name]["status"] == "completed"
            and selected[name]["conclusion"] != "success"
        ]
        pending = [
            name
            for name in required
            if selected.get(name) is None or selected[name]["status"] != "completed"
        ]
        if failed:
            print(f"required checks failed for {sha}: {', '.join(failed)}", file=sys.stderr)
            return 1
        if not pending:
            print(f"release gate passed for {sha}: {', '.join(required)}")
            return 0

        remaining = deadline - clock()
        if remaining <= 0:
            print(f"release gate timed out waiting for checks for {sha}", file=sys.stderr)
            return 1
        sleeper(min(poll_interval, remaining))


def _bounded_seconds(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum} seconds")
    return value


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: release-gate.py COMMIT_SHA CHECK_NAME[,CHECK_NAME...]", file=sys.stderr)
        return 2
    sha, required_arg = sys.argv[1:]
    required = tuple(required_arg.split(","))
    if (
        not SHA_RE.fullmatch(sha)
        or set(required) != set(REQUIRED_CHECKS)
        or len(set(required)) != len(required)
    ):
        print("invalid release gate arguments", file=sys.stderr)
        return 2

    repository = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not repository or not token:
        print("GITHUB_REPOSITORY and GITHUB_TOKEN are required", file=sys.stderr)
        return 2
    try:
        poll_interval = _bounded_seconds(
            "RELEASE_GATE_POLL_INTERVAL_SECONDS",
            DEFAULT_POLL_INTERVAL_SECONDS,
            MIN_POLL_INTERVAL_SECONDS,
            MAX_POLL_INTERVAL_SECONDS,
        )
        timeout = _bounded_seconds(
            "RELEASE_GATE_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            MIN_TIMEOUT_SECONDS,
            MAX_TIMEOUT_SECONDS,
        )
    except ValueError as error:
        print(f"invalid release gate configuration: {error}", file=sys.stderr)
        return 2

    return run_gate(
        sha,
        required,
        repository,
        token,
        os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        poll_interval=poll_interval,
        timeout=timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
