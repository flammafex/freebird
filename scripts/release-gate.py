#!/usr/bin/env python3
"""Fail closed unless the required checks passed for one exact commit."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: release-gate.py COMMIT_SHA CHECK_NAME[,CHECK_NAME...]", file=sys.stderr)
        return 2
    sha, required_arg = sys.argv[1:]
    required = [item for item in required_arg.split(",") if item]
    if not required or len(sha) != 40:
        print("invalid release gate arguments", file=sys.stderr)
        return 2
    repository = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not repository or not token:
        print("GITHUB_REPOSITORY and GITHUB_TOKEN are required", file=sys.stderr)
        return 2
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    found = {}
    for page in range(1, 101):
        url = f"{api}/repos/{repository}/commits/{sha}/check-runs?per_page=100&page={page}"
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            print(f"release gate API failure (fail closed): {error}", file=sys.stderr)
            return 1
        runs = payload.get("check_runs")
        if not isinstance(runs, list):
            print("release gate API returned no check_runs (fail closed)", file=sys.stderr)
            return 1
        for run in runs:
            name = run.get("name")
            if name in required:
                found[name] = (run.get("status"), run.get("conclusion"))
        if len(runs) < 100:
            break
        if page == 100:
            print("release gate exceeded pagination safety limit (fail closed)", file=sys.stderr)
            return 1
    failed = [name for name in required if found.get(name) != ("completed", "success")]
    if failed:
        print(f"required checks missing or unsuccessful for {sha}: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"release gate passed for {sha}: {', '.join(required)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
