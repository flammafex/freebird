#!/usr/bin/env python3
"""Check local Markdown paths, recorded fixture hashes, and required configuration text.

Link checks cover path existence only. Hash checks compare fixtures against the
recorded digests and do not verify provenance. Run the Rust integration tests
to check behavior and use independent review to assess security.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
HOLD = "Privacy Pass release blocked: key rotation and independent RSA review incomplete"


def tracked_files() -> list[str]:
    return subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT
    ).decode().rstrip("\0").split("\0")


def check_links(files: list[str]) -> list[str]:
    errors = []
    for name in files:
        document = ROOT / name
        # Check files on disk because `git ls-files` includes unstaged deletions.
        if document.suffix.lower() != ".md" or not document.is_file():
            continue
        text = document.read_text(encoding="utf-8")
        targets = re.findall(r"!?\[[^]]*\]\(([^)\n]+)\)", text)
        targets += re.findall(r"(?m)^\s*\[[^]]+\]:\s*(\S+)", text)
        for raw in targets:
            target = raw.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith(("//", "#")):
                continue
            path = (document.parent / unquote(parsed.path)).resolve()
            if not path.is_relative_to(ROOT) or not path.exists():
                errors.append(f"{name}: broken local link {target}")
    return errors


def check_fixtures() -> list[str]:
    base = ROOT / "common/test-fixtures/privacy-pass"
    provenance = (base / "README.md").read_text(encoding="utf-8")
    errors = []
    for name in ("rfc9577-a1.json", "rfc9578-a2.json"):
        path = base / name
        row = next((line for line in provenance.splitlines() if f"`{name}`" in line), "")
        hashes = re.findall(r"`([0-9a-f]{64})`", row)
        if len(hashes) != 2 or "https://www.rfc-editor.org/rfc/" not in row:
            errors.append(f"{name}: missing source URL/RFC and fixture hashes")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != hashes[1]:
            errors.append(f"{name}: fixture hash differs from provenance")
        json.loads(path.read_text(encoding="utf-8"))
    return errors


def check_tree(files: list[str]) -> list[str]:
    errors = []
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
    if set(workspace["members"]) != {"crypto", "common", "privacy_pass_service"}:
        errors.append("workspace must contain only crypto, common, privacy_pass_service")
    removed = ("attester/", "issuer/", "verifier/", "interface/", "integration_tests/", "sdk/js/")
    for name in files:
        # Ignore paths that are missing on disk because `git ls-files` includes unstaged deletions.
        if name.startswith(removed) and (ROOT / name).is_file():
            errors.append(f"legacy tracked source remains: {name}")
    origin = (ROOT / "privacy_pass_service/src/origin.rs").read_text()
    production = origin.split("\n#[cfg(test)]\nmod tests", 1)[0]
    # Match known API names to flag possible changes in how the Origin handles keys.
    # Text matching cannot verify how the code uses those keys.
    for marker in ("PublicKey::from_spki(&k.spki)", "key: PublicKey"):
        if marker not in production:
            errors.append(f"Origin public-SPKI tripwire missing: {marker}")
    for marker in ("SecretKey", "RsaPrivateKey", "from_pkcs8", "BEGIN PRIVATE KEY"):
        if marker in production:
            errors.append(f"Origin production private-key tripwire: {marker}")
    for role in ("issuer", "origin"):
        unit = (ROOT / f"deploy/systemd/freebird-{role}.service").read_text()
        if "ConditionPathExists=/etc/freebird/serving-enabled" not in unit:
            errors.append(f"{role} unit must require the external serving permission")
    return errors


def check_workflows() -> list[str]:
    errors = []
    release = (ROOT / ".github/workflows/release.yml").read_text()
    # Compare the whole file so that any change to the blocking workflow fails this check.
    expected = """name: Privacy Pass release blocked

on:
  push:
    tags: ['*']
  workflow_dispatch:

permissions: {}

jobs:
  release-blocked:
    runs-on: ubuntu-latest
    steps:
      - name: Fail closed pending independent review and rotation
        run: |
          echo '""" + HOLD + """' >&2
          exit 1
"""
    if release != expected:
        errors.append("release workflow differs from fail-closed allowlist")
    directory = ROOT / ".github/workflows"
    if {p.name for p in directory.iterdir() if p.is_file()} != {"ci.yml", "release.yml"}:
        errors.append("only CI and held release workflows are allowed")
    ci = (directory / "ci.yml").read_text()
    for marker in ("packages:", "write", "publish", "upload-artifact", "gh release",
                   "docker build", "release-gate.py"):
        if marker in ci:
            errors.append(f"CI contains forbidden publishing/legacy marker: {marker}")
    # Require one locked dependency install in `interop/ts` and reject other `npm` commands.
    allowed_install = "npm ci --ignore-scripts"
    if ci.count(allowed_install) != 1 or "working-directory: interop/ts" not in ci:
        errors.append("CI must pin the single test-only interop npm install")
    if "npm " in ci.replace(allowed_install, ""):
        errors.append("CI contains an unapproved npm command")
    for marker in ("scripts/test-recovery.py", "scripts/test-recovery-catalog.py"):
        if marker not in ci:
            errors.append(f"CI must retain recovery evidence: {marker}")
    if "permissions:\n  contents: read\n" not in ci:
        errors.append("CI must retain read-only permissions")
    return errors


def main() -> int:
    try:
        files = tracked_files()
        errors = [
            *check_links(files), *check_fixtures(),
            *check_tree(files), *check_workflows(),
        ]
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        errors = [f"static check could not complete: {exc}"]
    if errors:
        print("CI static checks failed (cleanup link failures are not waived):", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Local links, fixture hashes, tree policy, and release hold checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
