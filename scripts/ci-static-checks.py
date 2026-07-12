#!/usr/bin/env python3
"""Dependency-free CI checks for documentation, profiles, and served UIs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
REQUIRED_PROFILES = ("atomic-v1", "ticket-v1", "enhanced-privacy-v1")
ADMIN_UI_PATHS = (
    ROOT / "admin-ui/index.html",
    ROOT / "issuer/src/admin_ui/index.html",
    ROOT / "verifier/src/admin_ui/index.html",
)
OPERATOR_CONSOLE_CLAIM = b"Experimental operator console \xc2\xb7 token-layer unlinkability only"


def check_markdown_links() -> list[str]:
    errors: list[str] = []
    for document in sorted((*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md"))):
        text = document.read_text(encoding="utf-8")
        for raw_target in LINK_RE.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("//") or target.startswith("#"):
                continue
            path = (document.parent / parsed.path).resolve()
            if not path.is_file() or ROOT not in path.parents and path != ROOT:
                errors.append(f"{document.relative_to(ROOT)}: broken link {target}")
    return errors


def check_profile_matrix() -> list[str]:
    matrix = ROOT / "docs/profile-claim-matrix.md"
    errors: list[str] = []
    if not matrix.is_file():
        return ["missing docs/profile-claim-matrix.md"]
    text = matrix.read_text(encoding="utf-8")
    for profile in REQUIRED_PROFILES:
        if f"`{profile}`" not in text:
            errors.append(f"profile matrix does not mention {profile}")
        row = next((line for line in text.splitlines() if f"`{profile}`" in line), "")
        if "PLANNED" not in row:
            errors.append(f"profile matrix row for {profile} must remain PLANNED")
    return errors


def check_admin_ui_sync() -> list[str]:
    """Ensure served admin UIs are exact copies of the canonical UI.

    Compare bytes rather than decoded text so newline/encoding changes made by
    the build copy step cannot silently make the embedded pages diverge.
    """
    errors: list[str] = []
    missing: list[Path] = []
    contents: list[bytes] = []
    for path in ADMIN_UI_PATHS:
        if not path.is_file():
            missing.append(path)
            continue
        contents.append(path.read_bytes())

    for path in missing:
        errors.append(f"missing admin UI: {path.relative_to(ROOT)}")
    if missing:
        return errors

    canonical = contents[0]
    for path, content in zip(ADMIN_UI_PATHS[1:], contents[1:]):
        if content != canonical:
            errors.append(
                f"admin UI is not synchronized with admin-ui/index.html: "
                f"{path.relative_to(ROOT)}"
            )

    for path, content in zip(ADMIN_UI_PATHS[1:], contents[1:]):
        if OPERATOR_CONSOLE_CLAIM not in content:
            errors.append(
                f"embedded admin UI lacks the experimental operator-console claim: "
                f"{path.relative_to(ROOT)}"
            )
    return errors


def check_reverse_proxy_examples() -> list[str]:
    """Keep the checked-in nginx examples aligned with the trust contract."""
    errors: list[str] = []
    expected_routes = {
        "freebird-issuer.conf": ("/healthz", "/readyz"),
        "freebird-verifier.conf": ("/health", "/ready"),
    }
    for name, backend in (("freebird-issuer.conf", "8081"), ("freebird-verifier.conf", "8082")):
        path = ROOT / "server-configs" / name
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        if not text:
            errors.append(f"missing reverse-proxy example: server-configs/{name}")
            continue
        if "$proxy_add_x_forwarded_for" in text or "$scheme" in text:
            errors.append(f"{name} appends or derives forwarded headers")
        if text.count("proxy_set_header X-Forwarded-Proto https;") < 2:
            errors.append(f"{name} does not set strict forwarded proto")
        if text.count("proxy_set_header X-Forwarded-For $remote_addr;") < 2:
            errors.append(f"{name} does not set a single client IP")
        if f'127.0.0.1:{backend}' not in text:
            errors.append(f"{name} backend is not loopback-private")
        if "location /admin" not in text or "return 404;" not in text:
            errors.append(f"{name} does not block public admin routes")
        for route in expected_routes[name]:
            route_block = re.search(
                rf"location = {re.escape(route)}\s*\{{(?P<body>.*?)\n\s*\}}",
                text,
                re.DOTALL,
            )
            if not route_block or "proxy_pass $backend;" not in route_block.group("body"):
                errors.append(f"{name} does not proxy exact health route {route}")
    return errors


def check_compose_host_ports() -> list[str]:
    """Ensure host publication and container listeners are not overloaded."""
    path = ROOT / "docker-compose.yaml"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    errors: list[str] = []
    required = (
        '${ISSUER_HOST_BIND_ADDR:-127.0.0.1:8081}:8081',
        '${VERIFIER_HOST_BIND_ADDR:-127.0.0.1:8082}:8082',
        'BIND_ADDR=${ISSUER_BIND_ADDR:-0.0.0.0:8081}',
        'BIND_ADDR=${VERIFIER_BIND_ADDR:-0.0.0.0:8082}',
    )
    for value in required:
        if value not in text:
            errors.append(f"docker-compose.yaml missing separated port/bind contract: {value}")
    env = ROOT / ".env.example"
    env_text = env.read_text(encoding="utf-8") if env.is_file() else ""
    for value in ("ISSUER_HOST_BIND_ADDR=127.0.0.1:8081", "VERIFIER_HOST_BIND_ADDR=127.0.0.1:8082"):
        if value not in env_text:
            errors.append(f".env.example missing {value}")
    return errors


def check_kind_smoke_platform_selection() -> list[str]:
    path = ROOT / "scripts/release-kind-smoke.sh"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    errors: list[str] = []
    for value in ("KIND_VERSION=\"v0.23.0\"", "Linux) KIND_OS=linux", "Darwin) KIND_OS=darwin", "KIND_ARTIFACT=\"kind-${KIND_OS}-${KIND_ARCH}\""):
        if value not in text:
            errors.append(f"release-kind-smoke.sh missing platform selection contract: {value}")
    if "kind-linux-amd64\"" in text:
        errors.append("release-kind-smoke.sh still hard-codes kind-linux-amd64")
    if "unsupported kind host OS" not in text or "unsupported kind host architecture" not in text:
        errors.append("release-kind-smoke.sh lacks fail-closed unsupported-platform errors")
    return errors


def check_kind_smoke_ingress_prepull() -> list[str]:
    path = ROOT / "scripts/release-kind-smoke.sh"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    errors: list[str] = []
    for value in (
        'INGRESS_READY_TIMEOUT="${INGRESS_READY_TIMEOUT:-600s}"',
        'INGRESS_CONTROLLER_IMAGE=',
        'INGRESS_CERTGEN_IMAGE=',
        'docker pull "$INGRESS_CONTROLLER_IMAGE"',
        'docker pull "$INGRESS_CERTGEN_IMAGE"',
        'kind load docker-image "$INGRESS_CONTROLLER_IMAGE" "$INGRESS_CERTGEN_IMAGE"',
        '--timeout="$INGRESS_READY_TIMEOUT"',
    ):
        if value not in text:
            errors.append(f"release-kind-smoke.sh missing ingress pre-pull contract: {value}")
    return errors


def main() -> int:
    errors = [
        *check_markdown_links(),
        *check_profile_matrix(),
        *check_admin_ui_sync(),
        *check_reverse_proxy_examples(),
        *check_compose_host_ports(),
        *check_kind_smoke_platform_selection(),
        *check_kind_smoke_ingress_prepull(),
    ]
    if errors:
        print("CI static checks failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Documentation links, profile matrix, and admin UI checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
