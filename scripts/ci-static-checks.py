#!/usr/bin/env python3
"""Dependency-free CI checks for documentation, profiles, and served UIs."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
ACTION_REF_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)(?:\s+#\s*(.*))?\s*$")
FULL_ACTION_SHA_RE = re.compile(r"@[0-9a-f]{40}\Z")
REQUIRED_PROFILES = ("atomic-v1", "ticket-v1", "enhanced-privacy-v1")
ADMIN_UI_PATHS = (
    ROOT / "admin-ui/index.html",
    ROOT / "issuer/src/admin_ui/index.html",
    ROOT / "verifier/src/admin_ui/index.html",
)
OPERATOR_CONSOLE_CLAIM = b"Experimental operator console \xc2\xb7 token-layer unlinkability only"
DOCKER_WORKFLOW = ROOT / ".github/workflows/docker.yml"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
RELEASE_GATE_SCRIPT = ROOT / "scripts/release-gate.py"


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


def _workflow_job(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        text,
    )
    return match.group("body") if match else ""


def check_docker_action_pins_and_order() -> list[str]:
    """Keep Docker publishing actions immutable and credentials last in setup."""
    text = DOCKER_WORKFLOW.read_text(encoding="utf-8") if DOCKER_WORKFLOW.is_file() else ""
    errors: list[str] = []
    actions: list[tuple[int, str, str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ACTION_REF_RE.match(line)
        if not match:
            continue
        reference, comment = match.groups()
        action = reference.rsplit("@", 1)[0] if "@" in reference else reference
        comment = comment or ""
        actions.append((line_number, action, reference, comment))
        if not FULL_ACTION_SHA_RE.search(reference):
            errors.append(f"docker workflow action is not pinned to a full SHA: line {line_number}")
        if not re.search(r"\bv\d", comment):
            errors.append(f"docker workflow action lacks a release comment: line {line_number}")

    expected = {
        "actions/checkout": ("11d5960a326750d5838078e36cf38b85af677262", "v4.2.2"),
        "docker/login-action": ("c94ce9fb468520275223c153574b00df6fe4bcc9", "v3"),
        "docker/setup-qemu-action": ("c7c53464625b32c7a7e944ae62b3e17d2b600130", "v3.7.0"),
        "docker/setup-buildx-action": ("8d2750c68a42422c14e847fe6c8ac0403b4cbd6f", "v3.12.0"),
    }
    for action, (digest, release) in expected.items():
        matching = [item for item in actions if item[1] == action]
        if not matching:
            errors.append(f"docker workflow is missing pinned action {action}")
            continue
        for line_number, _action, reference, comment in matching:
            if reference.rsplit("@", 1)[-1] != digest:
                errors.append(f"docker workflow has an unexpected {action} pin on line {line_number}")
            if release not in comment:
                errors.append(f"docker workflow has an unexpected {action} release comment on line {line_number}")

    positions = {
        "qemu": text.find("docker/setup-qemu-action@"),
        "buildx": text.find("docker/setup-buildx-action@"),
        "validate": text.find("docker buildx inspect --bootstrap"),
        "login": text.find("docker/login-action@"),
        "push": text.find("docker buildx build --platform"),
    }
    if any(position < 0 for position in positions.values()):
        errors.append("docker workflow is missing a required QEMU/Buildx/validation/login/push step")
    elif list(positions.values()) != sorted(positions.values()):
        errors.append("docker workflow must order QEMU, Buildx, validation, login, then build/push")
    if "docker login \"$REGISTRY\"" in text:
        errors.append("docker workflow must use the pinned login action, not a shell login")
    buildx = _workflow_job(text, "build")
    if "driver: docker-container" not in buildx or "use: true" not in buildx:
        errors.append("docker workflow must use the active docker-container Buildx builder")
    if "driver=\"$(docker buildx inspect --format '{{.Driver}}')\"" not in buildx:
        errors.append("docker workflow must assert the active Buildx driver")
    return errors


def check_docker_tag_gate() -> list[str]:
    """Require tag publishing to pass the exact-SHA gate while keeping branches runnable."""
    text = DOCKER_WORKFLOW.read_text(encoding="utf-8") if DOCKER_WORKFLOW.is_file() else ""
    errors: list[str] = []
    gate = _workflow_job(text, "gate")
    build = _workflow_job(text, "build")
    if not gate or not build:
        return ["docker workflow must define gate and build jobs"]

    for marker in (
        "if: startsWith(github.ref, 'refs/tags/v')",
        "contents: read",
        "checks: read",
        'git fetch --force --no-tags origin',
        '"refs/heads/main:refs/remotes/origin/main"',
        '"refs/tags/${TAG}:refs/tags/${TAG}"',
        'git rev-parse "refs/tags/${TAG}^{commit}"',
        '[[ "$sha" == "${GITHUB_SHA}" ]]',
        'git merge-base --is-ancestor "$sha" refs/remotes/origin/main',
        "python3 scripts/release-gate.py",
    ):
        if marker not in gate:
            errors.append(f"docker tag gate is missing: {marker}")
    if "packages: write" in gate or "id-token: write" in gate:
        errors.append("docker tag gate must not have registry or signing permissions")
    if "timeout-minutes: 65" not in gate:
        errors.append("docker tag gate timeout must cover the bounded release gate")
    if "needs: gate" not in build:
        errors.append("docker publisher must need the tag gate")
    if "always()" not in build or "needs.gate.result == 'success'" not in build or "needs.gate.result == 'skipped'" not in build:
        errors.append("docker publisher must run on gate success or a skipped non-tag gate")
    if "packages: write" not in build:
        errors.append("docker publisher must have packages: write")
    if "docker buildx build" not in build or "--push" not in build:
        errors.append("docker publisher must build and push images")
    if text.find("\n  gate:") > text.find("\n  build:"):
        errors.append("docker tag gate must be declared before the publisher")
    return errors


def check_release_gate_timeout_alignment() -> list[str]:
    """Keep workflow wall-clock limits above the script's 60-minute maximum."""
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8") if RELEASE_WORKFLOW.is_file() else ""
    script = RELEASE_GATE_SCRIPT.read_text(encoding="utf-8") if RELEASE_GATE_SCRIPT.is_file() else ""
    errors: list[str] = []
    gate = _workflow_job(workflow, "gate")
    timeout = re.search(r"(?m)^\s*timeout-minutes:\s*(\d+)\s*$", gate)
    if not timeout or int(timeout.group(1)) < 65:
        errors.append("release gate timeout must be at least 65 minutes")
    if not re.search(r"MAX_TIMEOUT_SECONDS\s*=\s*60\s*\*\s*60", script):
        errors.append("release gate script maximum timeout must remain 60 minutes")
    return errors


def check_release_gate_test_execution() -> list[str]:
    """Ensure release-gate tests run without leaving bytecode in the checkout."""
    text = CI_WORKFLOW.read_text(encoding="utf-8") if CI_WORKFLOW.is_file() else ""
    errors: list[str] = []
    for marker in (
        "scripts/test-release-gate.py",
        "PYTHONDONTWRITEBYTECODE=1",
        "TMPDIR=",
        'tmp="$(mktemp -d)"',
        "trap 'rm -rf \"$tmp\"' EXIT",
    ):
        if marker not in text:
            errors.append(f"CI must run release-gate tests with temporary bytecode-safe handling: {marker}")
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
        'INGRESS_MANIFEST_URL="https://raw.githubusercontent.com/kubernetes/ingress-nginx/${INGRESS_COMMIT}',
        'KIND_NODES="$(kind get nodes --name "$CLUSTER")"',
        'while IFS= read -r node; do',
        'docker exec "$node" crictl pull "$INGRESS_CONTROLLER_IMAGE"',
        'docker exec "$node" crictl inspecti "$INGRESS_CONTROLLER_IMAGE"',
        'docker exec "$node" crictl pull "$INGRESS_CERTGEN_IMAGE"',
        'docker exec "$node" crictl inspecti "$INGRESS_CERTGEN_IMAGE"',
        'INGRESS_APPLY_MANIFEST="$TMP/ingress-nginx-apply.yaml"',
        'python3 - "$INGRESS_MANIFEST" "$INGRESS_APPLY_MANIFEST"',
        'input_policy_count != 3',
        'output_policy_count != 3',
        'imagePullPolicy: IfNotPresent',
        'imagePullPolicy: Never',
        'imagePullPolicy: Always',
        'source_image_lines',
        'output_image_lines != source_image_lines',
        'output_path.write_bytes(transformed)',
        '@sha256:',
        'kubectl apply -f "$INGRESS_APPLY_MANIFEST"',
        'kubectl apply --dry-run=server -k k8s/overlays/kind >/dev/null',
        'kubectl apply -k k8s/overlays/kind',
        '--timeout="$INGRESS_READY_TIMEOUT"',
    ):
        if value not in text:
            errors.append(f"release-kind-smoke.sh missing ingress CRI preload contract: {value}")

    if re.search(r"docker\s+pull[^\n]*(?:INGRESS_CONTROLLER_IMAGE|INGRESS_CERTGEN_IMAGE)", text):
        errors.append("release-kind-smoke.sh must not host-pull ingress images")
    if re.search(r"kind\s+load\s+docker-image[^\n]*(?:INGRESS_CONTROLLER_IMAGE|INGRESS_CERTGEN_IMAGE)", text):
        errors.append("release-kind-smoke.sh must not host-load ingress images")
    if 'kubectl apply -f "$INGRESS_MANIFEST"' in text:
        errors.append("release-kind-smoke.sh must apply only the transformed ingress manifest")
    if 'kind load docker-image "$KIND_ISSUER_IMAGE" "$KIND_VERIFIER_IMAGE" --name "$CLUSTER"' not in text:
        errors.append("release-kind-smoke.sh must retain the local Freebird image load path")

    dry_run = 'kubectl apply --dry-run=server -k k8s/overlays/kind >/dev/null'
    real_apply = 'kubectl apply -k k8s/overlays/kind'
    if dry_run in text and real_apply in text and text.index(dry_run) >= text.index(real_apply):
        errors.append("release-kind-smoke.sh must server-dry-run the Kind overlay before applying it")

    transform = re.search(
        r"(?ms)^python3 - \"\$INGRESS_MANIFEST\" .*?<<'PY'\n(?P<body>.*?)^PY$",
        text,
    )
    if not transform:
        errors.append("release-kind-smoke.sh ingress policy transform heredoc is missing")
    else:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.yaml"
            output = Path(temporary) / "output.yaml"
            controller = b"registry.k8s.io/ingress-nginx/controller@sha256:controller"
            certgen = b"registry.k8s.io/ingress-nginx/kube-webhook-certgen@sha256:certgen"
            source.write_bytes(
                b"image: " + controller + b"\n"
                b"imagePullPolicy: IfNotPresent\n"
                b"image: " + certgen + b"\n"
                b"imagePullPolicy: IfNotPresent\n"
                b"imagePullPolicy: IfNotPresent\n"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    transform.group("body"),
                    str(source),
                    str(output),
                    controller.decode("utf-8"),
                    certgen.decode("utf-8"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                errors.append(
                    "release-kind-smoke.sh ingress policy transform fixture failed: "
                    f"{result.stderr.strip()}"
                )
            elif not output.is_file():
                errors.append("release-kind-smoke.sh ingress policy transform produced no output")
            else:
                transformed = output.read_bytes()
                if transformed.count(b"imagePullPolicy: Never") != 3:
                    errors.append("release-kind-smoke.sh transform did not produce exactly 3 Never policies")
                if b"imagePullPolicy: IfNotPresent" in transformed or b"imagePullPolicy: Always" in transformed:
                    errors.append("release-kind-smoke.sh transform retained a forbidden pull policy")
                for image in (controller, certgen):
                    image_line = b"image: " + image
                    if transformed.count(image_line) != 1:
                        errors.append("release-kind-smoke.sh transform changed a digest-pinned ingress image line")
    return errors


def check_kind_smoke_forwarding_tls() -> list[str]:
    errors: list[str] = []
    smoke_path = ROOT / "scripts/release-kind-smoke.sh"
    smoke = smoke_path.read_text(encoding="utf-8") if smoke_path.is_file() else ""
    kind_kustomization = (ROOT / "k8s/overlays/kind/kustomization.yaml").read_text(encoding="utf-8")
    production_kustomization = (ROOT / "k8s/overlays/production/kustomization.yaml").read_text(encoding="utf-8")
    kind_ingress = (ROOT / "k8s/overlays/kind/ingress.patch.yaml").read_text(encoding="utf-8")
    kind_probes = (ROOT / "k8s/overlays/kind/probes.patch.yaml").read_text(encoding="utf-8")
    kind_proxy_policy = (ROOT / "k8s/overlays/kind/proxy-policy.patch.yaml").read_text(encoding="utf-8")
    kind_health_egress = (ROOT / "k8s/overlays/kind/health-egress.patch.yaml").read_text(encoding="utf-8")

    for path in (
        ROOT / "k8s/overlays/kind/proxy-headers.yaml",
        ROOT / "k8s/overlays/production/proxy-headers.yaml",
    ):
        if path.exists():
            errors.append(f"custom forwarded-header ConfigMap must be deleted: {path.relative_to(ROOT)}")
    if "proxy-headers.yaml" in kind_kustomization or "proxy-headers.yaml" in production_kustomization:
        errors.append("overlay kustomizations must not wire custom forwarded-header ConfigMaps")
    for text, label in (
        (kind_kustomization, "kind kustomization"),
        (production_kustomization, "production kustomization"),
        (kind_ingress, "kind ingress patch"),
    ):
        if "freebird-proxy-headers" in text or "X-Forwarded-Proto:" in text or "X-Forwarded-For:" in text:
            errors.append(f"{label} contains a custom standard forwarded-header configuration")

    for value in (
        'proxy-set-headers":"","use-forwarded-headers":"false","compute-full-forwarded-for":"false"',
        'PROXY_SET_HEADERS="$(kubectl -n ingress-nginx get configmap ingress-nginx-controller',
        'USE_FORWARDED_HEADERS="$(kubectl -n ingress-nginx get configmap ingress-nginx-controller',
        'COMPUTE_FULL_FORWARDED_FOR="$(kubectl -n ingress-nginx get configmap ingress-nginx-controller',
        '"$USE_FORWARDED_HEADERS" == "false"',
        '"$COMPUTE_FULL_FORWARDED_FOR" == "false"',
        'subjectAltName=DNS:issuer.freebird.test,DNS:verifier.freebird.test',
        'https://issuer.freebird.test/readyz',
        'https://verifier.freebird.test/ready',
        "wrong CA was unexpectedly accepted for issuer",
        "wrong CA was unexpectedly accepted for verifier",
        "X-Forwarded-For: 198.51.100.1",
        "X-Forwarded-For: 203.0.113.2",
        "X-Forwarded-Proto: http",
        'nginx -T',
        "proxy_set_header",
        'ISSUER_PRIMARY_ENDPOINTS=',
        'VERIFIER_PRIMARY_ENDPOINTS=',
    ):
        if value not in smoke:
            errors.append(f"release-kind-smoke.sh missing built-in forwarding/TLS proof: {value}")
    if "freebird-proxy-headers" in smoke or "proxy-headers.yaml" in smoke:
        errors.append("release-kind-smoke.sh references the removed custom header ConfigMap")
    if re.search(r"curl[^\n]*(?:--insecure|-k\b)", smoke) or "http://verifier.freebird.test" in smoke:
        errors.append("release-kind-smoke.sh contains an insecure or HTTP verifier request")

    verifier_ingress = next(
        (block for block in kind_ingress.split("---") if "name: verifier-ingress" in block),
        "",
    )
    if 'nginx.ingress.kubernetes.io/ssl-redirect: "true"' not in verifier_ingress:
        errors.append("kind verifier ingress must enable SSL redirect")
    if "secretName: issuer-tls-cert" not in verifier_ingress or "verifier.freebird.test" not in verifier_ingress:
        errors.append("kind verifier ingress must use the temporary issuer TLS Secret and hostname")
    if "verifier.freebird.test:443:ingress-nginx-controller.ingress-nginx.svc.cluster.local:443" not in kind_probes:
        errors.append("kind verifier readiness must use the HTTPS ingress controller port")
    if "http://verifier.freebird.test" in kind_probes or "verifier.freebird.test:80" in kind_probes:
        errors.append("kind verifier readiness contains an HTTP port 80 URL")
    for text, label in ((kind_proxy_policy, "kind probe policy"), (kind_health_egress, "kind health policy")):
        if "port: 80" in text or "port:80" in text:
            errors.append(f"{label} must not allow ingress port 80")
        if "443" not in text:
            errors.append(f"{label} must retain HTTPS port 443")
    return errors


def check_kind_smoke_nginx_parser() -> list[str]:
    """Execute the smoke script's exact-location forwarding parser fixtures."""
    path = ROOT / "scripts/release-kind-smoke.sh"
    smoke = path.read_text(encoding="utf-8") if path.is_file() else ""
    parser = re.search(
        r'(?ms)^python3 - "\$TMP/nginx-config\.txt" <<\'PY\'\n(?P<body>.*?)^PY$',
        smoke,
    )
    if not parser:
        return ["release-kind-smoke.sh nginx forwarding parser heredoc is missing"]

    routes = ("/healthz", "/readyz", "/health", "/ready")

    def fixture(
        *,
        xff: dict[str, list[str]] | None = None,
        xfp: dict[str, list[str]] | None = None,
    ) -> str:
        xff = xff or {}
        xfp = xfp or {}
        lines = [
            "server {",
            "    # This internal controller location must not satisfy the smoke assertion.",
            "    location /healthz { return 200; }",
        ]
        for route in routes:
            lines.extend(
                [
                    f'    location = "{route}" {{',
                    *[
                        f"        proxy_set_header X-Forwarded-For {value};"
                        for value in xff.get(route, ["$remote_addr"])
                    ],
                    *[
                        f"        proxy_set_header X-Forwarded-Proto {value};"
                        for value in xfp.get(route, ["$pass_access_scheme"])
                    ],
                    "    }",
                ]
            )
        lines.append("}")
        return "\n".join(lines) + "\n"

    valid = fixture()
    negative = {
        "missing directive": fixture(xfp={"/ready": []}),
        "duplicate directive": fixture(xff={"/health": ["$remote_addr", "$remote_addr"]}),
        "incoming XFF": fixture(xff={"/healthz": ["$http_x_forwarded_for"]}),
        "appended XFF": fixture(xff={"/readyz": ["$proxy_add_x_forwarded_for"]}),
        "incoming XFP": fixture(xfp={"/ready": ["$http_x_forwarded_proto"]}),
    }
    errors: list[str] = []
    with tempfile.TemporaryDirectory() as temporary:
        config = Path(temporary) / "nginx-config.txt"

        def run_parser(contents: str) -> subprocess.CompletedProcess[str]:
            config.write_text(contents, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-c", parser.group("body"), str(config)],
                capture_output=True,
                text=True,
                check=False,
            )

        result = run_parser(valid)
        if result.returncode != 0:
            errors.append(
                "release-kind-smoke.sh nginx parser valid fixture failed: "
                f"{result.stderr.strip()}"
            )
        for label, contents in negative.items():
            result = run_parser(contents)
            if result.returncode == 0:
                errors.append(f"release-kind-smoke.sh nginx parser negative fixture passed: {label}")
    return errors


def check_kind_smoke_cleanup_safety() -> list[str]:
    """Require cleanup ownership, bounded diagnostics, and bounded deletion."""
    path = ROOT / "scripts/release-kind-smoke.sh"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    errors: list[str] = []
    cleanup = re.search(r"(?ms)^cleanup\(\) \{\n(?P<body>.*?)^\}\n", text)
    if not cleanup:
        return ["release-kind-smoke.sh cleanup function is missing"]

    body = cleanup.group("body")
    required = (
        "CLUSTER_OWNED=false",
        'if [[ "$CLUSTER_OWNED" == true ]]; then',
        'kind create cluster --name "$CLUSTER" --wait 90s',
        "CLUSTER_OWNED=true",
        'kubectl --context "kind-$CLUSTER" --request-timeout=15s',
        'python3 - "$CLUSTER" <<\'PY\' || true',
        '["kind", "delete", "cluster", "--name", cluster]',
        "start_new_session=True",
        "process.wait(timeout=30)",
        "signal.SIGTERM",
        "signal.SIGKILL",
    )
    for marker in required:
        if marker not in text:
            errors.append(f"release-kind-smoke.sh missing cleanup ownership contract: {marker}")

    create_position = text.find('kind create cluster --name "$CLUSTER" --wait 90s')
    owned_position = text.find("CLUSTER_OWNED=true", create_position)
    if create_position < 0 or owned_position < 0 or owned_position <= create_position:
        errors.append("release-kind-smoke.sh must claim cluster ownership only after kind create succeeds")
    if "kind get clusters" in text:
        errors.append("release-kind-smoke.sh must not scan Kind clusters")

    kubectl_lines = [line.strip() for line in body.splitlines() if "kubectl" in line]
    for line in kubectl_lines:
        prefix = 'kubectl --context "kind-$CLUSTER" --request-timeout=15s '
        if not line.startswith(prefix):
            errors.append(f"cleanup kubectl diagnostic lacks explicit context/timeout: {line}")
        if re.search(r"\b(delete|apply|patch|scale|rollout)\b", line):
            errors.append(f"cleanup contains an implicit kubectl mutation: {line}")
    if "kubectl delete secret" in body:
        errors.append("cleanup must not separately delete secrets from the disposable cluster")
    if re.search(r"(?m)^\s*kind\s+delete\s+cluster", body):
        errors.append("cleanup must not use an unbounded shell kind delete")
    if re.search(r"(?m)^\s*timeout\s+", body):
        errors.append("cleanup must not depend on GNU timeout")

    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        mock_bin = temporary_path / "bin"
        mock_bin.mkdir()
        call_log = temporary_path / "calls.log"
        (mock_bin / "curl").write_text(
            """#!/bin/sh
set -eu
output=
previous=
for argument in "$@"; do
  if [ "$previous" = -o ]; then
    output=$argument
    break
  fi
  previous=$argument
done
[ -n "$output" ]
cat >"$output" <<'KIND'
#!/bin/sh
printf 'kind %s\\n' "$*" >>"$MOCK_LOG"
if [ "${1:-}" = create ] && [ "${2:-}" = cluster ]; then
  exit 41
fi
exit 0
KIND
chmod 755 "$output"
""",
            encoding="utf-8",
        )
        (mock_bin / "kubectl").write_text(
            "#!/bin/sh\nprintf 'kubectl %s\\n' \"$*\" >>\"$MOCK_LOG\"\nexit 99\n",
            encoding="utf-8",
        )
        for executable in (mock_bin / "curl", mock_bin / "kubectl"):
            executable.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "ISSUER_IMAGE": "freebird-issuer:precreate-proof",
                "VERIFIER_IMAGE": "freebird-verifier:precreate-proof",
                "GITHUB_RUN_ID": "precreate-safety-proof",
                "GITHUB_RUN_ATTEMPT": "1",
                "MOCK_LOG": str(call_log),
                "PATH": f"{mock_bin}:{environment['PATH']}",
            }
        )
        result = subprocess.run(
            ["bash", str(path)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        calls = call_log.read_text(encoding="utf-8") if call_log.is_file() else ""
        if result.returncode == 0:
            errors.append("pre-create cleanup proof unexpectedly succeeded")
        if "kind create cluster" not in calls:
            errors.append("pre-create cleanup proof did not inject a failed kind create")
        if "kind delete cluster" in calls:
            errors.append("pre-create cleanup proof attempted to delete an unowned cluster")
        if "kubectl " in calls:
            errors.append("pre-create cleanup proof invoked kubectl before cluster ownership")
    return errors


def check_kind_smoke_bootstrap_order() -> list[str]:
    path = ROOT / "scripts/release-kind-smoke.sh"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    base_verifier = (ROOT / "k8s/base/verifier-deployment.yaml").read_text(encoding="utf-8")
    errors: list[str] = []
    if not re.search(r"(?m)^\s+replicas:\s*3\s+# Verifiers are stateless and can scale$", base_verifier):
        errors.append("base verifier replica count must remain exactly three")
    if "kubectl rollout restart deployment/issuer deployment/verifier" in text:
        errors.append("release-kind-smoke.sh must not combine issuer and verifier restarts")

    markers = (
        'kubectl apply -k k8s/overlays/kind',
        'kubectl -n freebird scale deployment/verifier --replicas=0',
        'kubectl -n freebird wait --for=delete pod -l app=freebird,component=verifier',
        'kubectl wait --for=condition=available deployment/issuer -n freebird --timeout=180s',
        'kubectl rollout restart deployment/issuer -n freebird',
        'kubectl rollout status deployment/issuer -n freebird --timeout=180s',
        'ISSUER_PRIMARY_ENDPOINTS=',
        'name: issuer-metadata',
        'https://issuer.freebird.test/.well-known/issuer',
        'kubectl delete pod issuer-metadata -n freebird --wait=true',
        'kubectl -n freebird scale deployment/verifier --replicas=3',
        'VERIFIER_CONVERGENCE_TIMEOUT=',
        'VERIFIER_CONVERGENCE_DEADLINE=',
        'verifier-pods.json',
        'verifier-rs.json',
        'verifier-endpoints.json',
        'deletionTimestamp',
        'pod-template-hash',
        'ready_pods',
        'endpoint_count',
        'len(ready_pods) == 3',
        'endpoint_count == 3',
        'did not converge before timeout',
        'VERIFIER_PRIMARY_ENDPOINTS=',
        'VERIFIER_PODS="$VERIFIER_CONVERGENCE_LAST"',
        'VERIFIER_METADATA_DEADLINE=',
        'VERIFIER_METADATA_MISSING=',
        'updated issuer metadata evidence before timeout',
        'kubectl logs "$verifier_pod" -n freebird --all-containers=true',
        'updated issuer metadata',
    )
    for marker in markers:
        if marker not in text:
            errors.append(f"release-kind-smoke.sh missing bootstrap-order contract: {marker}")
    if "VERIFIER_POD_COUNT=" in text or "expected exactly three current verifier pods, found" in text:
        errors.append("release-kind-smoke.sh must not use the racy immediate verifier pod snapshot gate")
    if "sleep 2" not in text or "VERIFIER_CONVERGENCE_DEADLINE" not in text:
        errors.append("release-kind-smoke.sh verifier convergence must be bounded and polling-based")
    if "VERIFIER_METADATA_DEADLINE" not in text or "VERIFIER_METADATA_MISSING" not in text:
        errors.append("release-kind-smoke.sh issuer metadata evidence must be bounded and polling-based")
    for pod_name in ("issuer-metadata", "health"):
        pod_start = text.find(f"  name: {pod_name}")
        pod_end = text.find("YAML\n", pod_start)
        pod_manifest = text[pod_start:pod_end] if pod_start >= 0 and pod_end >= 0 else ""
        for value in ("runAsNonRoot: true", "runAsUser: 1000", "runAsGroup: 1000"):
            if value not in pod_manifest:
                errors.append(f"{pod_name} pod must retain numeric non-root security setting: {value}")

    ordered = [
        'kubectl apply -k k8s/overlays/kind',
        'kubectl -n freebird scale deployment/verifier --replicas=0',
        'kubectl rollout restart deployment/issuer -n freebird',
        'ISSUER_PRIMARY_ENDPOINTS=',
        'name: issuer-metadata',
        'kubectl delete pod issuer-metadata -n freebird --wait=true',
        'kubectl -n freebird scale deployment/verifier --replicas=3',
        'VERIFIER_PRIMARY_ENDPOINTS=',
        'VERIFIER_PODS="$VERIFIER_CONVERGENCE_LAST"',
        'updated issuer metadata',
    ]
    positions = [text.find(marker) for marker in ordered]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append("release-kind-smoke.sh bootstrap stages are not in the required order")

    if 'kubectl --context "kind-$CLUSTER" --request-timeout=15s logs -n freebird -l app=freebird,component=issuer' not in text or \
       'kubectl --context "kind-$CLUSTER" --request-timeout=15s logs -n freebird -l app=freebird,component=verifier' not in text:
        errors.append("release-kind-smoke.sh cleanup must include selector-based issuer and verifier logs")
    return errors


def main() -> int:
    errors = [
        *check_markdown_links(),
        *check_profile_matrix(),
        *check_admin_ui_sync(),
        *check_reverse_proxy_examples(),
        *check_compose_host_ports(),
        *check_docker_action_pins_and_order(),
        *check_docker_tag_gate(),
        *check_release_gate_timeout_alignment(),
        *check_release_gate_test_execution(),
        *check_kind_smoke_platform_selection(),
        *check_kind_smoke_ingress_prepull(),
        *check_kind_smoke_forwarding_tls(),
        *check_kind_smoke_nginx_parser(),
        *check_kind_smoke_cleanup_safety(),
        *check_kind_smoke_bootstrap_order(),
    ]
    if errors:
        print("CI static checks failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Documentation links, profile matrix, and admin UI checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
