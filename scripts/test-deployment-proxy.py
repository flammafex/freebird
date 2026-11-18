#!/usr/bin/env python3
"""Exercise real service binaries through the shipped TLS nginx boundary."""
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, text):
    with path.open("w") as stream:
        print(text, file=stream)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    nginx = os.environ.get("FREEBIRD_NGINX") or shutil.which("nginx")
    if not nginx and Path("/opt/homebrew/bin/nginx").is_file():
        nginx = "/opt/homebrew/bin/nginx"
    require(nginx and all(shutil.which(x) for x in ("openssl", "curl")),
            "nginx, openssl, and curl are required")
    root = Path(__file__).resolve().parents[1]
    binary = root / "target/debug/freebird-privacy-pass-service"
    client = root / "target/debug/examples/loopback_client"
    require(binary.is_file() and client.is_file(), "build service and loopback_client first")
    diagnostics = []
    secrets = []
    children = []

    def run(args, data=None):
        result = subprocess.run([str(x) for x in args], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        diagnostics.append(result.stderr)
        require(result.returncode == 0, "subprocess failed (diagnostics suppressed)")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="freebird-proxy-") as temporary:
        tmp = Path(temporary)
        try:
            http, tls, issuer_port, origin_port = [port() for _ in range(4)]
            require(len({http, tls, issuer_port, origin_port}) == 4, "port allocation collision")
            ca, cert, key = tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", tmp / "ca.key", "-out", ca, "-days", "1",
                 "-subj", "/CN=Freebird test CA"])
            run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                 "-out", tmp / "leaf.csr", "-subj", "/CN=issuer.test"])
            save(tmp / "extensions", "subjectAltName=DNS:issuer.test,DNS:origin.test\n"
                 "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth")
            run(["openssl", "x509", "-req", "-in", tmp / "leaf.csr", "-CA", ca,
                 "-CAkey", tmp / "ca.key", "-CAcreateserial", "-out", cert,
                 "-days", "1", "-extfile", tmp / "extensions"])
            # Deliberately literal substitutions: template drift must fail closed.
            config = (root / "deploy/nginx/freebird.conf").read_text()

            def replace(old, new, count):
                nonlocal config
                require(config.count(old) == count, "nginx template changed: substitution count")
                config = config.replace(old, new)

            for host in ("issuer", "origin"):
                replace(f"/etc/letsencrypt/live/{host}.example.org/fullchain.pem", str(cert), 1)
                replace(f"/etc/letsencrypt/live/{host}.example.org/privkey.pem", str(key), 1)
                replace(f"{host}\\.example\\.org", f"{host}\\.test", 2)
                replace(f"{host}.example.org", f"{host}.test", 6 if host == "issuer" else 4)
            replace("    listen [::]:80;\n", "", 2)
            replace("    listen [::]:443 ssl;\n", "", 2)
            replace("listen 80;", f"listen 127.0.0.1:{http};", 2)
            replace("listen 443 ssl;", f"listen 127.0.0.1:{tls} ssl;", 2)
            replace("(:80)?", f"(:{http})?", 2)
            replace("(:443)?", f"(:{tls})?", 2)
            replace("127.0.0.1:8081", f"127.0.0.1:{issuer_port}", 4)
            # Origin upstream: one live location plus two in the commented app-protection example.
            replace("127.0.0.1:8082", f"127.0.0.1:{origin_port}", 3)
            replace("/var/log/nginx/freebird-access.log", str(tmp / "access.log"), 1)
            replace("/var/log/nginx/freebird-error.log", str(tmp / "error.log"), 1)
            replace("/var/lib/letsencrypt", str(tmp / "acme"), 2)
            save(tmp / "nginx.conf", f"daemon off;\nmaster_process off;\n"
                 f"pid {tmp}/nginx.pid;\nerror_log {tmp}/error.log warn;\n"
                 f"events {{}}\nhttp {{\nclient_body_temp_path {tmp}/body;\n{config}\n}}")
            run([nginx, "-t", "-p", str(tmp) + "/", "-c", tmp / "nginx.conf"])
            print("deployment proxy nginx configuration: passed")
            issuer, origin = tmp / "issuer", tmp / "origin"
            run([binary, "init-issuer", issuer])
            status = run([binary, "issuer-key-status", issuer]).decode()
            match = re.search(r"^active ([0-9a-f]{64}) ", status, re.MULTILINE)
            require(match is not None, "genesis key status missing")
            key_id = match.group(1)
            run([binary, "export-issuer-spki", issuer, key_id, tmp / "spki.der"])
            run([binary, "init-origin", origin, tmp / "spki.der", key_id])
            invitation = run([binary, "provision", issuer]).strip()
            require(re.fullmatch(rb"[A-Za-z0-9_-]{43}", invitation), "invalid invitation output")
            secrets.append(invitation)
            legacy_invitation = run([binary, "provision", issuer]).strip()
            require(re.fullmatch(rb"[A-Za-z0-9_-]{43}", legacy_invitation),
                    "invalid legacy invitation output")
            secrets.append(legacy_invitation)

            def start(args, label):
                stream = (tmp / f"{label}.diagnostic").open("wb")
                try:
                    child = subprocess.Popen([str(x) for x in args], stdout=stream, stderr=stream)
                finally:
                    stream.close()
                children.append(child)

            start([binary, "serve-issuer", issuer, f"issuer.test:{tls}",
                   f"https://issuer.test:{tls}/private-token/issue",
                   f"127.0.0.1:{issuer_port}"], "issuer")
            start([binary, "serve-origin", origin, f"issuer.test:{tls}",
                   f"origin.test:{tls}", f"127.0.0.1:{origin_port}"], "origin")
            start([nginx, "-p", str(tmp) + "/", "-c", tmp / "nginx.conf"], "nginx")
            for number in (issuer_port, origin_port, tls):
                for _ in range(100):
                    require(all(c.poll() is None for c in children), "child exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("listener startup timed out")

            def probe(host, path, expected, extra=(), data=None):
                args = ["curl", "--silent", "--show-error", "--noproxy", "*",
                        "--cacert", ca, "--resolve", f"{host}:{tls}:127.0.0.1",
                        "--output", os.devnull, "--max-time", "15",
                        "-w", "%{http_code}", *extra,
                        f"https://{host}:{tls}{path}"]
                require(run(args, data) == str(expected).encode(), "proxy status mismatch")

            probe("issuer.test", "/.well-known/private-token-issuer-directory", 200)
            probe("origin.test", "/private-token/protected", 401)
            probe("issuer.test", "/unknown", 404)
            probe("issuer.test", "/private-token/issue", 405)
            probe("issuer.test", "/private-token/issue", 421, ["-H", "Host: wrong.test"])
            probe("issuer.test", "/private-token/issue", 413,
                  ["-H", "Freebird-Admission: " + invitation.decode(),
                   "-H", "Content-Type: application/private-token-request",
                   "--data-binary", "@-"], b"x" * 4097)
            output = run([client, "--tls-ca", ca, "--connect", "127.0.0.1",
                           f"https://issuer.test:{tls}", f"https://origin.test:{tls}"],
                          invitation + b"\n")
            require(output == b"issuance: 200; redemption: 200; replay: 401; invitation retry: 403\n",
                     "reference client status mismatch")
            # The original numeric-loopback mode must remain usable without TLS.
            legacy = run([client, f"http://127.0.0.1:{issuer_port}",
                          f"http://127.0.0.1:{origin_port}"], legacy_invitation + b"\n")
            require(legacy == output, "legacy loopback client status mismatch")
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
            for child in reversed(children):
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            captured = b"".join(diagnostics)
            for name in ("access.log", "error.log", "issuer.diagnostic",
                         "origin.diagnostic", "nginx.diagnostic"):
                path = tmp / name
                if path.exists():
                    captured += path.read_bytes()
            require(not any(secret in captured for secret in secrets)
                    and b"authorization" not in captured.lower()
                    and b"freebird-admission" not in captured.lower(),
                    "sensitive material detected in logs (contents suppressed)")
    print("deployment proxy: passed")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError):
        print("deployment proxy: failed; check prerequisites, build, template, and proxy behavior")
        raise SystemExit(1)
