#!/usr/bin/env python3
"""Run the nginx app-protection example to check that the Origin protects application routes.

Remove comment prefixes from the example in `deploy/nginx/freebird.conf` and
substitute the test ports. The test runs a Python application and both service
binaries on loopback behind nginx TLS. It keeps secrets, tokens, and request
bodies out of the printed diagnostics.

Build the service and client with `cargo build --locked -p freebird-privacy-pass-service --bin freebird-privacy-pass-service --example sidecar_client`.
"""
import http.server
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
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


def replace(text, old, new, count):
    # Count exact matches before substituting so that unexpected template changes fail the test.
    require(text.count(old) == count, "app-protection example changed: substitution count")
    return text.replace(old, new)


def app_example(template, app_port, origin_port):
    begin, end = "# BEGIN app-protection example\n", "# END app-protection example\n"
    require(template.count(begin) == 1 and template.count(end) == 1,
            "app-protection markers changed")
    lines = []
    for line in template.split(begin, 1)[1].split(end, 1)[0].splitlines():
        require(line.startswith("#"), "app-protection example line is not commented")
        lines.append(line[2:] if line.startswith("# ") else line[1:])
    example = "\n".join(lines) + "\n"
    require("listen" not in example and "return 403" in example,
            "app-protection example changed")
    example = replace(example, "127.0.0.1:9000", f"127.0.0.1:{app_port}", 2)
    return replace(example, "127.0.0.1:8082", f"127.0.0.1:{origin_port}", 2)


class Application:
    """Record request metadata in a local HTTP server to check routing and header isolation."""

    def __init__(self, bind_port):
        self.records = []
        self.lock = threading.Lock()
        records, lock = self.records, self.lock

        class Handler(http.server.BaseHTTPRequestHandler):
            def handle_request(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with lock:
                    records.append({
                        "method": self.command,
                        "path": self.path,
                        "authorization": self.headers.get("Authorization") is not None,
                        "scope": self.headers.get("Freebird-Scope") is not None,
                        "body": len(body),
                    })
                payload = b"app ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = handle_request

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", bind_port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def snapshot(self):
        with self.lock:
            return list(self.records)


def main():
    nginx = os.environ.get("FREEBIRD_NGINX") or shutil.which("nginx")
    if not nginx and Path("/opt/homebrew/bin/nginx").is_file():
        nginx = "/opt/homebrew/bin/nginx"
    require(nginx and all(shutil.which(x) for x in ("openssl", "curl")),
            "nginx, openssl, and curl are required")
    root = Path(__file__).resolve().parents[1]
    binary = root / "target/debug/freebird-privacy-pass-service"
    client = root / "target/debug/examples/sidecar_client"
    require(binary.is_file() and client.is_file(),
            "build service and sidecar_client first (see module docstring)")
    diagnostics = []
    secrets = []
    children = []

    def run(args, data=None):
        result = subprocess.run([str(x) for x in args], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        diagnostics.append(result.stderr)
        require(result.returncode == 0, "subprocess failed (diagnostics suppressed)")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="freebird-sidecar-") as temporary:
        tmp = Path(temporary)
        application = None
        try:
            tls, issuer_port, origin_port, app_port = [port() for _ in range(4)]
            require(len({tls, issuer_port, origin_port, app_port}) == 4,
                    "port allocation collision")
            ca, cert, key = tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", tmp / "ca.key", "-out", ca, "-days", "1",
                 "-subj", "/CN=Freebird test CA"])
            run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                 "-out", tmp / "leaf.csr", "-subj", "/CN=origin.test"])
            save(tmp / "extensions", "subjectAltName=DNS:issuer.test,DNS:origin.test\n"
                 "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth")
            run(["openssl", "x509", "-req", "-in", tmp / "leaf.csr", "-CA", ca,
                 "-CAkey", tmp / "ca.key", "-CAcreateserial", "-out", cert,
                 "-days", "1", "-extfile", tmp / "extensions"])

            issuer, origin = tmp / "issuer", tmp / "origin"
            run([binary, "init-issuer", issuer])
            status = run([binary, "issuer-key-status", issuer]).decode()
            match = re.search(r"^active ([0-9a-f]{64}) ", status, re.MULTILINE)
            require(match is not None, "genesis key status missing")
            key_id = match.group(1)
            run([binary, "export-issuer-spki", issuer, key_id, tmp / "spki.der"])
            run([binary, "init-origin", origin, tmp / "spki.der", key_id])
            invitations = [run([binary, "provision", issuer]).strip() for _ in range(6)]
            for invitation in invitations:
                require(re.fullmatch(rb"[A-Za-z0-9_-]{43}", invitation),
                        "invalid invitation output")
            secrets.extend(invitations)

            # Use the deployment example with test ports to exercise the exact routing rules.
            template = (root / "deploy/nginx/freebird.conf").read_text()
            example = app_example(template, app_port, origin_port)
            tls_files = (f"    listen 127.0.0.1:{tls} ssl;\n"
                         f"    ssl_certificate {cert};\n"
                         f"    ssl_certificate_key {key};\n"
                         "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                         "    ssl_early_data off;\n"
                         "    client_max_body_size 1k;\n"
                         "    client_header_timeout 10s;\n"
                         "    client_body_timeout 10s;\n"
                         "    send_timeout 10s;\n"
                         "    keepalive_timeout 15s;\n"
                         "    proxy_connect_timeout 2s;\n"
                         "    proxy_send_timeout 10s;\n"
                         "    proxy_read_timeout 10s;\n"
                         "    proxy_request_buffering on;\n"
                         "    proxy_buffering on;\n"
                         "    proxy_cache off;\n"
                         "    proxy_store off;\n"
                         "    proxy_next_upstream off;\n"
                         "    proxy_pass_request_headers off;\n"
                         "    proxy_set_header Connection close;\n")
            # Put the Issuer on the same TLS listener to match the deployment template.
            issuer_block = (
                "server {\n"
                f"    listen 127.0.0.1:{tls} ssl;\n"
                "    server_name issuer.test;\n"
                f"    ssl_certificate {cert};\n"
                f"    ssl_certificate_key {key};\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "    ssl_early_data off;\n"
                "    client_max_body_size 4k;\n"
                "    proxy_connect_timeout 2s;\n"
                "    proxy_read_timeout 10s;\n"
                "    proxy_pass_request_headers off;\n"
                "    proxy_set_header Host issuer.test;\n"
                "    proxy_set_header Content-Type $http_content_type;\n"
                "    proxy_set_header Freebird-Admission $http_freebird_admission;\n"
                "    proxy_set_header Connection close;\n"
                "    location = /.well-known/private-token-issuer-directory {\n"
                f"        proxy_pass http://127.0.0.1:{issuer_port};\n"
                "    }\n"
                "    location = /private-token/issue {\n"
                "        if ($request_method != POST) { return 405; }\n"
                f"        proxy_pass http://127.0.0.1:{issuer_port};\n"
                "    }\n"
                "    location / { return 404; }\n"
                "}\n")
            origin_block = (
                "server {\n"
                f"    listen 127.0.0.1:{tls} ssl;\n"
                "    server_name origin.test;\n"
                f"    ssl_certificate {cert};\n"
                f"    ssl_certificate_key {key};\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "    ssl_early_data off;\n"
                "    client_max_body_size 1k;\n"
                "    proxy_connect_timeout 2s;\n"
                "    proxy_read_timeout 10s;\n"
                "    proxy_pass_request_headers off;\n"
                "    proxy_set_header Host origin.test;\n"
                "    proxy_set_header Connection close;\n"
                f"{example}"
                "    location / { return 404; }\n"
                "}\n")
            require("listen 127.0.0.1:" in tls_files, "internal template error")
            nginx_conf = tmp / "nginx.conf"
            save(nginx_conf, f"daemon off;\nmaster_process off;\n"
                 f"pid {tmp}/nginx.pid;\nerror_log {tmp}/error.log warn;\n"
                 f"events {{}}\nhttp {{\nclient_body_temp_path {tmp}/body;\naccess_log off;\n"
                 f"{issuer_block}{origin_block}}}")
            run([nginx, "-t", "-p", str(tmp) + "/", "-c", nginx_conf])
            print("app sidecar nginx configuration: passed", flush=True)

            application = Application(app_port)
            application.thread.start()

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
            start([nginx, "-p", str(tmp) + "/", "-c", nginx_conf], "nginx")
            for number in (issuer_port, origin_port, tls, app_port):
                for _ in range(100):
                    require(all(c.poll() is None for c in children), "child exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("listener startup timed out")

            def probe(method, path, extra=()):
                dump = tmp / "headers.txt"
                status = run(["curl", "--silent", "--show-error", "--noproxy", "*",
                              "--cacert", ca, "--resolve", f"origin.test:{tls}:127.0.0.1",
                              "--output", os.devnull, "--max-time", "15",
                              "--dump-header", dump, "-X", method, "-w", "%{http_code}",
                              *extra, f"https://origin.test:{tls}{path}"])
                return int(status), dump.read_text(errors="replace").lower()

            def sidecar(invitation, challenge_path, present_path=None, *options):
                args = [client, *options, "--tls-ca", ca, "--connect", "127.0.0.1",
                        f"https://issuer.test:{tls}/",
                        f"https://origin.test:{tls}{challenge_path}"]
                if present_path is not None:
                    args.append(f"https://origin.test:{tls}{present_path}")
                return run(args, invitation + b"\n")

            def expect_accepted(output, label):
                head, _, body = output.partition(b"\n")
                require(head == b"challenge: 401; first: 200; replay: 401" and body == b"app ok\n",
                        f"{label}: unexpected sidecar result")

            def expect_rejected(output, label, first):
                require(output.startswith(f"challenge: 401; first: {first}; replay: 401\n".encode()),
                        f"{label}: unexpected sidecar result")

            # Check that missing or malformed credentials and disallowed ballot IDs block app access.
            status, headers = probe("GET", "/app/x")
            require(status == 401 and 'www-authenticate: privatetoken challenge="' in headers,
                    "unauthenticated app request was not challenged")
            status, headers = probe("POST", "/app/x")
            require(status == 401 and "www-authenticate: privatetoken" in headers,
                    "unauthenticated POST was not challenged")
            status, _ = probe("GET", "/app/x", ["-H", "Authorization: PrivateToken token=bad"])
            require(status == 401, "malformed token was not rejected")
            status, _ = probe("GET", "/ballot/x")
            require(status == 403, "ballot request without an allowlisted id was not refused")
            status, _ = probe("GET", "/ballot/x?ballot=3")
            require(status == 403, "ballot id outside the allowlist was not refused")
            require(application.snapshot() == [], "application was contacted without a token")

            # Redeem each valid token once to check that a replay receives a `401` challenge.
            expect_accepted(sidecar(invitations[0], "/app/x"), "unscoped GET")
            expect_accepted(sidecar(invitations[1], "/app/x", "/app/x", "--method", "POST"),
                            "unscoped POST")
            # The proxy takes the ballot ID from the query string, so `Freebird-Scope` cannot replace it.
            expect_accepted(sidecar(invitations[2], "/ballot/x?ballot=1", "/ballot/x?ballot=1",
                                    "--scope-header", "ballot:2"), "ballot with client scope")
            # A token scoped to `ballot=1` must fail at `ballot=2` and at the unscoped route.
            expect_rejected(sidecar(invitations[3], "/ballot/x?ballot=1", "/ballot/x?ballot=2"),
                            "cross-ballot", 401)
            expect_rejected(sidecar(invitations[4], "/ballot/x?ballot=1", "/app/x"),
                            "scoped-to-unscoped", 401)
            # An unscoped route must accept its token even if the client sets `Freebird-Scope`.
            expect_accepted(sidecar(invitations[5], "/app/x", "/app/x",
                                    "--scope-header", "ballot:1"), "unscoped with client scope")

            # Verify that only the four accepted requests reached the app and that the `POST` body arrived.
            # Neither the credential header nor the scope header should reach the app.
            records = application.snapshot()
            require([(r["method"], r["path"]) for r in records] == [
                ("GET", "/app/x"), ("POST", "/app/x"),
                ("GET", "/ballot/x?ballot=1"), ("GET", "/app/x")],
                "application saw unexpected requests")
            require(all(not r["authorization"] and not r["scope"] for r in records),
                    "credential or scope header reached the application")
            require(records[1]["body"] == 4, "POST body did not reach the application")
            print("app sidecar: accepted, rejected, and header-isolation checks passed",
                  flush=True)
        finally:
            if application is not None:
                application.server.shutdown()
                application.server.server_close()
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
            for name in ("error.log", "issuer.diagnostic", "origin.diagnostic",
                         "nginx.diagnostic"):
                path = tmp / name
                if path.exists():
                    captured += path.read_bytes()
            require(not any(secret in captured for secret in secrets)
                    and b"authorization" not in captured.lower()
                    and b"freebird-scope" not in captured.lower()
                    and b"freebird-admission" not in captured.lower(),
                    "sensitive material detected in logs (contents suppressed)")
    print("app sidecar: passed")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError):
        print("app sidecar: failed; check prerequisites, build, template, and proxy behavior")
        raise SystemExit(1)
