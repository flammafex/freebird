#!/usr/bin/env python3
"""Build the browser demo and test token redemption and replay through the nginx TLS configuration.

Install `cargo`, Node 26 or later, `npm`, `openssl`, `nginx`, and Chrome or Chromium.
Use `FREEBIRD_NGINX` and `FREEBIRD_CHROME` to select specific executables.

The test keeps service state, certificates, the build copy, and the browser
profile in a temporary directory. It prints only fixed statuses because
subprocess and browser diagnostics can contain credentials.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    root = Path(__file__).resolve().parents[1]
    web = root / "demo/web"
    nginx = os.environ.get("FREEBIRD_NGINX") or shutil.which("nginx")
    if not nginx and Path("/opt/homebrew/bin/nginx").is_file():
        nginx = "/opt/homebrew/bin/nginx"
    chrome = os.environ.get("FREEBIRD_CHROME")
    if not chrome:
        chrome = next((path for path in [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            shutil.which("google-chrome"), shutil.which("chromium"),
            shutil.which("chromium-browser"),
        ] if path and Path(path).is_file()), None)
    require(chrome, "Chrome/Chromium not found; install it or set FREEBIRD_CHROME")
    require(nginx, "nginx not found; install it or set FREEBIRD_NGINX")
    for name in ("cargo", "node", "npm", "openssl"):
        require(shutil.which(name), f"required executable missing: {name}")

    def run(args, label, data=None, cwd=root, timeout=60):
        try:
            result = subprocess.run([str(arg) for arg in args], input=data, cwd=cwd,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{label}: timed out (diagnostics suppressed)") from None
        if result.returncode and label == "browser CDP flow":
            # Pass through only fixed failure statuses to keep credentials out of the output.
            for status in (
                "Chrome page target unavailable", "CDP connection timed out",
                "CDP connection failed", "CDP command timed out", "CDP command rejected",
                "page evaluation failed", "worker instrumentation failed",
                "HTTPS navigation failed", "not a secure context", "incomplete browser flow",
                "real PoW worker not observed", "browser console/exception errors observed",
                "browser CSP/security violations observed", "unexpected browser resource errors",
                "TLS document not observed", "strict document CSP missing",
                "document security headers missing", "request outside Issuer/Origin boundary observed",
                "redemption/replay statuses differ",
                "browser/driver operation failed (diagnostics suppressed)",
                *(f"required browser protocol request missing: {stage}" for stage in
                  ("directory", "challenge", "admission", "issuance")),
                *(f"{stage}: {reason}" for stage in ("page ready", "access", "replay")
                  for reason in ("page reported failure", "timed out")),
            ):
                if f"browser demo CDP: failed; {status}".encode() in result.stderr.splitlines():
                    raise RuntimeError(f"{label}: failed; {status}")
        require(result.returncode == 0, f"{label}: failed (diagnostics suppressed)")
        return result.stdout

    version = run(["node", "--version"], "Node version")
    require(int(version.decode().strip().lstrip("v").split(".")[0]) >= 26,
            "Node 26+ is required for the built-in WebSocket/fetch CDP driver")
    run(["cargo", "build", "--locked", "-p", "freebird-privacy-pass-service",
         "--bin", "freebird-privacy-pass-service"], "service build", timeout=600)
    print("browser demo service build: passed", flush=True)
    run(["npm", "ci", "--ignore-scripts"], "demo dependency installation", cwd=web, timeout=300)
    run(["npm", "run", "build"], "demo build", cwd=web, timeout=120)
    print("browser demo static build: passed", flush=True)
    binary = root / "target/debug/freebird-privacy-pass-service"
    children = []

    preferred = Path(tempfile.gettempdir()) / "opencode"
    # Use a short prefix so that the Issuer's socket path can fit within macOS's 104-byte limit.
    with tempfile.TemporaryDirectory(prefix="fb-",
                                     dir=preferred if preferred.is_dir() else None) as temporary:
        tmp = Path(temporary)
        require(len(os.fsencode(tmp / "issuer/control.sock")) < 104,
                "temporary base too long for issuer control socket")
        try:
            http, tls, issuer_port, origin_port = [port() for _ in range(4)]
            require(len({http, tls, issuer_port, origin_port}) == 4, "port allocation collision")
            issuer_name = f"issuer.test:{tls}"
            origin_name = f"origin.test:{tls}"
            issuer_url = f"https://{issuer_name}"
            origin_url = f"https://{origin_name}"
            ca, cert, key = tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", tmp / "ca.key", "-out", ca, "-days", "1",
                 "-subj", "/CN=Freebird browser test CA"], "CA creation")
            run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", key, "-out", tmp / "leaf.csr",
                 "-subj", "/CN=issuer.test"], "leaf CSR creation")
            (tmp / "extensions").write_text(
                "subjectAltName=DNS:issuer.test,DNS:origin.test\n"
                "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
            run(["openssl", "x509", "-req", "-in", tmp / "leaf.csr", "-CA", ca,
                 "-CAkey", tmp / "ca.key", "-CAcreateserial", "-out", cert,
                 "-days", "1", "-extfile", tmp / "extensions"], "leaf signing")
            public_key = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"],
                             "leaf public key")
            spki = run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                       "leaf SPKI", data=public_key)
            trusted_spki = base64.b64encode(hashlib.sha256(spki).digest()).decode()

            demo = tmp / "demo"
            shutil.copytree(web / "dist", demo)
            index = demo / "index.html"
            html = index.read_text()
            marker = '<meta name="freebird-issuer" content="">'
            require(html.count(marker) == 1, "demo issuer meta template changed")
            index.write_text(html.replace(marker,
                             f'<meta name="freebird-issuer" content="{issuer_url}">'))
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
            replace("https://issuer.test;", f"{issuer_url};", 1)  # Match the CSP to the test port.
            replace("    listen [::]:80;\n", "", 2)
            replace("    listen [::]:443 ssl;\n", "", 2)
            replace("listen 80;", f"listen 127.0.0.1:{http};", 2)
            replace("listen 443 ssl;", f"listen 127.0.0.1:{tls} ssl;", 2)
            replace("(:80)?", f"(:{http})?", 2)
            replace("(:443)?", f"(:{tls})?", 2)
            replace("127.0.0.1:8081", f"127.0.0.1:{issuer_port}", 4)
            # Replace one Origin address in active rules and two in the app-protection example.
            replace("127.0.0.1:8082", f"127.0.0.1:{origin_port}", 3)
            replace("/var/log/nginx/freebird-access.log", str(tmp / "access.log"), 1)
            replace("/var/log/nginx/freebird-error.log", str(tmp / "error.log"), 1)
            replace("/var/lib/letsencrypt", str(tmp / "acme"), 2)
            # Replace both occurrences of the demo path to point `root` at the temporary build.
            replace("/var/www/freebird-demo", str(demo), 2)
            nginx_config = tmp / "nginx.conf"
            nginx_config.write_text(
                f"daemon off;\nmaster_process off;\npid {tmp}/nginx.pid;\n"
                f"error_log {tmp}/error.log warn;\nevents {{}}\nhttp {{\n"
                f"client_body_temp_path {tmp}/body;\n{config}\n}}\n")
            run([nginx, "-t", "-p", str(tmp) + "/", "-c", nginx_config], "nginx -t")
            print("browser demo nginx configuration: passed", flush=True)

            issuer, origin = tmp / "issuer", tmp / "origin"
            run([binary, "init-issuer", issuer], "issuer initialization")
            run([binary, "init-issuer-pow", issuer], "PoW initialization")
            status = run([binary, "issuer-key-status", issuer], "genesis key status").decode()
            match = re.search(r"^active ([0-9a-f]{64}) ", status, re.MULTILINE)
            require(match is not None, "genesis key status missing")
            key_id = match.group(1)
            run([binary, "export-issuer-spki", issuer, key_id, tmp / "spki.der"],
                "genesis SPKI export")
            run([binary, "init-origin", origin, tmp / "spki.der", key_id], "origin initialization")

            def start(args, label):
                with (tmp / f"{label}.diagnostic").open("wb") as stream:
                    # Start a separate process group so that cleanup can stop Chrome and its helpers
                    # before they can write to the temporary profile again.
                    child = subprocess.Popen([str(arg) for arg in args], cwd=root,
                                             stdout=stream, stderr=stream,
                                             start_new_session=True)
                children.append(child)
                return child

            start([binary, "serve-issuer", issuer, issuer_name,
                   f"{issuer_url}/private-token/issue", f"127.0.0.1:{issuer_port}",
                   origin_url], "issuer")
            start([binary, "serve-origin", origin, issuer_name, origin_name,
                   f"127.0.0.1:{origin_port}"], "origin")
            start([nginx, "-p", str(tmp) + "/", "-c", nginx_config], "nginx")
            for number in (issuer_port, origin_port, tls):
                for _ in range(200):
                    require(all(child.poll() is None for child in children),
                            "service/nginx exited during startup (diagnostics suppressed)")
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("listener startup timed out")
            print("browser demo TLS services: ready", flush=True)

            profile = tmp / "chrome-profile"
            chrome_args = [
                chrome, "--headless=new", "--no-first-run", "--no-default-browser-check",
                "--disable-background-networking", "--disable-component-update",
                "--disable-default-apps", "--disable-extensions", "--disable-sync",
                "--metrics-recording-only", "--no-proxy-server",
                "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
                f"--user-data-dir={profile}",
                "--host-resolver-rules=MAP issuer.test 127.0.0.1, MAP origin.test 127.0.0.1",
                f"--ignore-certificate-errors-spki-list={trusted_spki}", "about:blank",
            ]
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                # Disable the sandbox in root-only containers because Chrome cannot start it as root.
                chrome_args.insert(1, "--no-sandbox")
            start(chrome_args, "chrome")
            active_port = profile / "DevToolsActivePort"
            # Allow more than ten seconds because Chrome can take longer to start on shared CI runners.
            deadline = time.monotonic() + 60
            while True:
                require(all(child.poll() is None for child in children),
                        "Chrome/service exited during startup (diagnostics suppressed)")
                if active_port.is_file():
                    lines = active_port.read_text().splitlines()
                    if lines and lines[0].isdigit():
                        debugging_port = int(lines[0])
                        break
                if time.monotonic() > deadline:
                    raise RuntimeError("Chrome DevTools startup timed out")
                time.sleep(.05)
            # Check driver statuses before printing them to keep raw browser data private.
            output = run(["node", web / "test/e2e-cdp.mjs", str(debugging_port), origin_url,
                          issuer_url], "browser CDP flow", timeout=180)
            allowed = {
                b"browser demo access: 200", b"browser demo replay: 401",
                b"browser demo console/CSP: passed", b"browser demo network boundary: passed",
            }
            require(set(output.splitlines()) == allowed, "unexpected browser driver output")
            require(all(child.poll() is None for child in children),
                    "browser/service exited during flow")
            for line in output.decode().splitlines():
                print(line, flush=True)
        finally:
            for child in reversed(children):
                signal_group(child, signal.SIGTERM)
            for child in reversed(children):
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                signal_group(child, signal.SIGKILL)
                child.wait()
    print("browser demo: passed")


def signal_group(child, number):
    try:
        os.killpg(child.pid, number)
    except ProcessLookupError:
        pass


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"browser demo: failed; {error}")
        raise SystemExit(1)
    except (OSError, subprocess.SubprocessError) as error:
        # Report only the exception type and `errno` because messages can expose paths or arguments.
        print("browser demo: failed; prerequisite/process error "
              f"({type(error).__name__} errno={getattr(error, 'errno', None)}; "
              "diagnostics suppressed)")
        raise SystemExit(1)
