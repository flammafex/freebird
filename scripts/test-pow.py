#!/usr/bin/env python3
"""Check that the Issuer enforces ALTCHA admission while keeping credentials out of diagnostics."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
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
    binary = root / "target/debug/freebird-privacy-pass-service"
    allowed = "https://origin.example"
    diagnostics, secrets = [], []
    child = None
    phase = "build"

    def run(command, succeeds=True, input_bytes=None, timeout=300):
        result = subprocess.run(list(map(str, command)), cwd=root, input=input_bytes,
                                capture_output=True, timeout=timeout)
        diagnostics.append(result.stderr)
        require((result.returncode == 0) == succeeds, "unexpected command status")
        if not succeeds:
            require(not result.stdout, "failed command emitted stdout")
        return result.stdout

    def cli(*args, succeeds=True):
        return run([binary, *args], succeeds=succeeds)

    def request(number, method, path, body=None, origin=allowed, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", number, timeout=30)
        try:
            headers = dict(headers or {})
            if origin is not None:
                headers["Origin"] = origin
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read(16385)
        finally:
            conn.close()

    run(["cargo", "build", "--locked", "-q", "-p", "freebird-privacy-pass-service",
         "--bin", "freebird-privacy-pass-service"])
    # Build the optimized solver before issuing any challenges because debug PBKDF2
    # can take longer than a challenge remains valid.
    run(["cargo", "build", "--locked", "-q", "--release", "-p",
         "freebird-privacy-pass-service", "--example", "pow_solve"])
    with tempfile.TemporaryDirectory(prefix="freebird-pow-") as directory:
        tmp = Path(directory)
        tmp.chmod(0o700)
        diagnostic = tmp / "issuer.diagnostic"
        try:
            phase = "initialization"
            issuer = tmp / "issuer"
            cli("init-issuer", issuer)
            number = port()
            arguments = ["serve-issuer", issuer, "issuer.test",
                         "https://issuer.test/private-token/issue", f"127.0.0.1:{number}"]
            # Missing proof-of-work state must block startup until explicit initialization.
            cli(*arguments, allowed, succeeds=False)
            cli("init-issuer-pow", issuer)
            cli("init-issuer-pow", issuer, succeeds=False)
            for name in ("pow-key", "pow.sqlite", "pow.sqlite.lock"):
                metadata = (issuer / name).lstat()
                require(stat.S_ISREG(metadata.st_mode), "PoW state must be regular")
                require(stat.S_IMODE(metadata.st_mode) == 0o600, "PoW state must be private")
            require((issuer / "pow-key").stat().st_size == 32, "invalid PoW key size")
            for origin in ("http://origin.example", allowed + "/", allowed + "?x",
                           "https://user@origin.example", allowed + ":65536"):
                cli(*arguments, origin, succeeds=False)
            with diagnostic.open("xb") as stream:
                diagnostic.chmod(0o600)
                child = subprocess.Popen([str(binary), *map(str, arguments), allowed],
                                         cwd=root, stdout=stream, stderr=stream)
            phase = "readiness"
            for _ in range(200):
                require(child.poll() is None, "issuer exited")
                try:
                    with socket.create_connection(("127.0.0.1", number), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError("issuer readiness timeout")
            phase = "CORS"
            paths = ("/freebird/pow/challenge", "/freebird/pow/admission",
                     "/.well-known/private-token-issuer-directory", "/private-token/issue")
            for path in paths:
                for origin in (allowed, "https://other.example"):
                    status, headers, _ = request(number, "OPTIONS", path, origin=origin, headers={
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "Content-Type, Freebird-Admission",
                    })
                    require(status == 204, "preflight status")
                    require(headers.get("vary") == "Origin", "preflight Vary")
                    require("access-control-allow-credentials" not in headers, "credentials forbidden")
                    if origin == allowed:
                        require(headers.get("access-control-allow-origin") == allowed, "preflight origin")
                        require(headers.get("access-control-allow-methods") == "GET, POST", "preflight methods")
                        require(headers.get("access-control-allow-headers") ==
                                "Content-Type, Freebird-Admission", "preflight headers")
                        require(headers.get("access-control-max-age") == "600", "preflight max-age")
                    else:
                        require("access-control-allow-origin" not in headers, "other origin allowed")
            phase = "challenge and solve"
            start = int(time.time())
            status, headers, challenge_bytes = request(number, "GET", paths[0])
            require(status == 200 and headers.get("cache-control") == "no-store", "challenge response")
            require(headers.get("access-control-allow-origin") == allowed, "challenge CORS")
            challenge = json.loads(challenge_bytes)
            require(start + 300 <= challenge["parameters"]["expiresAt"] <= int(time.time()) + 300,
                    "challenge expiry")
            require(challenge["parameters"]["algorithm"] == "PBKDF2/SHA-256", "challenge algorithm")
            payload = run(["cargo", "run", "--locked", "-q", "-p",
                           "freebird-privacy-pass-service", "--example", "pow_solve", "--release"],
                          input_bytes=challenge_bytes).strip()
            secrets.append(payload)
            submission = json.dumps({"payload": payload.decode()}).encode()
            phase = "admission and replay"
            status, headers, response = request(number, "POST", paths[1], submission,
                                               headers={"Content-Type": "application/json"})
            require(status == 200 and headers.get("cache-control") == "no-store", "admission response")
            require(headers.get("access-control-allow-origin") == allowed, "admission CORS")
            code = json.loads(response)["admission"]
            secrets.append(code.encode())
            require(re.fullmatch(r"[A-Za-z0-9_-]{43}", code) is not None, "admission encoding")
            status, _, _ = request(number, "POST", paths[1], submission,
                                   headers={"Content-Type": "application/json"})
            require(status == 403, "replay accepted")
            phase = "issuance admission"
            status, headers, document = request(number, "GET", paths[2])
            require(status == 200 and headers.get("access-control-allow-origin") == allowed,
                    "directory response")
            spki = base64.urlsafe_b64decode(json.loads(document)["token-keys"][0]["token-key"])
            # Use the selected key ID to reach admission and check the code.
            # The Issuer returns `422` for a mismatched key before it checks the code.
            body = b"\x00\x02" + hashlib.sha256(spki).digest()[-1:] + bytes(256)
            issue_headers = {"Content-Type": "application/private-token-request",
                             "Freebird-Admission": "A" * 43}
            require(request(number, "POST", paths[3], body, headers=issue_headers)[0] == 403,
                    "unprovisioned admission accepted")
            issue_headers["Freebird-Admission"] = code
            status, headers, _ = request(number, "POST", paths[3], body, headers=issue_headers)
            require(status in (200, 500), "PoW admission did not pass admission check")
            require(headers.get("access-control-allow-origin") == allowed, "issue CORS")
            require(request(number, "POST", paths[3], body, headers=issue_headers)[0] == 403,
                    "admission reusable")
            status, headers, _ = request(number, "GET", paths[2], origin="https://other.example")
            require(status == 200 and "access-control-allow-origin" not in headers, "other origin CORS")
            require(child.poll() is None, "issuer stopped serving")
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError):
            raise RuntimeError(f"PoW test failed during {phase}; diagnostics suppressed") from None
        finally:
            if child is not None:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            captured = b"".join(diagnostics)
            if diagnostic.exists():
                captured += diagnostic.read_bytes()
            require(not any(secret in captured for secret in secrets),
                    "PoW test failed: sensitive diagnostics detected; contents suppressed")
    print("PoW: ALTCHA solved; admission accepted once; replay refused; "
          "single-origin CORS; diagnostics secret-free.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if type(error) is RuntimeError else "PoW test failed; diagnostics suppressed")
        raise SystemExit(1)
