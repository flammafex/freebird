#!/usr/bin/env python3
"""Exercise application admission against the real loopback Issuer binary.

Keys and admission codes are captured privately and never printed; every
diagnostic is scanned for them before the script reports success.
"""
import http.client
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time

KEY = re.compile(rb"fba_[A-Za-z0-9_-]{43}\n")
CODE = re.compile(r"[A-Za-z0-9_-]{43}")


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
    diagnostics, secrets = [], []
    child = None
    phase = "initialization"

    def run(args, succeeds=True):
        result = subprocess.run([str(binary), *map(str, args)], cwd=root,
                                capture_output=True, timeout=120)
        diagnostics.append(result.stderr)
        require((result.returncode == 0) == succeeds, "unexpected command status")
        if not succeeds:
            require(not result.stdout, "failed command emitted stdout")
        return result.stdout

    def request(number, method, headers=None, body=b""):
        conn = http.client.HTTPConnection("127.0.0.1", number, timeout=10)
        try:
            conn.request(method, "/freebird/app/admission", body=body, headers=headers or {})
            response = conn.getresponse()
            data = response.read(4096)
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            conn.close()

    def admit(number, key, origin=None, body=b""):
        headers = {"Authorization": f"Bearer {key.decode()}"}
        if origin is not None:
            headers["Origin"] = origin
        return request(number, "POST", headers, body)

    def issue(number, code, body):
        conn = http.client.HTTPConnection("127.0.0.1", number, timeout=10)
        try:
            conn.request("POST", "/private-token/issue", body=body, headers={
                "Content-Type": "application/private-token-request",
                "Freebird-Admission": code.decode(),
            })
            response = conn.getresponse()
            response.read(16385)
            return response.status
        finally:
            conn.close()

    def app_list(issuer):
        output = run(["app-list", issuer])
        require(output.endswith(b"end\n"), "app-list reply is not terminated")
        return output

    with tempfile.TemporaryDirectory(prefix="freebird-app-") as directory:
        tmp = Path(directory)
        os.chmod(tmp, 0o700)
        diagnostic = tmp / "issuer.diagnostic"
        try:
            issuer = tmp / "issuer"
            run(["init-issuer", issuer])
            status = run(["issuer-key-status", issuer])
            match = re.search(rb"^active ([0-9a-f]{64}) ", status, re.MULTILINE)
            require(match is not None, "missing public key ID")
            key_id = match[1].decode()
            phase = "disabled state"
            # Feature off: no store, so every app command refuses; nothing is created.
            run(["app-list", issuer], succeeds=False)
            run(["app-add", issuer, "clienta", 2], succeeds=False)
            require(not (issuer / "app-clients.sqlite").exists(), "store created implicitly")
            phase = "initialization"
            require(run(["init-issuer-app-admission", issuer]) == b"", "init printed output")
            run(["init-issuer-app-admission", issuer], succeeds=False)
            run(["init-issuer-pow", issuer])
            number = port()
            with diagnostic.open("xb") as stream:
                os.chmod(diagnostic, 0o600)
                child = subprocess.Popen([
                    str(binary), "serve-issuer", str(issuer), "issuer.test",
                    "https://issuer.test/private-token/issue", f"127.0.0.1:{number}",
                    "https://origin.test",
                ], cwd=root, stdout=stream, stderr=stream)
            phase = "readiness"
            control = issuer / "control.sock"
            for _ in range(200):
                require(child.poll() is None, "issuer exited")
                try:
                    with socket.create_connection(("127.0.0.1", number), timeout=.1):
                        if control.exists():
                            break
                except OSError:
                    pass
                time.sleep(.05)
            else:
                raise RuntimeError("issuer readiness timeout")
            metadata = control.lstat()
            require(stat.S_ISSOCK(metadata.st_mode), "control path must be a socket")
            require(stat.S_IMODE(metadata.st_mode) == 0o600, "control socket must be private")

            phase = "enrollment"
            key_line = run(["app-add", issuer, "clienta", 2])
            require(KEY.fullmatch(key_line) is not None, "invalid key output")
            key_a = key_line[:-1]
            secrets.append(key_a)
            run(["app-add", issuer, "clienta", 2], succeeds=False)
            run(["app-add", issuer, "Bad_Name", 2], succeeds=False)
            run(["app-add", issuer, "clientb", 0], succeeds=False)
            run(["app-add", issuer, "clientb", 100001], succeeds=False)
            run(["app-cap", issuer, "missing", 3], succeeds=False)
            run(["app-revoke", issuer, "missing"], succeeds=False)

            phase = "admission"
            status, headers, _ = request(number, "POST")
            require(status == 401 and headers.get("www-authenticate") == "Bearer",
                    "missing credentials must be refused")
            status, _, _ = admit(number, b"fba_" + b"A" * 43)
            require(status == 401, "unknown key must be refused")
            status, _, _ = admit(number, key_a[:-1])
            require(status == 401, "truncated key must be refused")
            status, _, _ = admit(number, key_a, body=b"x")
            require(status == 400, "non-empty body must be refused")
            status, headers, _ = request(number, "OPTIONS", {
                "Origin": "https://origin.test", "Authorization": f"Bearer {key_a.decode()}",
            })
            require(status == 405 and "access-control-allow-origin" not in headers,
                    "app route must not receive browser CORS")
            status, headers, body = admit(number, key_a, origin="https://origin.test")
            require(status == 200, "enrolled key must be admitted")
            require("access-control-allow-origin" not in headers, "app route must not get CORS")
            require(headers.get("cache-control") == "no-store", "admission must not be cached")
            code_one = re.fullmatch(rb'\{"admission":"([A-Za-z0-9_-]{43})"\}', body)
            require(code_one is not None, "invalid admission reply")
            code_one = code_one[1]
            secrets.append(code_one)
            status, _, body = admit(number, key_a)
            require(status == 200, "second admission within cap must succeed")
            code_two = re.fullmatch(rb'\{"admission":"([A-Za-z0-9_-]{43})"\}', body)
            require(code_two is not None and code_two[1] != code_one, "codes must differ")
            code_two = code_two[1]
            secrets.append(code_two)
            status, headers, _ = admit(number, key_a)
            require(status == 429, "admission beyond the daily cap must be refused")
            require(headers.get("retry-after", "").isdigit()
                    and 1 <= int(headers["retry-after"]) <= 86400, "invalid Retry-After")

            phase = "issuance admission"
            # Same not-403 check as test-live-provision: the one-use code must
            # advance past admission, and a second use must be refused.
            body = b"\x00\x02" + bytes([int(key_id[-2:], 16)]) + bytes(256)
            require(len(body) == 259, "invalid request length")
            require(issue(number, code_one, body) in (200, 500),
                    "app-issued code did not pass admission")
            require(issue(number, code_one, body) == 403, "app-issued code was reusable")

            phase = "listing"
            listing = app_list(issuer)
            require(b"app clienta 2 2 active\n" in listing, "usage listing mismatch")

            phase = "revocation and reactivation"
            require(run(["app-revoke", issuer, "clienta"]) == b"ok\n", "revoke reply")
            status, _, _ = admit(number, key_a)
            require(status == 401, "revoked key must be refused")
            require(b"app clienta 2 2 revoked\n" in app_list(issuer), "revoked listing mismatch")
            key_line = run(["app-add", issuer, "clienta", 3])
            require(KEY.fullmatch(key_line) is not None, "reactivation key output")
            key_b = key_line[:-1]
            require(key_b != key_a, "reactivation must issue a fresh key")
            secrets.append(key_b)
            status, _, _ = admit(number, key_a)
            require(status == 401, "old key must stay revoked after reactivation")
            status, _, _ = admit(number, key_b)
            require(status == 200, "reactivated key must be admitted within remaining cap")
            require(run(["app-cap", issuer, "clienta", 5]) == b"ok\n", "cap reply")
            status, _, _ = admit(number, key_b)
            require(status == 200, "raised cap must admit again")
            require(b"app clienta 5 4 active\n" in app_list(issuer), "cap listing mismatch")
            require(child.poll() is None, "issuer stopped serving")

            phase = "offline after stop"
            child.terminate()
            child.wait(timeout=10)
            child = None
            # Socket file may remain after exit: connection refusal must still
            # fall back to offline maintenance, which needs the store lock.
            listing = app_list(issuer)
            require(b"app clienta 5 4 active\n" in listing, "offline listing mismatch")
            key_line = run(["app-add", issuer, "clientb", 1])
            require(KEY.fullmatch(key_line) is not None, "offline key output")
            secrets.append(key_line[:-1])
            require(run(["app-revoke", issuer, "clientb"]) == b"ok\n", "offline revoke")
            require(b"app clientb 1 0 revoked\n" in app_list(issuer), "offline listing")
            print("App admission: enrolled, capped per UTC day, one-use codes admitted, "
                  "revocation and offline maintenance enforced; diagnostics secret-free.")
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            raise RuntimeError(f"app admission failed during {phase}; diagnostics suppressed") from None
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
                    "app admission failed: sensitive diagnostics detected; contents suppressed")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if type(error) is RuntimeError
              else "app admission failed; diagnostics suppressed")
        raise SystemExit(1)
