#!/usr/bin/env python3
"""Exercise operator-only live provisioning against the real loopback Issuer."""
import http.client
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

    def issue(number, invitation, body):
        conn = http.client.HTTPConnection("127.0.0.1", number, timeout=10)
        try:
            conn.request("POST", "/private-token/issue", body=body, headers={
                "Content-Type": "application/private-token-request",
                "Freebird-Admission": invitation.decode(),
            })
            response = conn.getresponse()
            response.read(16385)
            return response.status
        finally:
            conn.close()

    with tempfile.TemporaryDirectory(prefix="freebird-live-") as directory:
        tmp = Path(directory)
        os.chmod(tmp, 0o700)
        diagnostic = tmp / "issuer.diagnostic"
        try:
            issuer = tmp / "issuer"
            run(["init-issuer", issuer])
            require(stat.S_IMODE(issuer.stat().st_mode) == 0o700, "state must be private")
            status = run(["issuer-key-status", issuer])
            match = re.search(rb"^active ([0-9a-f]{64}) ", status, re.MULTILINE)
            require(match is not None, "missing public key ID")
            key_id = match[1].decode()
            run(["provision-live", issuer], succeeds=False)
            number = port()
            with diagnostic.open("xb") as stream:
                os.chmod(diagnostic, 0o600)
                child = subprocess.Popen([
                    str(binary), "serve-issuer", str(issuer), "issuer.test",
                    "https://issuer.test/private-token/issue", f"127.0.0.1:{number}",
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
            phase = "live provisioning"
            for _ in range(2):
                output = run(["provision-live", issuer])
                require(re.fullmatch(rb"[A-Za-z0-9_-]{43}\n", output) is not None,
                        "invalid invitation output")
                secrets.append(output[:-1])
            require(secrets[0] != secrets[1], "invitations must differ")
            phase = "offline lock exclusion"
            run(["provision", issuer], succeeds=False)
            require(child.poll() is None, "issuer stopped serving")
            phase = "issuance admission"
            # Use the selected truncated key ID, so admission is actually checked.
            # An invalid blinded message is sufficient: live admission must advance
            # past 403, whereas an unprovisioned canonical invitation must get 403.
            body = b"\x00\x02" + bytes([int(key_id[-2:], 16)]) + bytes(256)
            require(len(body) == 259, "invalid request length")
            require(issue(number, b"A" * 43, body) == 403, "garbage invitation was not refused")
            live_status = issue(number, secrets[0], body)
            require(live_status in (200, 500), "live invitation did not pass admission")
            require(issue(number, secrets[0], body) == 403, "live invitation was reusable")
            require(child.poll() is None, "issuer stopped serving")
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            raise RuntimeError(f"live provisioning failed during {phase}; diagnostics suppressed") from None
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
                    "live provisioning failed: sensitive diagnostics detected; contents suppressed")
    print("Live provisioning: two distinct invitations; offline lock enforced; "
          "issuance admission accepted once; diagnostics secret-free.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if type(error) is RuntimeError
              else "live provisioning failed; diagnostics suppressed")
        raise SystemExit(1)
