#!/usr/bin/env python3
"""Check that independent clients can obtain and redeem tokens over loopback."""
import base64
import http.client
import os
from pathlib import Path
import re
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
    binary = root / "target/debug/freebird-privacy-pass-service"
    children, diagnostics, secrets, public = [], [], [], []
    phase = "versions"

    def run(args, cwd=root):
        result = subprocess.run([str(x) for x in args], cwd=cwd,
                                capture_output=True, timeout=120)
        diagnostics.append(result.stderr)
        require(result.returncode == 0, "subprocess failed")
        return result.stdout

    def expected(args, output, cwd=root):
        actual = run(args, cwd)
        diagnostics.append(actual)
        require(actual == output.encode(), "unexpected harness output")

    def request(number, path, headers=None, data=None):
        conn = http.client.HTTPConnection("127.0.0.1", number, timeout=10)
        try:
            conn.request("POST" if data is not None else "GET", path,
                         body=data, headers=headers or {})
            response = conn.getresponse()
            response.read(16385)
            return response.status
        finally:
            conn.close()

    with tempfile.TemporaryDirectory(prefix="freebird-interop-") as directory:
        tmp = Path(directory)
        os.chmod(tmp, 0o700)
        try:
            node = run(["node", "--version"]).decode().strip()
            go = run(["go", "version"]).decode().strip()
            require(re.fullmatch(r"v26\.\d+\.\d+", node), "Node 26 required")
            require(re.fullmatch(r"go version go1\.27(?:\.\d+)? \S+", go), "Go 1.27 required")
            public.extend([node, go])
            modules = run(["go", "list", "-m", "github.com/cloudflare/pat-go",
                           "go.vitalvas.com/kasper"], root / "interop/go").decode().splitlines()
            require(modules == [
                "github.com/cloudflare/pat-go v0.0.0-20260601145634-7e6bbd0e4fa8",
                "go.vitalvas.com/kasper v1.1.0",
            ], "Go dependency pin changed")
            public.extend(["@cloudflare/privacypass-ts 0.9.0", *modules])
            phase = "offline initialization"
            issuer, origin = tmp / "issuer", tmp / "origin"
            run([binary, "init-issuer", issuer])
            status = run([binary, "issuer-key-status", issuer])
            match = re.search(rb"^active ([0-9a-f]{64}) ", status, re.MULTILINE)
            require(match is not None, "missing public key ID")
            key_id = match[1].decode()
            run([binary, "export-issuer-spki", issuer, key_id, tmp / "spki.der"])
            run([binary, "init-origin", origin, tmp / "spki.der", key_id])
            invitations = []
            for index in range(2):
                invitation = run([binary, "provision", issuer]).strip()
                require(re.fullmatch(rb"[A-Za-z0-9_-]{43}", invitation), "invalid invitation")
                secrets.append(invitation)
                path = tmp / f"invitation-{index}"
                with path.open("xb") as stream:
                    os.chmod(path, 0o600)
                    stream.write(invitation + b"\n")
                invitations.append(path)
            require(secrets[0] != secrets[1], "invitations must differ")
            issuer_port, origin_port = port(), port()
            require(issuer_port != origin_port, "port collision")
            for label, args in (
                ("issuer", ["serve-issuer", issuer, "issuer.test",
                            "https://issuer.test/private-token/issue", f"127.0.0.1:{issuer_port}"]),
                ("origin", ["serve-origin", origin, "issuer.test", "origin.test",
                            f"127.0.0.1:{origin_port}"]),
            ):
                with (tmp / f"{label}.diagnostic").open("wb") as stream:
                    children.append(subprocess.Popen(
                        [str(binary), *map(str, args)], stdout=stream, stderr=stream))
            phase = "readiness"
            for number in (issuer_port, origin_port):
                for _ in range(100):
                    require(all(c.poll() is None for c in children), "service exited")
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("readiness timeout")
            phase = "wrong truncated key ID"
            malformed = b"\x00\x02" + bytes([(int(key_id[-2:], 16) + 1) % 256]) + bytes(256)
            require(len(malformed) == 259, "request length")
            require(request(issuer_port, "/private-token/issue", {
                "Content-Type": "application/private-token-request",
                "Freebird-Admission": secrets[0].decode(),
            }, malformed) == 422, "wrong-key status mismatch")
            public.append("wrong truncated key ID: 422")
            artifacts = tmp / "artifacts"
            artifacts.mkdir(mode=0o700)
            bases = [f"http://127.0.0.1:{p}" for p in (issuer_port, origin_port)]
            phase = "Node issuance"
            expected(["node", root / "interop/ts/issue.mjs", *bases, invitations[0], artifacts],
                     "@cloudflare/privacypass-ts 0.9.0\ndirectory: 200\nchallenge: 401\n"
                     f"key ID: {key_id}\nissuance: 200\n"
                     "serialization: OK; finalization: OK; private artifacts: OK\n")
            token = (artifacts / "token.bin").read_bytes()
            require(len(token) == 354, "token length")
            encoded = base64.urlsafe_b64encode(token)
            secrets.extend([token, encoded, encoded.rstrip(b"=")])
            phase = "Go verification"
            expected(["go", "run", ".", "verify", artifacts],
                     f"key_id={key_id} verify=ok replay=rejected wrong_challenge=rejected\n",
                     root / "interop/go")
            phase = "Node token redemption"
            require(request(origin_port, "/private-token/protected", {
                "Authorization": 'PrivateToken token="AA=="',
            }) == 401, "malformed token accepted")
            headers = {"Authorization": 'PrivateToken token="' + encoded.decode() + '"'}
            require(request(origin_port, "/private-token/protected", headers) == 200,
                    "redemption status mismatch")
            require(request(origin_port, "/private-token/protected", headers) == 401,
                    "replay status mismatch")
            phase = "Go client"
            expected(["go", "run", ".", "client", *bases, invitations[1]],
                     f"key_id={key_id} issuance=ok redemption=ok replay=rejected\n",
                     root / "interop/go")
            public.extend([f"key ID: {key_id}", "Node issuance: 200; Go verification: OK",
                           "Node redemption: 200; replay: 401",
                           "Go issuance: 200; redemption: 200; replay: 401"])
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            raise RuntimeError(f"interop failed during {phase}; diagnostics suppressed") from None
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
            for child in reversed(children):
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            captured = b"".join(diagnostics)
            for path in tmp.glob("*.diagnostic"):
                captured += path.read_bytes()
            require(not any(secret in captured for secret in secrets),
                    "interop failed: sensitive diagnostics detected; contents suppressed")
    print("\n".join(public))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        # Print a fixed diagnostic because OS and subprocess messages can expose paths or arguments.
        print(str(error) if type(error) is RuntimeError else "interop failed; diagnostics suppressed")
        raise SystemExit(1)
