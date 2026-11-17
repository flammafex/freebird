#!/usr/bin/env python3
"""Cold restore drill. No root/systemd or fault injection; all output is redacted."""
import base64
import http.client
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "target/debug/freebird-privacy-pass-service"
PHASE = "build"
PROCESSES = []


def require(value):
    if not value:
        raise RuntimeError("assertion")


def run(args, expected=0, timeout=120):
    result = subprocess.run([str(x) for x in args], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if expected is None:
        require(result.returncode != 0)
    elif result.returncode != expected:
        raise RuntimeError("subprocess exit " + str(result.returncode))
    return result.stdout


def cli(*args):
    return run([BIN, *args])


def query(path, sql):
    with sqlite3.connect(path) as db:
        return db.execute(sql).fetchall()


def request(port, headers=None, payload=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST" if payload is not None else "GET",
                     "/private-token/issue" if payload is not None else
                     "/private-token/protected", body=payload, headers=headers or {})
        response = conn.getresponse()
        response.read(16384)
        return response.status
    finally:
        conn.close()


def stop():
    for process in PROCESSES:
        if process.poll() is None:
            process.terminate()
    for process in PROCESSES:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    PROCESSES.clear()


def start(issuer, origin):
    ports = []
    for _ in range(2):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
    commands = [
        ["serve-issuer", issuer, "issuer.test",
         "https://issuer.test/private-token/issue", f"127.0.0.1:{ports[0]}"],
        ["serve-origin", origin, "issuer.test", "origin.test",
         f"127.0.0.1:{ports[1]}"],
    ]
    for command, port in zip(commands, ports):
        process = subprocess.Popen([str(BIN), *map(str, command)], cwd=ROOT,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        PROCESSES.append(process)
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise RuntimeError("service exit " + str(process.returncode))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    break
            except OSError:
                require(time.monotonic() < deadline)
                time.sleep(.05)
    return ports


def invitation(issuer, path):
    path.write_bytes(cli("provision", issuer))
    path.chmod(0o600)
    return path


def issue(ports, invite, out):
    out.mkdir(mode=0o700)
    run(["node", ROOT / "interop/ts/issue.mjs",
         f"http://127.0.0.1:{ports[0]}", f"http://127.0.0.1:{ports[1]}",
         invite, out])
    return (out / "token.bin").read_bytes()


def redeem(port, token):
    return request(port, {"Authorization": 'PrivateToken token="' +
                          base64.urlsafe_b64encode(token).decode() + '"'})


def catalog(action, issuer, origin, path, expected=0):
    args = [sys.executable, ROOT / "scripts/recovery-catalog.py", action,
            issuer / "issuer-keys.sqlite", origin / "origin.sqlite", path]
    if expected is None:
        result = subprocess.run(list(map(str, args)), cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120)
        require(result.returncode == 1 and result.stdout == b"" and
                result.stderr == b"recovery catalog operation refused\n")
    else:
        run(args, expected=expected)


def main():
    global PHASE
    os.umask(0o077)
    run(["cargo", "build", "--locked", "-p", "freebird-privacy-pass-service",
         "--bin", "freebird-privacy-pass-service"], timeout=300)
    with tempfile.TemporaryDirectory(prefix="freebird-recovery-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        issuer, origin = root / "issuer", root / "origin"
        PHASE = "initialize"
        cli("init-issuer", issuer)
        key_id = query(issuer / "issuer-keys.sqlite", "SELECT key_id FROM keys")[0][0].hex()
        spki = root / "genesis.der"
        cli("export-issuer-spki", issuer, key_id, spki)
        cli("init-origin", origin, spki, key_id)
        used = invitation(issuer, root / "used.invite")
        spare = invitation(issuer, root / "spare.invite")
        PHASE = "initial issuance"
        ports = start(issuer, origin)
        token = issue(ports, used, root / "initial-token")
        stop()
        PHASE = "cold snapshot and external catalog"
        snapshot_i, snapshot_o = root / "snapshot-i", root / "snapshot-o"
        shutil.copytree(issuer, snapshot_i)
        shutil.copytree(origin, snapshot_o)
        require(any(p.stat().st_size for state in (snapshot_i, snapshot_o)
                    for p in state.glob("*.sqlite-wal")))
        external = root / "external"
        external.mkdir(mode=0o700)
        catalog_path = external / "history.json"
        catalog("record", issuer, origin, catalog_path)
        PHASE = "restart redemption"
        ports = start(issuer, origin)
        require(redeem(ports[1], token) == 200)
        require(redeem(ports[1], token) == 401)
        issue(ports, spare, root / "spare-token")
        stop()
        print("PASS cold snapshot; restart redemption 200 then 401; spare consumed")
        # Each case stages fresh directories; live state is never overwritten.
        for case in ("admission", "origin", "issuer-keys", "full"):
            PHASE = "restore " + case
            stage_i, stage_o = root / (case + "-i"), root / (case + "-o")
            shutil.copytree(issuer, stage_i)
            shutil.copytree(origin, stage_o)
            components = {
                "admission": [(snapshot_i, stage_i, ("admission.sqlite", "generation"))],
                "origin": [(snapshot_o, stage_o, ("origin.sqlite", "context"))],
                "issuer-keys": [(snapshot_i, stage_i, ("issuer-keys.sqlite",))],
                "full": [(snapshot_i, stage_i, None), (snapshot_o, stage_o, None)],
            }[case]
            for source, target, names in components:
                if names is None:
                    shutil.rmtree(target)
                    shutil.copytree(source, target)
                else:
                    for name in names:
                        for old in target.glob(name + "*"):
                            old.unlink()
                        for saved in source.glob(name + "*"):
                            shutil.copy2(saved, target / saved.name)
            catalog("check", stage_i, stage_o, catalog_path)
            before_keys = query(stage_o / "origin.sqlite", "SELECT * FROM origin_keys")
            before_high = query(stage_o / "origin.sqlite", "SELECT high_water FROM metadata")
            history = query(stage_i / "issuer-keys.sqlite", "SELECT * FROM keys ORDER BY key_id")
            cli("recover-issuer-admission", stage_i)
            recovery_floor = int(time.time())
            cli("recover-origin-context", stage_o)
            require(query(stage_o / "origin.sqlite", "SELECT * FROM origin_keys") == before_keys)
            high = query(stage_o / "origin.sqlite", "SELECT high_water FROM metadata")[0][0]
            require(high >= before_high[0][0] and high >= recovery_floor)
            for table in ("challenges", "spent"):
                require(query(stage_o / "origin.sqlite", f"SELECT count(*) FROM {table}") == [(0,)])
            require(query(stage_i / "issuer-keys.sqlite", "SELECT * FROM keys ORDER BY key_id") == history)
            ports = start(stage_i, stage_o)
            valid_request = (root / "initial-token/request.bin").read_bytes()
            require(len(valid_request) == 259)
            for old in (used, spare):
                require(request(ports[0], {
                    "Freebird-Admission": old.read_text().strip(),
                    "Content-Type": "application/private-token-request",
                }, valid_request) == 403)
            require(redeem(ports[1], token) == 401)
            stop()
            ports = start(stage_i, stage_o)
            require(redeem(ports[1], token) == 401)
            stop()
            fresh = invitation(stage_i, root / (case + ".invite"))
            ports = start(stage_i, stage_o)
            new_token = issue(ports, fresh, root / (case + "-token"))
            require(redeem(ports[1], new_token) == 200)
            require(redeem(ports[1], new_token) == 401)
            require(request(ports[0], {
                "Freebird-Admission": fresh.read_text().strip(),
                "Content-Type": "application/private-token-request",
            }, valid_request) == 403)
            stop()
            print("PASS " + case + " restore; catalog first; invalidation; fresh token 200/401")
        PHASE = "stale key history refusal"
        cli("stage-issuer-key", issuer)
        newer = external / "newer.json"
        catalog("record", issuer, origin, newer)
        catalog("check", snapshot_i, snapshot_o, newer, expected=None)
        print("PASS stale issuer key history refused by newer external catalog")
        print("OMITTED wrong/missing context startup and interruption cases; no fault injection")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"FAIL phase={PHASE}; {detail}; diagnostics redacted", file=sys.stderr)
        sys.exit(1)
    finally:
        stop()
