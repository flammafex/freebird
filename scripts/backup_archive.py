#!/usr/bin/env python3
"""The deliberately boring, standard-library part of the backup protocol.

Shell is an orchestrator, not a parser.  In particular, this file is the only
place which interprets JSON or tar members.  Every command is a closed,
machine-readable operation; there is no command execution hook here.
"""
import argparse, base64, datetime, hashlib, json, os, re, shutil, stat, sys, tarfile, tempfile
from pathlib import Path
from typing import NoReturn

SCHEMA = "freebird-backup-manifest/v2"
STATE_SCHEMA = "freebird-operator-state/v2"
JOURNAL_SCHEMA = "freebird-rollback/v1"
MAX_FILE = 1 << 30
MAX_ARCHIVE = 4 << 30
MAX_MEMBERS = 100_000
MAX_DIRECTORIES = 10_000
MAX_PATH = 4096
MAX_METADATA = 1 << 20
HEX = re.compile(r"[0-9a-f]{64}\Z")

def die(msg: str) -> NoReturn:
    raise SystemExit(msg)

def canon(v) -> str:
    return json.dumps(v, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"

def read_json(path, keys):
    try:
        raw = Path(path).read_bytes()
        def pairs(items):
            d = {}
            for k, v in items:
                if k in d: die("duplicate JSON key")
                d[k] = v
            return d
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        die(f"invalid protected record: {exc}")
    if not isinstance(value, dict) or set(value) != set(keys) or raw != canon(value).encode("ascii"):
        die("non-canonical closed-schema JSON record")
    return value

def atomic(path, text):
    path = Path(path); path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".freebird-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600); os.write(fd, text.encode("ascii")); os.fsync(fd); os.close(fd)
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_RDONLY); os.fsync(d); os.close(d)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def state(a):
    root = Path(a.state); counter, accepted, journal = (root/x for x in ("counter.json", "accepted.json", "rollback.json"))
    if a.action == "init":
        if any(x.exists() for x in (counter, accepted, journal)): die("state already exists; refusing reinitialization")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700: die("operator state ownership/mode is unsafe")
        atomic(counter, canon({"counter": 0, "high_water_generation": 0})); atomic(accepted, canon({"generation": 0, "archive_sha256": "none"}))
        atomic(journal, canon({"schema": JOURNAL_SCHEMA, "entries": []})); return
    if not all(x.is_file() for x in (counter, accepted, journal)): die("missing or partial protected state")
    if root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700: die("operator state ownership/mode is unsafe")
    for record in (counter, accepted, journal):
        if record.stat().st_uid != os.getuid() or stat.S_IMODE(record.stat().st_mode) != 0o600: die("operator record ownership/mode is unsafe")
    c = read_json(counter, {"counter", "high_water_generation"}); ac = read_json(accepted, {"generation", "archive_sha256"}); j = read_json(journal, {"schema", "entries"})
    if type(c["counter"]) is not int or c["counter"] < 0 or type(c["high_water_generation"]) is not int or c["high_water_generation"] < 0 or c["high_water_generation"] > c["counter"] or type(ac["generation"]) is not int or ac["generation"] < 0 or ac["generation"] > c["high_water_generation"]: die("invalid protected generation state")
    if ac["generation"] == 0 and ac["archive_sha256"] != "none": die("invalid accepted state")
    if ac["generation"] and (not isinstance(ac["archive_sha256"], str) or not HEX.fullmatch(ac["archive_sha256"])): die("invalid accepted digest")
    if j["schema"] != JOURNAL_SCHEMA or not isinstance(j["entries"], list): die("invalid rollback journal")
    for entry in j["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"archive_sha256","generation","reason_b64","timestamp_utc"} or type(entry["generation"]) is not int or not HEX.fullmatch(entry["archive_sha256"]) or not isinstance(entry["reason_b64"], str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", entry["timestamp_utc"]): die("invalid rollback journal entry")
    if a.action == "next":
        n = c["counter"] + 1; atomic(counter, canon({"counter": n, "high_water_generation": n})); print(n)
    elif a.action == "check": print(ac["generation"])
    elif a.action == "high-water": print(c["high_water_generation"])
    elif a.action == "accept":
        if a.generation < 1 or a.generation > c["high_water_generation"] or not HEX.fullmatch(a.digest or ""): die("invalid accepted archive")
        atomic(accepted, canon({"generation": a.generation, "archive_sha256": a.digest}))
    elif a.action == "rollback":
        if a.generation < 1 or a.generation > c["high_water_generation"] or not HEX.fullmatch(a.digest or "") or not a.reason or any(ord(x) < 32 for x in a.reason): die("invalid rollback record")
        j["entries"].append({"archive_sha256": a.digest, "generation": a.generation, "reason_b64": base64.b64encode(a.reason.encode()).decode(), "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")})
        atomic(journal, canon(j))

def inventory(root):
    root = Path(root); out = []
    if not root.is_dir(): die("missing payload")
    for p in sorted(root.rglob("*"), key=lambda x: x.relative_to(root).as_posix()):
        rel = p.relative_to(root).as_posix(); s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or not (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)): die("source contains link, device, or non-file")
        mode = stat.S_IMODE(s.st_mode)
        if stat.S_ISDIR(s.st_mode):
            out.append({"kind":"dir", "mode":mode, "path":rel, "sha256":"dir", "size":0}); continue
        if s.st_size > MAX_FILE: die("file capacity exceeded")
        h = hashlib.sha256();
        with p.open("rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
        out.append({"kind":"file", "mode": mode, "path": rel, "sha256": h.hexdigest(), "size": s.st_size})
    return out

def identity(root):
    """Return a stable identity derived from all captured volume files."""
    h = None
    for p in sorted(Path(root).rglob("*"), key=lambda x: x.relative_to(root).as_posix()):
        if p.is_symlink() or not p.is_file(): continue
        if h is None: h = hashlib.sha256()
        name = p.relative_to(root).as_posix()
        h.update(name.encode()); h.update(b"\0")
        file_hash = hashlib.sha256()
        with p.open("rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""): file_hash.update(b)
        h.update(file_hash.digest())
    if h is None: die("captured volume identity material is missing")
    print(h.hexdigest())

MANIFEST_KEYS = {"created_utc", "format", "generation", "inventory", "issuer_key_id", "redis_lastsave", "redis_volume"}
ITEM_KEYS = {"kind", "mode", "path", "sha256", "size"}
def make_manifest(a):
    obj = {"created_utc": a.created, "format": SCHEMA, "generation": a.generation, "inventory": inventory(Path(a.root)/"payload"), "issuer_key_id": a.issuer_key_id, "redis_lastsave": a.redis_lastsave, "redis_volume": a.redis_volume}
    atomic(Path(a.root)/"MANIFEST.json", canon(obj)); print(canon(obj), end="")

def check(root, announce=True, expected_issuer_key_id=None):
    obj = read_json(Path(root)/"MANIFEST.json", MANIFEST_KEYS)
    if obj["format"] != SCHEMA or type(obj["generation"]) is not int or obj["generation"] < 1 or not isinstance(obj["inventory"], list): die("invalid manifest")
    if not isinstance(obj["created_utc"], str) or not isinstance(obj["issuer_key_id"], str) or not isinstance(obj["redis_volume"], str) or not isinstance(obj["redis_lastsave"], str): die("invalid manifest fields")
    if expected_issuer_key_id is not None and obj["issuer_key_id"] != expected_issuer_key_id: die("issuer key identity mismatch")
    seen = set()
    for i in obj["inventory"]:
        if not isinstance(i, dict) or set(i) != ITEM_KEYS or i["kind"] not in ("file","dir") or type(i["mode"]) is not int or not 0 <= i["mode"] <= 0o777 or type(i["size"]) is not int or i["size"] < 0 or not isinstance(i["path"], str) or i["path"].startswith("/") or ".." in Path(i["path"]).parts or i["path"] in seen or (i["kind"] == "file" and not HEX.fullmatch(i["sha256"])) or (i["kind"] == "dir" and (i["sha256"] != "dir" or i["size"] != 0)): die("invalid manifest inventory")
        seen.add(i["path"])
    actual = inventory(Path(root)/"payload")
    if obj["inventory"] != actual: die("manifest inventory/hash/mode mismatch")
    if announce: print(obj["generation"])

def verify_tree(root, manifest, prefix=None):
    """Verify a restored volume's content and modes against its manifest.

    Ownership is intentionally not part of this comparison: restore applies a
    fixed destination ownership policy after this exact content/mode check.
    """
    obj = read_json(manifest, MANIFEST_KEYS)
    actual = inventory(root)
    expected = obj["inventory"]
    if prefix:
        marker = prefix.rstrip("/") + "/"
        expected = [dict(item, path=item["path"][len(marker):]) for item in expected if item["path"].startswith(marker)]
    if expected != actual:
        die("restored tree content/mode mismatch")

def member_ok(m, seen, total, directories):
    n = m.name
    if len(n) > MAX_PATH or len(seen) >= MAX_MEMBERS: die("archive member/path limit exceeded")
    if len(json.dumps(getattr(m, "pax_headers", {}), ensure_ascii=True)) > MAX_METADATA: die("archive metadata limit exceeded")
    if n in seen or n.startswith("/") or ".." in Path(n).parts or "\\" in n: die("unsafe duplicate/path archive entry")
    if m.issym() or m.islnk() or m.isdev() or not (m.isfile() or m.isdir()) or stat.S_IMODE(m.mode) != m.mode & 0o777: die("unsafe tar entry")
    if m.isdir() and directories >= MAX_DIRECTORIES: die("archive directory limit exceeded")
    if m.size > MAX_FILE or total + m.size > MAX_ARCHIVE: die("archive capacity exceeded")
    seen.add(n); return total + m.size

def pack(a):
    root = Path(a.root); check(root, announce=False); seen = set(); total = 0
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as t:
        paths = [root/"MANIFEST.json", root/"MANIFEST.json.minisig", root/"payload"]
        directories = 0
        for p in paths:
            seq = [p] if p.is_file() else [p] + sorted(p.rglob("*"), key=lambda x: x.relative_to(root).as_posix())
            for q in seq:
                name = q.relative_to(root).as_posix(); info = t.gettarinfo(str(q), arcname=name); total = member_ok(info, seen, total, directories); directories += int(info.isdir())
                info.mtime = 0
                with q.open("rb") if q.is_file() else tempfile.TemporaryFile() as f:
                    t.addfile(info, f if q.is_file() else None)
    if {"MANIFEST.json", "MANIFEST.json.minisig", "payload"} - seen or any(not (x in ("MANIFEST.json","MANIFEST.json.minisig","payload") or x.startswith("payload/")) for x in seen): die("archive structure incomplete")

def extract(a):
    dest = Path(a.dest).resolve()
    if dest.exists(): die("destination must not exist")
    dest.mkdir(mode=0o700, parents=True); seen = set(); total = 0; directory_modes = []
    try:
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
            for m in t:
                total = member_ok(m, seen, total, len(directory_modes)); target = (dest/m.name).resolve()
                if dest not in target.parents: die("archive traversal")
                if m.isdir(): target.mkdir(mode=0o700, parents=True, exist_ok=False); directory_modes.append((target, stat.S_IMODE(m.mode)))
                else:
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True); src = t.extractfile(m)
                    if src is None: die("missing tar payload")
                    fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as out:
                        shutil.copyfileobj(src, out); out.flush(); os.fsync(out.fileno())
                    os.chmod(target, stat.S_IMODE(m.mode))
        if {"MANIFEST.json", "MANIFEST.json.minisig", "payload"} - seen or any(not (x in ("MANIFEST.json","MANIFEST.json.minisig","payload") or x.startswith("payload/")) for x in seen): die("archive structure incomplete")
        for directory, mode in directory_modes: os.chmod(directory, mode)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True); raise

def main():
    p = argparse.ArgumentParser(); s = p.add_subparsers(dest="cmd", required=True)
    x=s.add_parser("state"); x.add_argument("action", choices=["init","next","accept","rollback","check","high-water"]); x.add_argument("--state",required=True); x.add_argument("--generation",type=int); x.add_argument("--digest"); x.add_argument("--reason",default=""); x.set_defaults(fn=state)
    x=s.add_parser("manifest"); x.add_argument("--root",required=True); x.add_argument("--generation",type=int,required=True); x.add_argument("--created",required=True); x.add_argument("--issuer-key-id",required=True); x.add_argument("--redis-volume",required=True); x.add_argument("--redis-lastsave",required=True); x.set_defaults(fn=make_manifest)
    x=s.add_parser("check"); x.add_argument("--root",required=True); x.add_argument("--expected-issuer-key-id"); x.set_defaults(fn=lambda a: check(a.root, expected_issuer_key_id=a.expected_issuer_key_id))
    x=s.add_parser("identity"); x.add_argument("--root",required=True); x.set_defaults(fn=lambda a: identity(a.root))
    for cmd, fn in (("pack",pack),("extract",extract)):
        x=s.add_parser(cmd); x.add_argument("--root" if cmd=="pack" else "--dest",required=True); x.set_defaults(fn=fn)
    x=s.add_parser("verify-tree"); x.add_argument("--root",required=True); x.add_argument("--manifest",required=True); x.add_argument("--prefix"); x.set_defaults(fn=lambda a: verify_tree(a.root, a.manifest, a.prefix))
    a=p.parse_args(); a.fn(a)
if __name__ == "__main__": main()
