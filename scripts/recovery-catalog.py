#!/usr/bin/env python3
"""Operator-controlled key-history catalog for stopped, single-host restores.

Usage: recovery-catalog.py {record,check} ISSUER_STATE ORIGIN_STATE CATALOG
State arguments are SQLite database files. Stop both services first.
Keep the newest catalog OUTSIDE any VPS/state snapshot restore scope (not merely
outside the state directories). This is NOT automatic rollback detection: an old
catalog restored with old state defeats the check. After a successful check,
perform the separate explicit restore-context invalidation before restarting.
Never resets or regenerates keys. High-water/context/generation are not compared.
"""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys


MAX_HOUR = ((1 << 63) - 1 - 300) // 3600


def require(condition):
    if not condition:
        raise ValueError("invalid recovery input")


def integer(value, maximum=(1 << 63) - 1):
    require(type(value) is int and 0 <= value <= maximum)


def blob(value, length=None):
    require(type(value) is bytes)
    require(len(value) == length if length is not None else 0 < len(value) <= 65536)


def history(path, issuer):
    # mode=ro, not immutable=1: committed WAL contents must remain visible.
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("BEGIN")
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)])
        metadata = connection.execute(
            "SELECT singleton, version, high_water FROM metadata"
        ).fetchall()
        require(len(metadata) == 1)
        singleton, version, high_water = metadata[0]
        require(type(singleton) is int and singleton == 1)
        require(type(version) is int and version == 2)
        integer(high_water)
        query = ("SELECT key_id, spki, activation_hour, "
                 "typeof(pkcs8), length(pkcs8) FROM keys" if issuer else
                 "SELECT key_id, spki, activation_hour, retired FROM origin_keys")
        rows = connection.execute(query).fetchall()
        require(bool(rows))
        result, ids, hours = [], set(), set()
        for row in rows:
            key_id, spki, hour = row[:3]
            blob(key_id, 32)
            blob(spki)
            require(key_id not in ids)
            ids.add(key_id)
            if hour is not None:
                integer(hour, MAX_HOUR)
                require(hour not in hours)
                hours.add(hour)
            entry = dict(key_id=key_id.hex(),
                         spki_sha256=hashlib.sha256(spki).hexdigest(),
                         activation_hour=hour)
            if issuer:
                kind, size = row[3:]
                require(kind == "null" or
                        (kind == "blob" and type(size) is int and 0 < size <= 65536))
                require(kind != "null" or hour is not None)
                entry["has_private"] = kind != "null"
            else:
                require(hour is not None)
                require(type(row[3]) is int and row[3] in (0, 1))
                entry["retired"] = bool(row[3])
            result.append(entry)
        require(sum(r["activation_hour"] is None for r in result) <= 1)
        return sorted(result, key=lambda row: row["key_id"])
    finally:
        connection.close()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def run(action, issuer, origin, catalog):
    require(action in ("record", "check"))
    issuer, origin = Path(issuer).resolve(strict=True), Path(origin).resolve(strict=True)
    catalog = Path(catalog).resolve()
    require(issuer.is_file() and origin.is_file() and issuer != origin)
    for state in (issuer, origin):
        require(not catalog.is_relative_to(state.parent))
    expected = dict(format_version=1, issuer=history(issuer, True),
                    origin=history(origin, False))
    if action == "record":
        data = (json.dumps(expected, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(catalog, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    else:
        with catalog.open("rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600)
            data = source.read(16 * 1024 * 1024 + 1)
        require(len(data) <= 16 * 1024 * 1024)
        actual = json.loads(data, object_pairs_hook=no_duplicates)
        # Canonical JSON comparison also distinguishes booleans from integers.
        require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True))


def main():
    try:
        require(len(sys.argv) == 5)
        run(*sys.argv[1:])
    except Exception:
        print("recovery catalog operation refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
