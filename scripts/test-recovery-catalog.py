#!/usr/bin/env python3
"""Check that the recovery catalog accepts matching key history and rejects invalid inputs.

The tests use the Python standard library, so they need no extra packages.
"""
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("recovery-catalog.py")


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.issuer = root / "issuer" / "keys.db"
        self.origin = root / "origin" / "state.db"
        self.catalog = root / "external" / "catalog.json"
        for path in (self.issuer, self.origin, self.catalog):
            path.parent.mkdir()
        for path, issuer in ((self.issuer, True), (self.origin, False)):
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE metadata(singleton INTEGER, version INTEGER, high_water INTEGER)")
                db.execute("INSERT INTO metadata VALUES(1,2,100)")
                db.execute("CREATE TABLE " + ("keys(key_id BLOB, spki BLOB, activation_hour INTEGER, pkcs8 BLOB)"
                           if issuer else "origin_keys(key_id BLOB, spki BLOB, activation_hour INTEGER, retired INTEGER)"))
                for n in (1, 2):
                    db.execute("INSERT INTO " + ("keys" if issuer else "origin_keys") +
                               " VALUES(?,?,?,?)", (bytes([n]) * 32, b"public" + bytes([n]),
                                                    n, b"PRIVATE-SECRET" if issuer else 0))

    def cli(self, action, success=True, catalog=None):
        result = subprocess.run([sys.executable, str(SCRIPT), action, str(self.issuer),
                                 str(self.origin), str(catalog or self.catalog)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        if not success:
            self.assertEqual(result.stderr, "recovery catalog operation refused\n")
        return result

    def mutate(self, path, sql):
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(sql)

    def test_roundtrip_permissions_exclusive_and_no_secrets(self):
        self.cli("record")
        self.assertEqual(self.catalog.stat().st_mode & 0o777, 0o600)
        data = self.catalog.read_text()
        self.assertNotIn("PRIVATE", data)
        self.assertNotIn(str(self.issuer), data)
        self.assertEqual(json.loads(data)["format_version"], 1)
        self.cli("check")
        self.cli("record", False)
        self.mutate(self.issuer, "UPDATE metadata SET high_water=0")
        self.cli("check")
        os.chmod(self.catalog, 0o644)
        self.cli("check", False)

    def test_changed_histories(self):
        for path, sql in [
            (self.issuer, "UPDATE keys SET pkcs8=NULL WHERE activation_hour=1"),
            (self.origin, "UPDATE origin_keys SET retired=1 WHERE activation_hour=1"),
            (self.origin, "UPDATE origin_keys SET activation_hour=3 WHERE activation_hour=2"),
            (self.issuer, "DELETE FROM keys WHERE activation_hour=1"),
            (self.origin, "DELETE FROM origin_keys WHERE activation_hour=1"),
        ]:
            with self.subTest(sql=sql):
                self.cli("record")
                self.mutate(path, sql)
                self.cli("check", False)
                self.catalog.unlink()

    def test_outside_directories(self):
        self.cli("record", False, self.issuer.parent / "catalog")
        self.cli("record", False, self.origin.parent / "catalog")
        link = self.catalog.parent / "link"
        link.symlink_to(self.issuer.parent, target_is_directory=True)
        self.cli("record", False, link / "catalog")

    def test_invalid_metadata_and_rows(self):
        for sql in [
            "UPDATE metadata SET version=1",
            "INSERT INTO metadata VALUES(1,2,0)",
            "DELETE FROM metadata",
            "UPDATE keys SET key_id=x'00'",
            "UPDATE keys SET activation_hour=-1",
            "UPDATE keys SET spki='not a blob'",
            "UPDATE keys SET pkcs8='private'",
            "DELETE FROM keys",
        ]:
            with self.subTest(sql=sql):
                with closing(sqlite3.connect(self.issuer)) as db, db:
                    db.execute("SAVEPOINT fixture")
                    db.execute(sql)
                    db.commit()
                self.cli("record", False)
                # Recreate the fixture so that each destructive case starts from intact state.
                self.temp.cleanup()
                self.setUp()

    def test_wal_is_visible(self):
        db = sqlite3.connect(self.issuer)
        self.addCleanup(db.close)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("UPDATE keys SET activation_hour=7 WHERE activation_hour=2")
        db.commit()
        self.cli("record")
        rows = json.loads(self.catalog.read_text())["issuer"]
        self.assertIn(7, [r["activation_hour"] for r in rows])
        self.cli("check")


if __name__ == "__main__":
    unittest.main()
