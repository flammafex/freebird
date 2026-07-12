#!/usr/bin/env python3
"""Behavioural, no-external-dependency tests for the archive primitive."""
import io, json, os, subprocess, sys, tarfile, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts" / "backup_archive.py"
def run(*args): return subprocess.run([sys.executable, str(HELPER), *args], text=True, capture_output=True)
class BackupArchiveTests(unittest.TestCase):
    def test_state_monotonic_and_partial_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run("state","init","--state",d).returncode, 0)
            self.assertEqual(run("state","next","--state",d).stdout.strip(), "1")
            self.assertNotEqual(run("state","init","--state",d).returncode, 0)
            (Path(d)/"counter.json").unlink()
            self.assertNotEqual(run("state","check","--state",d).returncode, 0)
    def test_duplicate_json_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/"counter.json").write_text('{"counter":0,"counter":1}\n')
            self.assertNotEqual(run("state","check","--state",d).returncode, 0)
    def test_accepted_generation_invariant_and_timestamped_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run("state","init","--state",d).returncode,0)
            self.assertEqual(run("state","next","--state",d).returncode,0)
            digest="a"*64
            self.assertEqual(run("state","rollback","--state",d,"--generation","1","--digest",digest,"--reason","operator test").returncode,0)
            record=json.loads((Path(d)/"rollback.json").read_text()); self.assertRegex(record["entries"][0]["timestamp_utc"],r"^20.*Z$"); self.assertEqual(json.loads((Path(d)/"counter.json").read_text())["high_water_generation"],1)
            self.assertNotEqual(run("state","accept","--state",d,"--generation","2","--digest",digest).returncode,0)
    def test_high_water_is_distinct_and_never_decreases(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run("state", "init", "--state", d).returncode, 0)
            for expected in ("1", "2", "3"):
                self.assertEqual(run("state", "next", "--state", d).stdout.strip(), expected)
            digest = "b" * 64
            self.assertEqual(run("state", "accept", "--state", d, "--generation", "1", "--digest", digest).returncode, 0)
            self.assertEqual(run("state", "rollback", "--state", d, "--generation", "1", "--digest", digest, "--reason", "recovery").returncode, 0)
            self.assertEqual(run("state", "high-water", "--state", d).stdout.strip(), "3")
    def test_pack_extract_and_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"root"; (root/"payload").mkdir(parents=True); (root/"payload"/"key").write_bytes(b"secret")
            args=("manifest","--root",str(root),"--generation","1","--created","2026-01-01T00:00:00Z","--issuer-key-id","kid","--redis-volume","redis","--redis-lastsave","1")
            self.assertEqual(run(*args).returncode, 0); (root/"MANIFEST.json.minisig").write_bytes(b"signature")
            packed=subprocess.run([sys.executable,str(HELPER),"pack","--root",str(root)],capture_output=True)
            self.assertEqual(packed.returncode,0); dest=Path(d)/"out"
            extracted=subprocess.run([sys.executable,str(HELPER),"extract","--dest",str(dest)],input=packed.stdout,capture_output=True)
            self.assertEqual(extracted.returncode,0); self.assertEqual((dest/"payload"/"key").read_bytes(),b"secret"); self.assertEqual(run("check","--root",str(dest)).returncode,0)
    def test_nested_directory_modes_and_closed_root(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"root"; nested=root/"payload"/"a"/"b"; nested.mkdir(parents=True); os.chmod(root/"payload"/"a",0o751); os.chmod(nested,0o711); (nested/"x").write_text("x")
            self.assertEqual(run("manifest","--root",str(root),"--generation","1","--created","x","--issuer-key-id","i","--redis-volume","v","--redis-lastsave","1").returncode,0); (root/"MANIFEST.json.minisig").write_text("s")
            p=subprocess.run([sys.executable,str(HELPER),"pack","--root",str(root)],capture_output=True); self.assertEqual(p.returncode,0)
            out=Path(d)/"out"; self.assertEqual(subprocess.run([sys.executable,str(HELPER),"extract","--dest",str(out)],input=p.stdout,capture_output=True).returncode,0); self.assertEqual((out/"payload"/"a").stat().st_mode&0o777,0o751); self.assertEqual((out/"payload"/"a"/"b").stat().st_mode&0o777,0o711)
            self.assertEqual(run("verify-tree","--root",str(out/"payload"),"--manifest",str(out/"MANIFEST.json")).returncode,0)
            os.chmod(out/"payload"/"a",0o700)
            self.assertNotEqual(run("verify-tree","--root",str(out/"payload"),"--manifest",str(out/"MANIFEST.json")).returncode,0)
            bad=io.BytesIO();
            with tarfile.open(fileobj=bad,mode="w") as t:
                for n in ("MANIFEST.json","MANIFEST.json.minisig","payload","unexpected"):
                    m=tarfile.TarInfo(n); m.type=tarfile.DIRTYPE if n=="payload" else tarfile.REGTYPE; m.size=0; t.addfile(m,io.BytesIO())
            self.assertNotEqual(subprocess.run([sys.executable,str(HELPER),"extract","--dest",str(Path(d)/"bad")],input=bad.getvalue(),capture_output=True).returncode,0)
    def test_zero_mode_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                for name, kind in (("MANIFEST.json", tarfile.REGTYPE), ("MANIFEST.json.minisig", tarfile.REGTYPE), ("payload", tarfile.DIRTYPE), ("payload/zero", tarfile.REGTYPE)):
                    member = tarfile.TarInfo(name); member.type = kind; member.mode = 0 if name == "payload/zero" else 0o700
                    if kind == tarfile.REGTYPE:
                        data = b"{}\n" if name == "MANIFEST.json" else (b"s" if name.endswith("minisig") else b"x"); member.size = len(data); tar.addfile(member, io.BytesIO(data))
                    else: tar.addfile(member)
            out = Path(d) / "out"; self.assertEqual(subprocess.run([sys.executable, str(HELPER), "extract", "--dest", str(out)], input=archive.getvalue(), capture_output=True).returncode, 0)
            self.assertEqual((out / "payload" / "zero").stat().st_mode & 0o777, 0)
    def test_member_count_bound(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"; (root / "payload").mkdir(parents=True)
            for i in range(100001): (root / "payload" / str(i)).touch()
            self.assertEqual(run("manifest", "--root", str(root), "--generation", "1", "--created", "x", "--issuer-key-id", "i", "--redis-volume", "v", "--redis-lastsave", "1").returncode, 0)
            (root / "MANIFEST.json.minisig").write_text("s")
            self.assertNotEqual(subprocess.run([sys.executable, str(HELPER), "pack", "--root", str(root)], capture_output=True).returncode, 0)
    def test_capacity_limit_is_checked_before_writing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"root"; (root/"payload").mkdir(parents=True); (root/"payload"/"huge").touch(); os.truncate(root/"payload"/"huge",(1<<30)+1)
            self.assertNotEqual(run("manifest","--root",str(root),"--generation","1","--created","x","--issuer-key-id","i","--redis-volume","v","--redis-lastsave","1").returncode,0)
    def test_tar_attacks_rejected(self):
        for name in ("../escape","link"):
            out=io.BytesIO()
            with tarfile.open(fileobj=out,mode="w") as tar:
                m=tarfile.TarInfo(name); m.type=tarfile.SYMTYPE if name=="link" else tarfile.REGTYPE; m.linkname="/etc/passwd"; tar.addfile(m)
            with tempfile.TemporaryDirectory() as d:
                r=subprocess.run([sys.executable,str(HELPER),"extract","--dest",str(Path(d)/"out")],input=out.getvalue(),capture_output=True); self.assertNotEqual(r.returncode,0)
if __name__ == "__main__": unittest.main()
