#!/usr/bin/env python3
"""Check dependency pins from an independent consumer, without the root lockfile."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


REVISION = "13f6c4565d2ac0c7a4488eba35933b2ca85ff317"
EXPECTED_SOURCE = f"git+https://github.com/kixel-ai/rind?rev={REVISION}#{REVISION}"


def main():
    crypto = Path(__file__).resolve().parents[1] / "crypto"
    # Respect TMPDIR (including the approved session temp directory on macOS).
    with tempfile.TemporaryDirectory(prefix="freebird-external-consumer-") as temp:
        consumer = Path(temp)
        (consumer / "src").mkdir()
        (consumer / "Cargo.toml").write_text(
            '[package]\nname = "freebird-external-consumer"\n'
            'version = "0.0.0"\nedition = "2021"\n\n'
            '[workspace]\n\n[dependencies]\n'
            f"freebird-crypto = {{ path = {json.dumps(str(crypto))} }}\n",
            encoding="utf-8",
        )
        (consumer / "src/main.rs").write_text(
            "use freebird_crypto::privacy_pass::PublicKey;\n\n"
            "fn main() { let _: Option<PublicKey> = None; }\n",
            encoding="utf-8",
        )
        # Do not inherit a caller's workspace-specific target override.
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        metadata = subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            cwd=consumer, env=env, check=True, capture_output=True, text=True,
        )
        packages = json.loads(metadata.stdout)["packages"]
        for name, field, expected in (
            ("blind-rsa-signatures", "source", EXPECTED_SOURCE),
            ("rsa", "version", "0.10.0"),
        ):
            matches = [package for package in packages if package["name"] == name]
            actual = [package.get(field) for package in matches]
            if not matches or any(value != expected for value in actual):
                raise ValueError(
                    f"{name}: expected {field} {expected!r}, found {actual!r}"
                )
            print(f"{name}: {field} = {expected}", flush=True)
        subprocess.run(
            ["cargo", "check", "--locked"], cwd=consumer, env=env, check=True,
        )
    print("Independent external consumer check passed.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        print(f"External consumer check failed: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError) as error:
        print(f"External consumer check failed: {error}", file=sys.stderr)
        sys.exit(1)
