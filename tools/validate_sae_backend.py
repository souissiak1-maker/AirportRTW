#!/usr/bin/env python3
"""Verify vendored SAE provenance and private crypto symbol isolation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SAE = ROOT / "rtw80211/sae"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--archive", type=Path)
parser.add_argument("--bundle", type=Path)
args = parser.parse_args()
manifest = json.loads((SAE / "UPSTREAM.json").read_text())
for name, digest in manifest["files"].items():
    assert hashlib.sha256((SAE / name).read_bytes()).hexdigest() == digest, name
actual = {str(p.relative_to(SAE)) for p in (SAE / "third_party").rglob("*") if p.is_file()}
assert actual == set(manifest["files"]), "Vendor manifest is incomplete"
assert (SAE / "NOTICE.txt").is_file()
if args.archive:
    output = subprocess.check_output(["nm", "-gU", str(args.archive)], text=True)
    symbols = [line.split()[-1] for line in output.splitlines() if len(line.split()) == 3]
    assert symbols, "Empty SAE archive"
    for symbol in symbols:
        assert symbol.startswith(("_airport_sae_", "_rtw_sae_")), symbol
if args.bundle:
    binary = args.bundle / "Contents/MacOS/AirportRTW"
    output = subprocess.check_output(["nm", "-u", str(binary)], text=True)
    for line in output.splitlines():
        assert not any(s in line for s in ("_airport_sae_", "_rtw_sae_", "_mbedtls_", "_wpabuf_")), line
    assert (args.bundle / "Contents/Resources/NOTICE.txt").is_file()
print("OK: SAE provenance, licenses and requested symbol checks")
