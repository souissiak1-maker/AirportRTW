#!/usr/bin/env python3
"""Offline integrity checks for the RTL8852AE kext backend."""
from pathlib import Path
import hashlib
import re
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "itlwm" / "hal_rtw89"
PROJECT = ROOT / "itlwm.xcodeproj" / "project.pbxproj"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    project = PROJECT.read_text(encoding="utf-8")
    sources = sorted(p.relative_to(ROOT).as_posix() for p in BACKEND.rglob("*")
                     if p.suffix in {".c", ".cpp"})
    phases = len(re.findall(r"isa = PBXSourcesBuildPhase;", project))
    require(phases > 0, "no Xcode source phases found")
    for source in sources:
        name = Path(source).name
        require(project.count(f'path = "{source}";') == 1,
                f"missing or duplicate file reference: {source}")
        require(project.count(f"/* {name} in Sources */," ) == phases,
                f"{name} is not in all {phases} source phases")

    driver_c = [p for p in sources if p.endswith(".c") and
                Path(p).name not in {"rtw88_firmware.c", "fw_blobs89.c"}]
    require(project.count("-include $(SRCROOT)/rtw/hal_rtw89/compat/rtw89_compat.h")
            == len(driver_c) * phases, "incorrect rtw89 C prefix-header coverage")
    require(project.count("{") == project.count("}"), "unbalanced Xcode braces")
    require(project.count("(") == project.count(")"), "unbalanced Xcode lists")

    blob_source = (BACKEND / "compat" / "fw_blobs89.c").read_text()
    body = blob_source.split("fw_rtw8852a_fw_bin[] = {", 1)[1].split("};", 1)[0]
    compressed = bytes(int(value, 16) for value in
                       re.findall(r"0x([0-9a-fA-F]{2})", body))
    decoded = zlib.decompress(compressed)
    firmware = (BACKEND / "firmware" / "rtw8852a_fw.bin").read_bytes()
    require(decoded == firmware, "embedded RTL8852A firmware does not match input")

    for plist in [ROOT / "itlwm" / "Info.plist",
                  *sorted((ROOT / "AirportRTW").glob("*Info.plist"))]:
        contents = plist.read_text(encoding="utf-8")
        require("0x885210ec" in contents and "0xa85a10ec" in contents,
                f"RTL8852AE PCI IDs missing from {plist.relative_to(ROOT)}")

    print(f"OK: {len(sources)} sources x {phases} phases; "
          f"firmware {len(firmware)} bytes, sha256={hashlib.sha256(firmware).hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
