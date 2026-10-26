#!/usr/bin/env python3
"""Check target isolation, Realtek matching, archive inputs and firmware."""
from pathlib import Path
import plistlib
import re
import sys
import xml.etree.ElementTree as ET
import zlib
from xcode_project import ROOT, load_project, source_paths


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    project = load_project()
    objects = project["objects"]
    # Resolve file references through group paths, including renamed sources.
    resolved = {}
    def visit(ident, parent):
        obj = objects[ident]
        base = ROOT if obj.get("sourceTree") == "SOURCE_ROOT" else parent
        path = base / obj.get("path", "")
        if obj["isa"] == "PBXGroup":
            for child in obj.get("children", []):
                visit(child, path)
        elif obj["isa"] == "PBXFileReference" and obj.get("sourceTree") != "BUILT_PRODUCTS_DIR":
            resolved[ident] = path
    visit(objects[project["rootObject"]]["mainGroup"], ROOT)
    targets = {o["name"]: o for o in objects.values() if o["isa"] == "PBXNativeTarget"}
    names = ["High Sierra", "Mojave", "Catalina", "Big Sur", "Monterey", "Ventura", "Sonoma14.0", "Sonoma14.4", "Sequoia", "Tahoe"]
    for os_name in names:
        name = "AirportRTW-" + os_name
        require(name in targets, f"Missing target {name}")
        target = targets[name]
        modern = os_name in {"Sequoia", "Tahoe"}
        sources = source_paths(project, target)
        for backend in ["RTWCore.cpp", "RTWCore89.cpp", "Rtw89LinuxBridge.cpp", "Rtw89PciTransport.cpp"]:
            require(sum(Path(s).name == backend for s in sources) == 1, f"{name}: missing/duplicate {backend}")
        for backend in ["RTWCore88.cpp", "Rtw88LinuxBridge.cpp", "Rtw88PciTransport.cpp"]:
            require(sum(Path(s).name == backend for s in sources) == 1, f"{name}: missing/duplicate RTW88 {backend}")
        require(("AirportRTW/WCL/WCL.cpp" in sources) == modern, f"{name}: WCL source isolation")
        for frontend in ["AirportRTWV2.cpp", "AirportRTWSkywalkInterface.cpp"]:
            if modern:
                require("AirportRTW/WCL/" + frontend in sources and frontend not in sources, f"{name}: frontends mixed")
        if not modern:
            require(not any("/WCL/" in s for s in sources), f"{name}: modern source in old target")
        phases = [objects[p] for p in target["buildPhases"]]
        for phase in phases:
            if phase["isa"] != "PBXSourcesBuildPhase":
                continue
            for build_id in phase["files"]:
                ref = objects[build_id].get("fileRef")
                if ref and ref in resolved:
                    source = resolved[ref]
                    require(source.is_file() or source.name == "FwBinary.cpp", f"{name}: missing source {source}")
        archive_phases = [p for p in phases if "build_rtw89_c_archive.sh" in p.get("shellScript", "")]
        require(archive_phases, f"{name}: no C archive phase")
        for phase in archive_phases:
            require(str(phase.get("alwaysOutOfDate")) == "1",
                    f"{name}: C archive may reuse stale driver sources")
        for config_id in objects[target["buildConfigurationList"]]["buildConfigurations"]:
            settings = objects[config_id]["buildSettings"]
            require("rtw80211/openbsd" in str(settings.get("HEADER_SEARCH_PATHS", "")),
                    f"{name}: project headers must participate in dependency tracking")
            definitions = settings.get("GCC_PREPROCESSOR_DEFINITIONS", [])
            require(("AIRPORT_WCL" in definitions) == modern, f"{name}: incorrect WCL flag")
            require("librtw89_c.a" in str(settings.get("OTHER_LDFLAGS", [])), f"{name}: archive not linked")
            plist = plistlib.loads((ROOT / settings["INFOPLIST_FILE"]).read_bytes())
            matches = [p["IOPCIMatch"] for p in plist["IOKitPersonalities"].values() if "IOPCIMatch" in p]
            require(any("0x885210ec" in m and "0xa85a10ec" in m for m in matches), f"{name}: missing Realtek matches")
            require(all(all(i.lower().endswith("10ec") for i in m.split()) for m in matches), f"{name}: non-Realtek IDs")
            if modern:
                require("com.apple.iokit.IO80211FamilyLegacy" not in plist["OSBundleLibraries"], f"{name}: legacy dependency")
                abi = "__MAC_15_2" if os_name == "Sequoia" else "__MAC_26_0"
                require("__IO80211_TARGET=" + abi in definitions, f"{name}: wrong ABI")
    for path in (ROOT / "AirportRTW.xcodeproj/xcshareddata/xcschemes").glob("*.xcscheme"):
        for ref in ET.parse(path).iter("BuildableReference"):
            require(ref.attrib["ReferencedContainer"] == "container:AirportRTW.xcodeproj", f"{path.name}: stale container")
            require(ref.attrib["BlueprintIdentifier"] in objects, f"{path.name}: missing target")
    script = (ROOT / "scripts/build_rtw89_c_archive.sh").read_text()
    driver = ROOT / "rtw/hal_rtw89/driver"
    listed = re.search(r'for file in \\\n(.*?)\ndo', script, re.S)[1]
    for name in re.findall(r'[\w]+\.c', listed) + ["Senmiko.c"]:
        require((driver / name).is_file(), f"Missing archive input {name}")
    blobs = (ROOT / "rtw/hal_rtw89/compat/fw_blobs89.c").read_text()
    firmware_count = 0
    for symbol, body in re.findall(r'(fw_\w+)\[\]\s*=\s*\{(.*?)\};', blobs, re.S):
        compressed = bytes(int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]{2})', body))
        if not compressed:
            continue
        decoded = zlib.decompress(compressed)
        candidates = [p for p in (ROOT / "rtw/hal_rtw89/firmware").rglob("*.bin") if "fw_" + re.sub(r'[^a-zA-Z0-9]', '_', p.name) == symbol]
        require(len(candidates) == 1, f"Cannot resolve firmware {symbol}")
        require(decoded == candidates[0].read_bytes(), f"Firmware mismatch: {symbol}")
        firmware_count += 1
    require(firmware_count > 0, "No firmware verified")
    classes = []
    for path in (ROOT / "rtw").rglob("*.hpp"):
        if re.search(r'\bclass RTWCore\s*:', path.read_text(encoding="utf-8")):
            classes.append(path)
    require(len(classes) == 1, "RTWCore HAL name collides with another class")
    for family in ['88', '89']:
        header = (ROOT / f"rtw/hal_rtw{family}/RTWCore{family}.hpp").read_text()
        require(f'class RTWCore{family} : public RTWCore' in header,
                f'RTW{family} must inherit the shared Realtek HAL')
    shared = (ROOT / 'rtw/RTWCore.hpp').read_text()
    require('hal_rtw88/' not in shared and 'hal_rtw89/' not in shared,
            'Shared RTWCore must not depend on concrete hardware backends')
    print(f"OK: {len(names)} OS targets; frontend isolation; schemes; archive inputs; {firmware_count} firmware blobs")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
