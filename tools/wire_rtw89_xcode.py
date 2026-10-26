#!/usr/bin/env python3
"""Restore Realtek C++ references; Linux C code stays in the C archive."""
import hashlib
import re
from xcode_project import PROJECT, load_project


def main():
    objects = load_project()["objects"]
    original = PROJECT.read_text(encoding="utf-8")
    text = original
    for name in ["RTWCore.cpp", "Rtw89LinuxBridge.cpp", "Rtw89PciTransport.cpp"]:
        path = "rtw/hal_rtw89/" + name
        candidates = [i for i, o in objects.items() if o["isa"] == "PBXFileReference" and o.get("path") == path]
        if len(candidates) != 1:
            raise RuntimeError(f"Expected one file reference for {path}")
        ref = candidates[0]
        for phase_id, phase in objects.items():
            if phase["isa"] != "PBXSourcesBuildPhase":
                continue
            if any(objects[b].get("fileRef") == ref for b in phase["files"]):
                continue
            ident = hashlib.sha256((phase_id + path).encode()).hexdigest()[:24].upper()
            text = text.replace("/* End PBXBuildFile section */", f"\t\t{ident} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {ref}; }};\n/* End PBXBuildFile section */")
            pattern = r'(' + phase_id + r' /\*[^\n]*\*/ = \{\n.*?files = \()'
            text, count = re.subn(pattern, lambda m: m[1] + f"\n\t\t\t\t{ident} /* {name} in Sources */,", text, count=1, flags=re.S)
            if count != 1:
                raise RuntimeError(f"Cannot update source phase {phase_id}")
    if text != original:
        PROJECT.write_text(text, encoding="utf-8", newline="\n")
    print("OK: Realtek backend source phases wired")


if __name__ == "__main__":
    main()
