#!/usr/bin/env python3
"""Deterministically add the RTL8852AE backend to every kext source phase."""
from hashlib import sha1
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "itlwm.xcodeproj" / "project.pbxproj"
BACKEND = ROOT / "itlwm" / "hal_rtw89"


def ident(label: str) -> str:
    return sha1(("rtw89:" + label).encode()).hexdigest()[:24].upper()


def main() -> None:
    text = PROJECT.read_text(encoding="utf-8")
    sources = sorted(
        p.relative_to(ROOT).as_posix()
        for p in BACKEND.rglob("*")
        if p.suffix in {".c", ".cpp"}
    )
    refs = []
    for path in sources:
        file_id = ident("file:" + path)
        kind = "sourcecode.cpp.cpp" if path.endswith(".cpp") else "sourcecode.c.c"
        refs.append(
            f"\t\t{file_id} /* {Path(path).name} */ = "
            f"{{isa = PBXFileReference; lastKnownFileType = {kind}; "
            f'path = "{path}"; sourceTree = SOURCE_ROOT; }};'
        )
    marker = "/* End PBXFileReference section */"
    if refs[0] not in text:
        text = text.replace(marker, "\n".join(refs) + "\n" + marker)

    phase_pattern = re.compile(
        r"(\t\t([A-F0-9]{24}) /\* Sources \*/ = \{\n"
        r"\t\t\tisa = PBXSourcesBuildPhase;.*?\n\t\t\tfiles = \(\n)"
        r"(.*?)(\t\t\t\);)", re.S
    )
    phase_ids = [match.group(2) for match in phase_pattern.finditer(text)]
    build_entries = []
    phase_lines = {}
    for phase in phase_ids:
        lines = []
        for path in sources:
            build_id = ident("build:" + phase + ":" + path)
            file_id = ident("file:" + path)
            name = Path(path).name
            standalone = name in {"rtw88_firmware.c", "fw_blobs89.c"}
            flags = (" settings = {COMPILER_FLAGS = \"-DRTW89_MACOS "
                     "-include $(SRCROOT)/rtw/hal_rtw89/compat/rtw89_compat.h\"; };"
                     if path.endswith(".c") and not standalone else "")
            build_entries.append(
                f"\t\t{build_id} /* {name} in Sources */ = "
                f"{{isa = PBXBuildFile; fileRef = {file_id} /* {name} */;{flags} }};"
            )
            lines.append(f"\t\t\t\t{build_id} /* {name} in Sources */,\n")
        phase_lines[phase] = "".join(lines)
    build_marker = "/* End PBXBuildFile section */"
    if build_entries and build_entries[0] not in text:
        text = text.replace(build_marker,
                            "\n".join(build_entries) + "\n" + build_marker)
    else:
        for entry in build_entries:
            build_id = entry.split()[0]
            text = re.sub(rf"^\t\t{build_id} .*?$", entry, text,
                          flags=re.M)

    def add_phase(match: re.Match[str]) -> str:
        lines = phase_lines[match.group(2)]
        if lines.splitlines()[0].strip() in match.group(3):
            lines = ""
        return match.group(1) + lines + match.group(3) + match.group(4)

    text = phase_pattern.sub(add_phase, text)
    old = 'SYSTEM_HEADER_SEARCH_PATHS = "rtw80211/openbsd itl80211 include";'
    new = ('SYSTEM_HEADER_SEARCH_PATHS = "rtw80211/openbsd itl80211 include '
           'rtw/hal_rtw89 rtw/hal_rtw89/compat '
           'rtw/hal_rtw89/driver";')
    text = text.replace(old, new)
    PROJECT.write_text(text, encoding="utf-8", newline="\n")

    for plist in (ROOT / "AirportRTW").glob("*Info.plist"):
        contents = plist.read_text(encoding="utf-8")
        if "0x885210ec" not in contents:
            contents = contents.replace("<string>0x27238086 ",
                                        "<string>0x885210ec 0xa85a10ec 0x27238086 ")
            plist.write_text(contents, encoding="utf-8", newline="\n")
    print(f"wired {len(sources)} sources into {len(phase_ids)} source phases")


if __name__ == "__main__":
    main()
