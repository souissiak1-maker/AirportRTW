"""Read OpenStep project files without requiring Xcode or external packages."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "AirportRTW.xcodeproj/project.pbxproj"


def load_project(path=PROJECT):
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}()=;,]|[^\s{}()=;,"]+', re.S)
    tokens = [m.group() for m in pattern.finditer(text) if not m.group().startswith(("/*", "//"))]
    position = 0

    def take(expected=None):
        nonlocal position
        token = tokens[position]
        position += 1
        if expected is not None and token != expected:
            raise ValueError(f"Expected {expected!r}, got {token!r} at token {position}")
        return token

    def value():
        token = take()
        if token == "{":
            result = {}
            while tokens[position] != "}":
                key = take().strip('"')
                take("=")
                item = value()
                take(";")
                if key in result:
                    raise ValueError(f"Duplicate OpenStep key: {key}")
                result[key] = item
            take("}")
            return result
        if token == "(":
            result = []
            while tokens[position] != ")":
                result.append(value())
                if tokens[position] != ")":
                    take(",")
            take(")")
            return result
        if token.startswith('"'):
            return token[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        return token

    result = value()
    if position != len(tokens):
        raise ValueError("Trailing OpenStep tokens")
    return result


def source_paths(project, target):
    objects = project["objects"]
    paths = []
    for phase_id in target["buildPhases"]:
        phase = objects[phase_id]
        if phase["isa"] != "PBXSourcesBuildPhase":
            continue
        for file_id in phase["files"]:
            build = objects[file_id]
            if "fileRef" in build:
                paths.append(objects[build["fileRef"]]["path"])
    return paths
