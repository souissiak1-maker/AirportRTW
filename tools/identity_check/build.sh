#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
app="$root/build/experiments/identity-check/AirportRTW Identity Check.app"
mkdir -p "$app/Contents/MacOS"
xcrun swiftc -O -target x86_64-apple-macos12.0 -framework AppKit -framework CoreLocation -framework CoreWLAN "$root/tools/identity_check/main.swift" -o "$app/Contents/MacOS/IdentityCheck"
python3 - "$app" <<'PY'
import pathlib,plistlib,sys
p=pathlib.Path(sys.argv[1])/'Contents/Info.plist'
p.write_bytes(plistlib.dumps({
 'CFBundleIdentifier':'com.senmiko.AirportRTW.IdentityCheck',
 'CFBundleName':'AirportRTW Identity Check','CFBundleExecutable':'IdentityCheck',
 'CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'1.0',
 'LSMinimumSystemVersion':'12.0',
 'NSLocationUsageDescription':'Read the current Wi-Fi SSID, BSSID and country locally to diagnose macOS identity reporting.',
 'NSLocationWhenInUseUsageDescription':'Read the current Wi-Fi SSID, BSSID and country locally to diagnose macOS identity reporting.'}))
PY
codesign --force --sign - --identifier com.senmiko.AirportRTW.IdentityCheck "$app"
codesign --verify --strict "$app"
/usr/bin/ditto -c -k --keepParent "$app" "$root/build/experiments/AirportRTW-Identity-Check.zip"
echo "$app"
