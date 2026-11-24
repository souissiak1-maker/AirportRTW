#!/bin/bash
set -euo pipefail

cd -- "$(dirname -- "$0")"
if [[ "$(uname -s)" != Darwin ]] || ! xcodebuild -version >/dev/null 2>&1; then
    echo 'Full Xcode must be available to xcodebuild on macOS.' >&2
    exit 1
fi

xcrun python3 tests/rtw89_bluetooth_coex_test.py
CONFIGURATION=Release bash scripts/build_release_kexts.sh AirportRTW-Sequoia

kext="$PWD/build/releases/Release/Sequoia/AirportRTW.kext"
plutil -lint "$kext/Contents/Info.plist"
xcrun otool -hv "$kext/Contents/MacOS/AirportRTW" | grep KEXTBUNDLE
printf '\nBuilt kext: %s\n' "$kext"
