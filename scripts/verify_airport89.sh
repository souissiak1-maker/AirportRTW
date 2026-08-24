#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
KEXT="$ROOT/build/out/AirportRTW89.kext"
BIN="$KEXT/Contents/MacOS/AirportRTW89"
PLIST="$KEXT/Contents/Info.plist"
[ -f "$BIN" ] || { echo "Missing $BIN; run make airport89 first" >&2; exit 1; }
/usr/bin/nm -u "$BIN" | c++filt | grep -E 'strnlen|monitorModeSetEnabled' && {
  echo "FAIL: known incompatible import remains" >&2; exit 1;
} || true
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$PLIST"
/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$PLIST"
/usr/libexec/PlistBuddy -c 'Print :OSBundleLibraries:com.apple.iokit.IO80211FamilyLegacy' "$PLIST"
/usr/libexec/PlistBuddy -c 'Print :OSBundleLibraries:com.apple.iokit.IOSkywalkFamily' "$PLIST"
if /usr/libexec/PlistBuddy -c 'Print :OSBundleLibraries:com.apple.iokit.IO80211Family' "$PLIST" >/dev/null 2>&1; then
  echo 'FAIL: stock IO80211Family dependency is still present' >&2
  exit 1
fi
dwarfdump --uuid "$BIN"
echo 'AirportRTW89 attachment-port checks passed.'
