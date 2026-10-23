#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$ROOT/build/releases"
OBJECTS="$ROOT/build/releases-obj"
CONFIGURATION="${CONFIGURATION:-Release}"

BACKEND_C_SOURCES="fw_blobs89.c rtw88_compat.c rtw88_firmware.c rtw89_compat.c Senmiko.c acpi.c cam.c chan.c coex.c core.c debug.c efuse.c efuse_be.c fw.c mac.c mac80211.c mac_be.c pci.c pci_be.c phy.c phy_be.c ps.c regd.c rtw8852a.c rtw8852a_rfk.c rtw8852a_rfk_table.c rtw8852a_table.c rtw8852ae.c sar.c ser.c util.c wow.c"

TARGETS=(
  AirportRTW-High\ Sierra
  AirportRTW-Mojave
  AirportRTW-Catalina
  AirportRTW-Big\ Sur
  AirportRTW-Monterey
  AirportRTW-Ventura
  AirportRTW-Sonoma14.0
  AirportRTW-Sonoma14.4
  AirportRTW-Sequoia
  AirportRTW-Tahoe
)

if (( $# )); then
  TARGETS=("$@")
fi

for target in "${TARGETS[@]}"; do
  xcodebuild -quiet \
    -project "$ROOT/AirportRTW.xcodeproj" \
    -target "$target" \
    -configuration "$CONFIGURATION" \
    ARCHS=x86_64 \
    CODE_SIGNING_ALLOWED=NO \
    EXCLUDED_SOURCE_FILE_NAMES="$BACKEND_C_SOURCES" \
    'OTHER_LDFLAGS=$(inherited) $(DERIVED_FILE_DIR)/librtw89_c.a $(DERIVED_FILE_DIR)/librtw88_c.a $(DERIVED_FILE_DIR)/librtw_sae.a' \
    SYMROOT="$OUTPUT" \
    OBJROOT="$OBJECTS"
done

if [[ "$CONFIGURATION" == "Release" ]]; then
  for target in "${TARGETS[@]}"; do
    executable="$OUTPUT/$CONFIGURATION/${target#AirportRTW-}/AirportRTW.kext/Contents/MacOS/AirportRTW"
    if [[ -f "$executable" ]]; then
      xcrun strip -S -x "$executable"
    fi
  done
fi

echo "Kexts are available in $OUTPUT/$CONFIGURATION"
