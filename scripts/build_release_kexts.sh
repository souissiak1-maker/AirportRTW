#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$ROOT/build/releases"
OBJECTS="$ROOT/build/releases-obj"

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
)

for target in "${TARGETS[@]}"; do
  xcodebuild -quiet \
    -project "$ROOT/AirportRTW.xcodeproj" \
    -target "$target" \
    -configuration Release \
    CODE_SIGNING_ALLOWED=NO \
    EXCLUDED_SOURCE_FILE_NAMES="$BACKEND_C_SOURCES" \
    'OTHER_LDFLAGS=$(inherited) $(DERIVED_FILE_DIR)/librtw89_c.a' \
    SYMROOT="$OUTPUT" \
    OBJROOT="$OBJECTS"
done

echo "Release kexts are available in $OUTPUT/Release"
