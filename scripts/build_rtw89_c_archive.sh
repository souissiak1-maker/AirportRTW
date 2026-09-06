#!/bin/bash
set -euo pipefail

ROOT="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT_DIR="${DERIVED_FILE_DIR:?DERIVED_FILE_DIR is required}/rtw89-c"
OUT_LIB="${DERIVED_FILE_DIR}/librtw89_c.a"
SDK_PATH="${SDKROOT:?SDKROOT is required}"
DRIVER="$ROOT/rtw/hal_rtw89/driver"
COMPAT="$ROOT/rtw/hal_rtw89/compat"

mkdir -p "$OUT_DIR"

COMMON=(
  -arch x86_64
  "-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET:-10.15}"
  -isysroot "$SDK_PATH"
  -fno-exceptions -fno-rtti -fno-stack-protector -mkernel
  -I"$ROOT/MacKernelSDK/Headers"
  -I"$SDK_PATH/System/Library/Frameworks/Kernel.framework/Headers"
)
DRIVER_FLAGS=(
  "${COMMON[@]}"
  -I"$COMPAT" -I"$COMPAT/linux" -I"$ROOT/rtw/hal_rtw89"
  -include "$COMPAT/rtw89_compat.h"
  -I"$DRIVER"
  -DRTW89_MACOS=1 -D__KERNEL__
  -Werror=implicit-function-declaration
  -Wno-int-conversion -Wno-incompatible-pointer-types
  -Wno-unused-variable -Wno-unused-function
)

if [[ "${CONFIGURATION:-Release}" == "Debug" ]]; then
  OPT=(-O0 -g)
else
  OPT=(-O2)
fi

objects=()
compile_c() {
  local src="$1"
  shift
  local rel="${src#$ROOT/}"
  local obj="$OUT_DIR/${rel//\//_}.o"
  echo "CC  $rel"
  xcrun clang "$@" "${OPT[@]}" -c "$src" -o "$obj"
  objects+=("$obj")
}

for file in \
  core.c mac80211.c mac.c mac_be.c phy.c phy_be.c fw.c cam.c efuse.c \
  efuse_be.c regd.c sar.c coex.c ps.c chan.c ser.c acpi.c util.c \
  pci.c pci_be.c \
  rtw8852a.c rtw8852a_rfk.c rtw8852a_rfk_table.c rtw8852a_table.c rtw8852ae.c \
  rtw8852b_common.c rtw8852b.c rtw8852b_rfk.c rtw8852b_rfk_table.c \
  rtw8852b_table.c rtw8852be.c \
  rtw8851b.c rtw8851b_rfk.c rtw8851b_rfk_table.c rtw8851b_table.c rtw8851be.c \
  rtw8852bt.c rtw8852bt_rfk.c rtw8852bt_rfk_table.c rtw8852bte.c \
  rtw8852c.c rtw8852c_rfk.c rtw8852c_rfk_table.c rtw8852c_table.c rtw8852ce.c \
  rtw8922a.c rtw8922a_rfk.c rtw8922ae.c
do
  compile_c "$DRIVER/$file" "${DRIVER_FLAGS[@]}"
done

compile_c "$DRIVER/Senmiko.c" -iquote "$DRIVER" "${DRIVER_FLAGS[@]}"
compile_c "$COMPAT/rtw88_compat.c" "${DRIVER_FLAGS[@]}"
compile_c "$COMPAT/rtw89_compat.c" "${DRIVER_FLAGS[@]}"
compile_c "$COMPAT/rtw88_firmware.c" "${COMMON[@]}" -I"$COMPAT" -Wno-unused-function
compile_c "$COMPAT/fw_blobs89.c" "${COMMON[@]}" -I"$COMPAT" -Wno-unused-function

echo "AR  ${OUT_LIB#$ROOT/}"
xcrun libtool -static -o "$OUT_LIB" "${objects[@]}"
