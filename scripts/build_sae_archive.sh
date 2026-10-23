#!/bin/bash
set -euo pipefail
ROOT="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
SAE="$ROOT/rtw80211/sae"
OUT="${DERIVED_FILE_DIR:?DERIVED_FILE_DIR is required}/sae"
mkdir -p "$OUT"
flags=(-include "$SAE/namespace.h" -std=gnu11 -O2 -I"$SAE/compat" -I"$SAE/third_party/hostap/src"
 -I"$SAE/third_party/hostap/src/utils" -I"$SAE/third_party/hostap/src/common"
 -I"$SAE/third_party/mbedtls/include" -I"$SAE/third_party/mbedtls/library"
 -I"$SAE" '-DMBEDTLS_CONFIG_FILE="rtw_sae_mbedtls_config.h"')
if [[ "${SAE_HOST_TEST:-0}" == 1 && "${SAE_HOST_SANITIZE:-0}" == 1 ]]; then
 flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
if [[ "${SAE_HOST_TEST:-0}" != 1 ]]; then
 flags+=(-include "$ROOT/include/AirportRTWDiagnostics.h" -arch x86_64 "-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET:-10.15}"
 -isysroot "${SDKROOT:?SDKROOT is required}" -mkernel -fno-stack-protector -DKERNEL
 -I"$ROOT/MacKernelSDK/Headers" -I"$SAE/compat/kernel_libc")
fi
objects=()
for file in "$SAE/third_party/hostap/src/common/sae.c" "$SAE/third_party/hostap/src/common/dragonfly.c" \
 "$SAE"/rtw_sae{,_hostap,_wpabuf,_crypto}.c \
 "$SAE/third_party/mbedtls/library/"{bignum,bignum_core,ecp,ecp_curves,constant_time,platform_util}.c; do
 obj="$OUT/$(basename "$file" .c).o"
 xcrun clang "${flags[@]}" -c "$file" -o "$obj"
 objects+=("$obj")
done
xcrun libtool -static -o "$OUT/../librtw_sae.a" "${objects[@]}"
