# Makefile for rtw88-macos
#
# Prerequisites:
#   Xcode Command Line Tools
#   macOS SDK (comes with Xcode)
#   IOKit headers (in SDK)
#
# Usage:
#   make              — build kext bundle + rtw88ctl  →  build/out/
#   make kext         — build kext only
#   make ctl          — build rtw88ctl only
#   make install      — copy build/out/rtw88.kext to /Library/Extensions
#   make load         — kextutil (unsigned, requires SIP kext loading enabled)
#   make unload       — kextunload
#   make clean        — remove build/

MAKEFLAGS += -j$(shell sysctl -n hw.logicalcpu)

# ------------------------------------------------------------------ #
# Paths                                                               #
# ------------------------------------------------------------------ #

PROJ_ROOT    := $(shell pwd)
LINUX_SRC    := $(PROJ_ROOT)/rtw/rtw88/drivers/net/wireless/realtek/rtw88
LINUX89_SRC  := $(PROJ_ROOT)/rtw/rtw89/drivers/net/wireless/realtek/rtw89
COMPAT_DIR   := $(PROJ_ROOT)/src/compat
KEXT_SRC     := $(PROJ_ROOT)/src/kext
NET80211_SRC := $(PROJ_ROOT)/src/net80211
FIRMWARE_DIR := $(PROJ_ROOT)/firmware
CTL_DIR      := $(PROJ_ROOT)/ctl

BUILD_DIR    := $(PROJ_ROOT)/build
OUT_DIR      := $(BUILD_DIR)/out

# Source bundle: Info.plist + Resources skeleton (tracked in git)
KEXT_SKEL    := $(PROJ_ROOT)/rtw88.kext

# Output bundle: fully assembled kext ready for OpenCore / kextutil
OUT_KEXT     := $(OUT_DIR)/rtw88.kext
OUT_KEXT_BIN := $(OUT_KEXT)/Contents/MacOS/rtw88

# rtw89 flavour (separate kext, same kext sources via class renames)
KEXT89_SKEL    := $(PROJ_ROOT)/rtw89.kext
OUT_KEXT89     := $(OUT_DIR)/rtw89.kext
OUT_KEXT89_BIN := $(OUT_KEXT89)/Contents/MacOS/rtw89

# Experimental native-AirPort rtw89 flavour (legacy IO80211, macOS 12 target)
AIRPORT89_SKEL    := $(PROJ_ROOT)/AirportRTW89.kext
OUT_AIRPORT89     := $(OUT_DIR)/AirportRTW89.kext
OUT_AIRPORT89_BIN := $(OUT_AIRPORT89)/Contents/MacOS/AirportRTW89

OUT_CTL      := $(OUT_DIR)/rtw88ctl

# ------------------------------------------------------------------ #
# Toolchain                                                           #
# ------------------------------------------------------------------ #

SDK          := $(shell xcrun --show-sdk-path)
MKSDK        := $(PROJ_ROOT)/MacKernelSDK
ARCH         := -arch x86_64
MINOS        := -mmacosx-version-min=11.0

CC           := xcrun clang
CXX          := xcrun clang++
LD           := xcrun clang++

KEXT_FLAGS   := -fno-exceptions -fno-rtti \
                -fno-stack-protector -mkernel \
                $(ARCH) $(MINOS) \
                -isysroot $(SDK) \
                -I$(MKSDK)/Headers \
                -I$(SDK)/System/Library/Frameworks/Kernel.framework/Headers

# Compat include path overrides ALL linux/ and net/ headers
# so the Linux driver C files find our shims instead.
COMPAT_FLAGS := \
    -I$(COMPAT_DIR) \
    -I$(COMPAT_DIR)/linux \
    -I$(PROJ_ROOT)/src/kext

# C flags for Linux driver files
DRIVER_CFLAGS := \
    $(KEXT_FLAGS) \
    $(COMPAT_FLAGS) \
    -include $(COMPAT_DIR)/rtw88_compat.h \
    -I$(LINUX_SRC) \
    -DRTW88_MACOS=1 \
    -D__KERNEL__ \
    -DCONFIG_RTW88_8822BE=1 \
    -DCONFIG_RTW88_8822CE=1 \
    -DCONFIG_RTW88_8821CE=1 \
    -DCONFIG_RTW88_8812AE=1 \
    -DCONFIG_RTW88_8814AE=1 \
    -DCONFIG_RTW88_8821AU=1 \
    -DCONFIG_RTW88_8822BU=1 \
    -DCONFIG_RTW88_8822CU=1 \
    -DCONFIG_RTW88_8812AU=1 \
    -Werror=implicit-function-declaration \
    -Wno-int-conversion \
    -Wno-incompatible-pointer-types \
    -Wno-unused-variable \
    -Wno-unused-function

# rtw89 driver flags — force-include rtw89_compat.h (which pulls in
# rtw88_compat.h first) and define RTW89_MACOS instead of RTW88_MACOS
DRIVER89_CFLAGS := \
    $(KEXT_FLAGS) \
    $(COMPAT_FLAGS) \
    -include \
    $(COMPAT_DIR)/rtw89_compat.h \
    -I$(LINUX89_SRC) \
    -DRTW89_MACOS=1 \
    -D__KERNEL__ \
    -Werror=implicit-function-declaration \
    -Wno-int-conversion \
    -Wno-incompatible-pointer-types \
    -Wno-unused-variable \
    -Wno-unused-function

# C++ flags for kext wrapper files (-fapple-kext only for C++)
KEXT_CXXFLAGS := \
    $(KEXT_FLAGS) \
    -fapple-kext \
    $(COMPAT_FLAGS) \
    -std=c++17 \
    -DKERNEL \
    -Wno-deprecated-declarations \
    -Wno-nullability-completeness

# rtw89 kext C++ flags — same sources, classes renamed so both kexts can
# coexist without OSMetaClass name collisions
KEXT89_CXXFLAGS := \
    $(KEXT_CXXFLAGS) \
    -DRTW89_MACOS=1 \
    -DRTW88Kext=RTW89Kext \
    -DRTW88PCIDevice=RTW89PCIDevice \
    -DRTW88IEEE80211=RTW89IEEE80211 \
    -DRTW88UserClient=RTW89UserClient

AIRPORT89_CXXFLAGS := \
    $(KEXT_CXXFLAGS) \
    -DRTW89_MACOS=1 \
    -DRTW_AIRPORT=1 \
    -D__IO80211_TARGET=130000 \
    -DRTW88Kext=AirportRTW89Kext \
    -DRTW88PCIDevice=AirportRTW89 \
    -DRTW88IEEE80211=AirportRTW89IEEE80211 \
    -DRTW88UserClient=AirportRTW89UserClient

# ------------------------------------------------------------------ #
# Source files                                                         #
# ------------------------------------------------------------------ #

# Linux driver core C files (compiled with compat headers)
DRIVER_SRCS := \
    $(LINUX_SRC)/main.c \
    $(LINUX_SRC)/mac.c \
    $(LINUX_SRC)/phy.c \
    $(LINUX_SRC)/fw.c \
    $(LINUX_SRC)/tx.c \
    $(LINUX_SRC)/rx.c \
    $(LINUX_SRC)/sec.c \
    $(LINUX_SRC)/efuse.c \
    $(LINUX_SRC)/coex.c \
    $(LINUX_SRC)/ps.c \
    $(LINUX_SRC)/regd.c \
    $(LINUX_SRC)/bf.c \
    $(LINUX_SRC)/sar.c \
    $(LINUX_SRC)/util.c \
    $(LINUX_SRC)/pci.c \
    $(LINUX_SRC)/usb.c \
    $(LINUX_SRC)/sdio.c \
    $(LINUX_SRC)/mac80211.c

# Chip-specific C files
CHIP_SRCS := \
    $(LINUX_SRC)/rtw8822b.c \
    $(LINUX_SRC)/rtw8822b_table.c \
    $(LINUX_SRC)/rtw8822be.c \
    $(LINUX_SRC)/rtw8822bu.c \
    $(LINUX_SRC)/rtw8822c.c \
    $(LINUX_SRC)/rtw8822c_table.c \
    $(LINUX_SRC)/rtw8822ce.c \
    $(LINUX_SRC)/rtw8822cu.c \
    $(LINUX_SRC)/rtw8821c.c \
    $(LINUX_SRC)/rtw8821c_table.c \
    $(LINUX_SRC)/rtw8821ce.c \
    $(LINUX_SRC)/rtw8821cu.c \
    $(LINUX_SRC)/rtw8812a.c \
    $(LINUX_SRC)/rtw8812a_table.c \
    $(LINUX_SRC)/rtw8812au.c \
    $(LINUX_SRC)/rtw8814a.c \
    $(LINUX_SRC)/rtw8814a_table.c \
    $(LINUX_SRC)/rtw8814ae.c \
    $(LINUX_SRC)/rtw8814au.c \
    $(LINUX_SRC)/rtw8821a.c \
    $(LINUX_SRC)/rtw8821a_table.c \
    $(LINUX_SRC)/rtw8821au.c \
    $(LINUX_SRC)/rtw88xxa.c

# rtw89 driver + chip sources (debug.c and wow.c excluded, as on Linux
# when CONFIG_RTW89_DEBUG*/CONFIG_PM are off)
DRIVER89_SRCS := \
    $(LINUX89_SRC)/core.c \
    $(LINUX89_SRC)/mac80211.c \
    $(LINUX89_SRC)/mac.c \
    $(LINUX89_SRC)/mac_be.c \
    $(LINUX89_SRC)/phy.c \
    $(LINUX89_SRC)/phy_be.c \
    $(LINUX89_SRC)/fw.c \
    $(LINUX89_SRC)/cam.c \
    $(LINUX89_SRC)/efuse.c \
    $(LINUX89_SRC)/efuse_be.c \
    $(LINUX89_SRC)/regd.c \
    $(LINUX89_SRC)/sar.c \
    $(LINUX89_SRC)/coex.c \
    $(LINUX89_SRC)/ps.c \
    $(LINUX89_SRC)/chan.c \
    $(LINUX89_SRC)/ser.c \
    $(LINUX89_SRC)/acpi.c \
    $(LINUX89_SRC)/util.c \
    $(LINUX89_SRC)/pci.c \
    $(LINUX89_SRC)/pci_be.c \
    $(LINUX89_SRC)/usb.c \

CHIP89_SRCS := \
    $(LINUX89_SRC)/rtw8851b.c \
    $(LINUX89_SRC)/rtw8851b_rfk.c \
    $(LINUX89_SRC)/rtw8851b_rfk_table.c \
    $(LINUX89_SRC)/rtw8851b_table.c \
    $(LINUX89_SRC)/rtw8851be.c \
    $(LINUX89_SRC)/rtw8851bu.c \
    $(LINUX89_SRC)/rtw8852a.c \
    $(LINUX89_SRC)/rtw8852a_rfk.c \
    $(LINUX89_SRC)/rtw8852a_rfk_table.c \
    $(LINUX89_SRC)/rtw8852a_table.c \
    $(LINUX89_SRC)/rtw8852ae.c \
    $(LINUX89_SRC)/rtw8852au.c \
    $(LINUX89_SRC)/rtw8852b.c \
    $(LINUX89_SRC)/rtw8852b_common.c \
    $(LINUX89_SRC)/rtw8852b_rfk.c \
    $(LINUX89_SRC)/rtw8852b_rfk_table.c \
    $(LINUX89_SRC)/rtw8852b_table.c \
    $(LINUX89_SRC)/rtw8852be.c \
    $(LINUX89_SRC)/rtw8852bu.c \
    $(LINUX89_SRC)/rtw8852bt.c \
    $(LINUX89_SRC)/rtw8852bt_rfk.c \
    $(LINUX89_SRC)/rtw8852bt_rfk_table.c \
    $(LINUX89_SRC)/rtw8852bte.c \
    $(LINUX89_SRC)/rtw8852c.c \
    $(LINUX89_SRC)/rtw8852c_rfk.c \
    $(LINUX89_SRC)/rtw8852c_rfk_table.c \
    $(LINUX89_SRC)/rtw8852c_table.c \
    $(LINUX89_SRC)/rtw8852ce.c \
    $(LINUX89_SRC)/rtw8852cu.c \
    $(LINUX89_SRC)/rtw8922a.c \
    $(LINUX89_SRC)/rtw8922a_rfk.c \
    $(LINUX89_SRC)/rtw8922ae.c


# Compat C implementation
COMPAT_SRCS := \
    $(COMPAT_DIR)/rtw88_compat.c

COMPAT89_SRCS := \
    $(COMPAT_DIR)/rtw88_compat.c \
    $(COMPAT_DIR)/rtw89_compat.c

# Senmiko's rtw89 in-driver macOS bridge — vendored in-tree (src/rtw89_glue/)
# so it survives a refresh of the sibling rtw89 source tree.  It must still
# see the REAL driver headers: its `#include "pci.h"` would otherwise be
# shadowed by the compat shim's linux/pci.h.  The compile rule below passes
# `-iquote $(LINUX89_SRC)` so quoted includes resolve to the driver tree
# before any -I path, while <linux/*.h> still hits the compat shims.
SENMIKO_GLUE_SRCS := \
    $(PROJ_ROOT)/src/rtw89_glue/Senmiko.c

# Firmware loader — compiled with system headers only (no Linux compat headers)
# fw_blobs.c is auto-generated from firmware/*.bin before compilation
FIRMWARE_SRCS := \
    $(COMPAT_DIR)/rtw88_firmware.c \
    $(COMPAT_DIR)/fw_blobs.c

FW_BLOBS_C := $(COMPAT_DIR)/fw_blobs.c

# kmod_info.c — defines _kmod_info (required by kmutil/kextutil)
KMOD_SRCS := \
    $(KEXT_SRC)/kmod_info.c

# IOKit C++ wrapper
# RTW88USBDevice excluded: IOUSBHostFamily not in OSBundleLibraries
KEXT_SRCS := \
    $(KEXT_SRC)/RTW88Kext.cpp \
    $(KEXT_SRC)/RTW88PCIDevice.cpp \
    $(KEXT_SRC)/RTW88IEEE80211.cpp \
    $(KEXT_SRC)/RTW88UserClient.cpp \
    $(KEXT_SRC)/RTW88Airport.cpp

# ------------------------------------------------------------------ #
# Object files                                                         #
# ------------------------------------------------------------------ #

DRIVER_OBJS   := $(patsubst $(LINUX_SRC)/%.c,  $(BUILD_DIR)/driver/%.o, $(DRIVER_SRCS))
CHIP_OBJS     := $(patsubst $(LINUX_SRC)/%.c,  $(BUILD_DIR)/driver/%.o, $(CHIP_SRCS))
COMPAT_OBJS   := $(patsubst $(COMPAT_DIR)/%.c, $(BUILD_DIR)/compat/%.o, $(COMPAT_SRCS))
FIRMWARE_OBJS := $(patsubst $(COMPAT_DIR)/%.c, $(BUILD_DIR)/compat/%.o, $(FIRMWARE_SRCS))
KMOD_OBJS   := $(patsubst $(KEXT_SRC)/%.c,   $(BUILD_DIR)/kext/%.o,   $(KMOD_SRCS))
KEXT_OBJS   := $(patsubst $(KEXT_SRC)/%.cpp, $(BUILD_DIR)/kext/%.o,   $(KEXT_SRCS))

ALL_OBJS    := $(DRIVER_OBJS) $(CHIP_OBJS) $(COMPAT_OBJS) $(FIRMWARE_OBJS) $(KMOD_OBJS) $(KEXT_OBJS)

# rtw89 objects — separate build dirs so both kexts can be built side by side
DRIVER89_OBJS   := $(patsubst $(LINUX89_SRC)/%.c,  $(BUILD_DIR)/driver89/%.o, $(DRIVER89_SRCS))
CHIP89_OBJS     := $(patsubst $(LINUX89_SRC)/%.c,  $(BUILD_DIR)/driver89/%.o, $(CHIP89_SRCS))
COMPAT89_OBJS   := $(patsubst $(COMPAT_DIR)/%.c, $(BUILD_DIR)/compat89/%.o, $(COMPAT89_SRCS))
FIRMWARE89_OBJS := $(BUILD_DIR)/compat89/rtw88_firmware.o $(BUILD_DIR)/compat89/fw_blobs89.o
KMOD89_OBJS     := $(BUILD_DIR)/kext89/kmod_info.o
KEXT89_OBJS     := $(patsubst $(KEXT_SRC)/%.cpp, $(BUILD_DIR)/kext89/%.o, $(KEXT_SRCS))
KMODAIRPORT89_OBJS := $(BUILD_DIR)/kextairport89/kmod_info.o
KEXTAIRPORT89_OBJS := $(patsubst $(KEXT_SRC)/%.cpp, $(BUILD_DIR)/kextairport89/%.o, $(KEXT_SRCS))
NET80211AIRPORT89_OBJS := $(BUILD_DIR)/kextairport89/RTW89Net80211Core.o

SENMIKO_GLUE_OBJS := $(patsubst $(PROJ_ROOT)/src/rtw89_glue/%.c,$(BUILD_DIR)/glue89/%.o,$(SENMIKO_GLUE_SRCS))
ALL89_OBJS := $(DRIVER89_OBJS) $(CHIP89_OBJS) $(COMPAT89_OBJS) $(SENMIKO_GLUE_OBJS) $(FIRMWARE89_OBJS) $(KMOD89_OBJS) $(KEXT89_OBJS)
ALLAIRPORT89_OBJS := $(DRIVER89_OBJS) $(CHIP89_OBJS) $(COMPAT89_OBJS) $(SENMIKO_GLUE_OBJS) $(FIRMWARE89_OBJS) $(KMODAIRPORT89_OBJS) $(KEXTAIRPORT89_OBJS) $(NET80211AIRPORT89_OBJS)

# ------------------------------------------------------------------ #
# Linker flags                                                         #
# ------------------------------------------------------------------ #

KEXT_LDFLAGS := \
    $(ARCH) \
    -static \
    -nostdlib \
    -Xlinker -kext \
    $(MKSDK)/Library/x86_64/libkmod.a \
    $(MKSDK)/Library/universal/libkmodc++.a \
    -F$(SDK)/System/Library/Frameworks

# ------------------------------------------------------------------ #
# Targets                                                             #
# ------------------------------------------------------------------ #

.PHONY: all kext kext89 airport89 ctl install install89 installairport89 load load89 loadairport89 unload unload89 unloadairport89 clean

all: kext ctl

kext89: $(OUT_KEXT89_BIN)

airport89: $(OUT_AIRPORT89_BIN)

kext: $(OUT_KEXT_BIN)

# Link, then assemble the full kext bundle in build/out/
$(OUT_KEXT_BIN): $(ALL_OBJS) | $(OUT_KEXT)/Contents/MacOS
	@echo "  LD   $(notdir $@)"
	$(LD) $(KEXT_LDFLAGS) -o $@ $(ALL_OBJS)
	@echo "  SYNC $(OUT_KEXT)"
	rsync -a --exclude='MacOS' $(KEXT_SKEL)/ $(OUT_KEXT)/
	@echo "  NOTE  run 'sudo chown -R root:wheel $(OUT_KEXT)' for kextutil"
	@echo "  KEXT $$(dwarfdump --uuid $(OUT_KEXT_BIN) 2>/dev/null)"
	@echo "  OK   build/out/rtw88.kext"

# rtw89 kext link + bundle assembly
$(OUT_KEXT89_BIN): $(ALL89_OBJS) | $(OUT_KEXT89)/Contents/MacOS
	@echo "  LD   $(notdir $@)"
	$(LD) $(KEXT_LDFLAGS) -o $@ $(ALL89_OBJS)
	@echo "  SYNC $(OUT_KEXT89)"
	rsync -a --exclude='MacOS' $(KEXT89_SKEL)/ $(OUT_KEXT89)/
	@echo "  NOTE  run 'sudo chown -R root:wheel $(OUT_KEXT89)' for kextutil"
	@echo "  OK   build/out/rtw89.kext"

# Experimental AirportRTW89 kext link + bundle assembly
$(OUT_AIRPORT89_BIN): $(ALLAIRPORT89_OBJS) | $(OUT_AIRPORT89)/Contents/MacOS
	@echo "  LD   $(notdir $@)"
	$(LD) $(KEXT_LDFLAGS) -o $@ $(ALLAIRPORT89_OBJS)
	@echo "  SYNC $(OUT_AIRPORT89)"
	rsync -a --exclude='MacOS' $(AIRPORT89_SKEL)/ $(OUT_AIRPORT89)/
	@echo "  NOTE  EXPERIMENTAL legacy IO80211 frontend; do not load with rtw89.kext"
	@echo "  OK   build/out/AirportRTW89.kext"

# Compile Linux driver C files with compat headers
$(BUILD_DIR)/driver/%.o: $(LINUX_SRC)/%.c | $(BUILD_DIR)/driver
	@echo "  CC   $(notdir $<)"
	$(CC) $(DRIVER_CFLAGS) -c $< -o $@

# Compile compat C files (with Linux compat headers)
$(BUILD_DIR)/compat/%.o: $(COMPAT_DIR)/%.c | $(BUILD_DIR)/compat
	@echo "  CC   $(notdir $<)"
	$(CC) $(DRIVER_CFLAGS) -c $< -o $@

# rtw89: compile Linux driver / compat C files
$(BUILD_DIR)/driver89/%.o: $(LINUX89_SRC)/%.c | $(BUILD_DIR)/driver89
	@echo "  CC89 $(notdir $<)"
	$(CC) $(DRIVER89_CFLAGS) -c $< -o $@

# Vendored rtw89 bridge — separate output dir so the driver89 pattern rule
# (keyed on LINUX89_SRC) cannot shadow it.  -iquote makes `#include "pci.h"`
# resolve to the driver's real pci.h, defeating the compat shadow.
$(BUILD_DIR)/glue89/%.o: $(PROJ_ROOT)/src/rtw89_glue/%.c | $(BUILD_DIR)/glue89
	@echo "  CC89 $(notdir $<) (vendored bridge)"
	$(CC) -iquote $(LINUX89_SRC) $(DRIVER89_CFLAGS) -c $< -o $@

$(BUILD_DIR)/compat89/%.o: $(COMPAT_DIR)/%.c | $(BUILD_DIR)/compat89
	@echo "  CC89 $(notdir $<)"
	$(CC) $(DRIVER89_CFLAGS) -c $< -o $@

# Generate fw_blobs.c from firmware/*.bin (zlib-compressed embedded blobs)
$(FW_BLOBS_C): $(wildcard $(FIRMWARE_DIR)/*.bin) scripts/gen_fw_blobs.py
	@echo "  GEN  fw_blobs.c"
	python3 $(PROJ_ROOT)/scripts/gen_fw_blobs.py $(FIRMWARE_DIR) $@

# Compile firmware loader + blobs (system headers only — no compat header conflicts)
FW_CFLAGS := $(KEXT_FLAGS) \
    -I$(MKSDK)/Headers \
    -I$(SDK)/System/Library/Frameworks/Kernel.framework/Headers \
    -I$(COMPAT_DIR) \
    -Wno-unused-function

$(BUILD_DIR)/compat/rtw88_firmware.o: $(COMPAT_DIR)/rtw88_firmware.c | $(BUILD_DIR)/compat
	@echo "  CC   rtw88_firmware.c"
	$(CC) $(FW_CFLAGS) -c $< -o $@

$(BUILD_DIR)/compat/fw_blobs.o: $(COMPAT_DIR)/fw_blobs.c | $(BUILD_DIR)/compat
	@echo "  CC   fw_blobs.c"
	$(CC) $(FW_CFLAGS) -c $< -o $@

# rtw89 firmware: blobs generated from firmware89/*.bin (linux-firmware rtw89/)
FIRMWARE89_DIR := $(PROJ_ROOT)/firmware89
FW_BLOBS89_C   := $(COMPAT_DIR)/fw_blobs89.c

$(FW_BLOBS89_C): $(wildcard $(FIRMWARE89_DIR)/*.bin) scripts/gen_fw_blobs.py
	@echo "  GEN  fw_blobs89.c"
	python3 $(PROJ_ROOT)/scripts/gen_fw_blobs.py $(FIRMWARE89_DIR) $@

$(BUILD_DIR)/compat89/rtw88_firmware.o: $(COMPAT_DIR)/rtw88_firmware.c | $(BUILD_DIR)/compat89
	@echo "  CC89 rtw88_firmware.c"
	$(CC) $(FW_CFLAGS) -c $< -o $@

$(BUILD_DIR)/compat89/fw_blobs89.o: $(FW_BLOBS89_C) | $(BUILD_DIR)/compat89
	@echo "  CC89 fw_blobs89.c"
	$(CC) $(FW_CFLAGS) -c $< -o $@

# Compile kmod_info.c (plain C, no compat headers)
$(BUILD_DIR)/kext/kmod_info.o: $(KEXT_SRC)/kmod_info.c | $(BUILD_DIR)/kext
	@echo "  CC   kmod_info.c"
	$(CC) $(KEXT_FLAGS) -c $< -o $@

# Compile kext C++ wrapper files
$(BUILD_DIR)/kext/%.o: $(KEXT_SRC)/%.cpp | $(BUILD_DIR)/kext
	@echo "  CXX  $(notdir $<)"
	$(CXX) $(KEXT_CXXFLAGS) -c $< -o $@

# rtw89: kmod_info + kext C++ (renamed classes)
$(BUILD_DIR)/kext89/kmod_info.o: $(KEXT_SRC)/kmod_info.c | $(BUILD_DIR)/kext89
	@echo "  CC89 kmod_info.c"
	$(CC) $(KEXT_FLAGS) -DRTW89_MACOS=1 -c $< -o $@

$(BUILD_DIR)/kext89/%.o: $(KEXT_SRC)/%.cpp | $(BUILD_DIR)/kext89
	@echo "  CXX89 $(notdir $<)"
	$(CXX) $(KEXT89_CXXFLAGS) -c $< -o $@

# AirportRTW89: kmod_info + native IO80211 C++ frontend
$(BUILD_DIR)/kextairport89/kmod_info.o: $(KEXT_SRC)/kmod_info.c | $(BUILD_DIR)/kextairport89
	@echo "  CCA  kmod_info.c"
	$(CC) $(KEXT_FLAGS) -DRTW89_MACOS=1 -DRTW_AIRPORT=1 -c $< -o $@

$(BUILD_DIR)/kextairport89/%.o: $(KEXT_SRC)/%.cpp | $(BUILD_DIR)/kextairport89
	@echo "  CXXA $(notdir $<)"
	$(CXX) $(AIRPORT89_CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/kextairport89/RTW89Net80211Core.o: $(NET80211_SRC)/RTW89Net80211Core.cpp | $(BUILD_DIR)/kextairport89
	@echo "  CXXA RTW89Net80211Core.cpp"
	$(CXX) $(AIRPORT89_CXXFLAGS) -c $< -o $@

# ctl binary
ctl: $(OUT_CTL)

$(OUT_CTL): $(CTL_DIR)/main.c | $(OUT_DIR)
	@echo "  CC   rtw88ctl"
	$(CC) $(ARCH) $(MINOS) \
	    -isysroot $(SDK) \
	    -framework IOKit \
	    -framework CoreFoundation \
	    -o $@ $<
	@echo "  OK   build/out/rtw88ctl"

# ------------------------------------------------------------------ #
# Directory creation                                                  #
# ------------------------------------------------------------------ #

$(BUILD_DIR)/driver:
	mkdir -p $@

$(BUILD_DIR)/compat:
	mkdir -p $@

$(BUILD_DIR)/kext:
	mkdir -p $@

$(BUILD_DIR)/driver89 $(BUILD_DIR)/compat89 $(BUILD_DIR)/kext89 $(BUILD_DIR)/kextairport89 $(BUILD_DIR)/glue89:
	mkdir -p $@

$(OUT_KEXT89)/Contents/MacOS:
	mkdir -p $@

$(OUT_AIRPORT89)/Contents/MacOS:
	mkdir -p $@

$(OUT_DIR):
	mkdir -p $@

$(OUT_KEXT)/Contents/MacOS:
	mkdir -p $@

# ------------------------------------------------------------------ #
# Install / load                                                      #
# ------------------------------------------------------------------ #

install: kext ctl
	@echo "Installing rtw88.kext to /Library/Extensions..."
	sudo cp -R $(OUT_KEXT) /Library/Extensions/
	sudo chown -R root:wheel /Library/Extensions/rtw88.kext
	sudo chmod -R 755 /Library/Extensions/rtw88.kext
	@echo "Installing rtw88ctl to /usr/local/bin..."
	sudo install -m 755 $(OUT_CTL) /usr/local/bin/rtw88ctl
	@echo "Done. Run 'make load' or reboot to activate."

install89: kext89 ctl
	@echo "Installing rtw89.kext to /Library/Extensions..."
	sudo cp -R $(OUT_KEXT89) /Library/Extensions/
	sudo chown -R root:wheel /Library/Extensions/rtw89.kext
	sudo chmod -R 755 /Library/Extensions/rtw89.kext
	@echo "Installing rtw88ctl to /usr/local/bin..."
	sudo install -m 755 $(OUT_CTL) /usr/local/bin/rtw88ctl
	@echo "Done. Run 'make load89' or reboot to activate."

load:
	@echo "Loading rtw88.kext (requires SIP kext loading enabled)..."
	sudo kextutil -v $(OUT_KEXT)

load89:
	@echo "Loading rtw89.kext (requires SIP kext loading enabled)..."
	sudo kextutil -v $(OUT_KEXT89)

unload:
	@echo "Unloading rtw88.kext..."
	sudo kextunload -b com.rtw88.driver

installairport89: airport89
	@echo "Installing AirportRTW89.kext to /Library/Extensions..."
	sudo cp -R $(OUT_AIRPORT89) /Library/Extensions/
	sudo chown -R root:wheel /Library/Extensions/AirportRTW89.kext
	sudo chmod -R 755 /Library/Extensions/AirportRTW89.kext

loadairport89: airport89
	@echo "Loading AirportRTW89.kext (do not load rtw89.kext at the same time)..."
	sudo kextutil -v $(OUT_AIRPORT89)

unloadairport89:
	@echo "Unloading AirportRTW89.kext..."
	sudo kextunload -b com.rtw.airport

unload89:
	@echo "Unloading rtw89.kext..."
	sudo kextunload -b com.rtw89.driver

clean:
	rm -rf $(BUILD_DIR)

# ------------------------------------------------------------------ #
# OpenCore injection helper                                           #
# ------------------------------------------------------------------ #
# To use with OpenCore:
#   1. Copy build/out/rtw88.kext to OC/Kexts/
#   2. Add to config.plist -> Kernel -> Add:
#      Arch: Any
#      BundlePath: rtw88.kext
#      Comment: Realtek rtw88 WiFi
#      Enabled: YES
#      ExecutablePath: Contents/MacOS/rtw88
#      MaxKernel: (empty)
#      MinKernel: 20.0.0   (macOS 11+)
#      PlistPath: Contents/Info.plist
#   3. Rebuild OC cache: sudo kextcache -i /
#
# BaseSystem / Recovery notes:
#   The kext loads via OpenCore injection before the OS, so it works
#   in BaseSystem automatically.  rtw88ctl is a standalone binary;
#   copy it to the USB installer's /usr/local/bin or run from a path.
