# AirportRTW

AirportRTW is an experimental macOS Wi-Fi driver for Realtek PCIe adapters.
The current development target is RTL8852AE (RTW89) on macOS Tahoe using
Apple's restored legacy IO80211 networking stack.

## Project status

- Wi-Fi power control and scanning work on the test system.
- Open-network association and traffic work.
- WPA2 association is not complete.
- AirDrop/AWDL is not implemented.
- RTL8852AE is the only regularly tested adapter.

This is development software. Keep a bootable recovery USB and a known-good
EFI before testing it. Do not install AirportRTW on a machine you cannot
recover locally.

## Important OCLP notice

AirportRTW depends on `IO80211FamilyLegacy` and a compatible
`IOSkywalkFamily`. Tahoe does not provide the complete compatible stack by
default, so the tested configuration uses the Modern Wireless components and
root patches supplied by OpenCore Legacy Patcher (OCLP).

OCLP is officially intended for unsupported genuine Macs. Using its root
patches on a Hackintosh is experimental and is not an upstream-supported OCLP
configuration. Tahoe wireless support is also still evolving. Read the
[official OCLP post-install documentation](https://dortania.github.io/OpenCore-Legacy-Patcher/POST-INSTALL.html)
and the [official Tahoe support tracker](https://github.com/dortania/OpenCore-Legacy-Patcher/issues/1167)
before continuing.

Root patching lowers macOS security and modifies the sealed system volume.
macOS updates remove root patches, so they must normally be reapplied after
each update.

## Requirements

- macOS Tahoe 26.x on Intel/x86_64.
- OpenCore with a working, validated `config.plist`.
- A recovery USB containing a known-good EFI.
- A temporary Internet connection through Ethernet or USB tethering.
- A current Tahoe-compatible OCLP build.
- `Lilu.kext`, `AMFIPass.kext`, the OCLP-compatible
  `IOSkywalkFamily.kext`, and `IO80211FamilyLegacy.kext`.
- The matching AirportRTW kext.

Do not mix `IOSkywalkFamily` and `IO80211FamilyLegacy` from unrelated macOS or
OCLP releases. Do not download Apple system kexts from random archives.

## Supported test hardware

The kext contains experimental PCI matches for several RTW89 devices, but the
known development machine uses:

```text
Realtek RTL8852AE
Vendor ID: 0x10EC
Device ID: 0x8852 or 0xA85A
```

Other listed devices are not proof of working support.

## Build AirportRTW

Install Xcode Command Line Tools, then run:

```sh
cd AirportRTW
make clean
make airport89
./scripts/verify_airport89.sh
```

The result is:

```text
AirportRTW/build/out/AirportRTW89.kext
```

The current internal executable and class names still use the historical
`AirportRTW89` name. The bundle may be renamed to `AirportRTW.kext` when it is
copied into OpenCore, but do not rename its internal executable.

Expected metadata:

```text
Bundle identifier: com.rtw.airport
Executable:        Contents/MacOS/AirportRTW89
Version:           0.5.49
```

## Back up the EFI first

Mount the active EFI and make a complete copy before changing it. Confirm that
the recovery USB can reach the OpenCore picker.

Never edit only the recovery USB and assume the internal EFI is safe. Keep one
EFI that does not load AirportRTW or the restored wireless stack.

## Copy the required kexts

Place these bundles in `EFI/OC/Kexts`:

```text
Lilu.kext
AMFIPass.kext
IOSkywalkFamily.kext
IO80211FamilyLegacy.kext
AirportRTW.kext
```

Use the `IOSkywalkFamily` and `IO80211FamilyLegacy` pair supplied by the same
Tahoe-compatible OCLP build. AirportRTW must not be loaded together with:

- another Intel Wi-Fi driver;
- another AirportRTW/RTW89 build;
- a Broadcom Airport plugin that claims the same Wi-Fi service;
- another driver claiming the same Realtek PCI device.

## OpenCore `config.plist`

Use ProperTree or another plist-aware editor. Do not edit the plist as plain
text unless you understand OpenCore's schema. After copying kexts, use a
ProperTree OC Snapshot and then verify the ordering manually.

The examples below target Darwin 25 only, which corresponds to macOS Tahoe
26.x.

### `Kernel -> Add`

The relevant entries must appear in this order:

| Order | BundlePath | ExecutablePath | MinKernel | MaxKernel |
| --- | --- | --- | --- | --- |
| 1 | `Lilu.kext` | `Contents/MacOS/Lilu` | existing value | existing value |
| 2 | `AMFIPass.kext` | `Contents/MacOS/AMFIPass` | `25.0.0` | `25.99.99` |
| 3 | `IOSkywalkFamily.kext` | `Contents/MacOS/IOSkywalkFamily` | `25.0.0` | `25.99.99` |
| 4 | `IO80211FamilyLegacy.kext` | `Contents/MacOS/IO80211FamilyLegacy` | `25.0.0` | `25.99.99` |
| 5 | `AirportRTW.kext` | `Contents/MacOS/AirportRTW89` | `25.0.0` | `25.99.99` |

For every entry set:

```text
Arch:      Any
Enabled:   True
PlistPath: Contents/Info.plist
```

The `BundlePath` must exactly match the filename in `EFI/OC/Kexts`. If the
bundle is kept as `AirportRTW-0.5.49.kext`, use that exact name instead of
`AirportRTW.kext`; the executable path remains `Contents/MacOS/AirportRTW89`.

### `Kernel -> Block`

Block Tahoe's stock Skywalk family so OpenCore can inject the compatible
restored version:

| Key | Value |
| --- | --- |
| Arch | `x86_64` |
| Comment | `Allow restored IOSkywalkFamily downgrade` |
| Enabled | `True` |
| Identifier | `com.apple.iokit.IOSkywalkFamily` |
| Strategy | `Exclude` |
| MinKernel | `25.0.0` |
| MaxKernel | `25.99.99` |

Do not add a block for `IO80211FamilyLegacy`.

### `Misc -> Security`

Set:

```text
SecureBootModel = Disabled
```

This is required for the tested root-patched Tahoe configuration. It reduces
Secure Boot protection.

### `NVRAM -> Add`

Under GUID `7C436110-AB2A-4BBB-A880-FE41995C9F82`, set:

```text
csr-active-config = 03080000
```

This is plist `Data`, not the literal text string `03080000`.

Append these values to the existing `boot-args` string:

```text
-amfipassbeta rtw89_native_topology=1 rtw89_exclusive_native=1
```

Keep boot arguments separated by one space. Do not replace unrelated arguments
that your machine needs to boot.

The two `rtw89_` arguments select the tested native single-interface topology.
Do not add old experimental arguments from development logs unless a specific
test build requires them.

### Validate OpenCore

Run the `ocvalidate` binary matching your OpenCore release:

```sh
path/to/ocvalidate EFI/OC/config.plist
```

Fix every schema error before rebooting.

## Apply the OCLP Modern Wireless root patch

Do this while Ethernet or USB tethering is available:

1. Boot through the newly prepared OpenCore EFI.
2. Open the current Tahoe-compatible OpenCore Legacy Patcher application.
3. Open **Post-Install Root Patch**.
4. Review the detected patch set. It must include the applicable Modern
   Wireless/legacy wireless components for this configuration.
5. Start root patching and authenticate when macOS requests an administrator
   password.
6. Allow OCLP to download any required support packages.
7. Wait for OCLP to report that patching completed successfully.
8. Reboot through the same OpenCore EFI.

Do not force an unrelated hardware patch merely because Modern Wireless is not
offered. If OCLP does not detect or permit the required patch, stop and use a
Tahoe-compatible OCLP build known to provide it. The exact GUI wording can
change between OCLP releases.

OCLP may require Internet access to obtain support packages. Its official
documentation notes that a first pass may install only networking support when
required downloads are unavailable; rerun root patching after Internet access
is restored if OCLP requests it.

## First boot

At the OpenCore picker, reset NVRAM once after changing the restored networking
stack or bundle identifier, then boot macOS. Resetting NVRAM also removes saved
boot variables, so ensure OpenCore can rediscover the correct startup volume.

Initially keep Ethernet or USB tethering connected. Test in this order:

1. Confirm macOS reaches the desktop without a panic.
2. Confirm Wi-Fi can be switched on.
3. Confirm supported channels appear in System Information.
4. Confirm scanning lists nearby networks.
5. Test an open network.
6. Test WPA2 only after the basic path is stable.

WPA2 is currently incomplete and failure to join a protected network is a
known driver limitation.

## Verify the loaded stack

Check the loaded dependencies:

```sh
sudo kmutil showloaded | grep -Ei 'AirportRTW|IO80211|Skywalk'
```

Expected identifiers include:

```text
com.apple.iokit.IOSkywalkFamily
com.apple.iokit.IO80211FamilyLegacy
com.rtw.airport
```

Inspect the driver service:

```sh
ioreg -l -w0 -r -c AirportRTW89
```

Inspect macOS Wi-Fi reporting:

```sh
system_profiler SPAirPortDataType
```

The primary interface may be `en2` instead of `en0`. Interface numbering alone
is not a failure.

## Troubleshooting

### AirportRTW does not appear in `kmutil`

- Confirm `BundlePath` matches the actual kext filename.
- Keep `ExecutablePath` as `Contents/MacOS/AirportRTW89`.
- Confirm the bundle identifier is `com.rtw.airport`.
- Confirm both restored Apple networking dependencies load first.
- Run `ocvalidate` and inspect the OpenCore boot log.

### Wi-Fi remains off

- Confirm `IO80211FamilyLegacy` and the restored `IOSkywalkFamily` are loaded.
- Confirm OCLP root patches survived the last macOS update.
- Confirm the two tested `rtw89_` boot arguments are present.
- Reset NVRAM once after changing the networking stack.
- Remove duplicate Wi-Fi drivers.

### Wi-Fi powers on but the network list is empty

- Verify supported channels with `system_profiler SPAirPortDataType`.
- Confirm the card is RTL8852AE and is visible in IORegistry/PCI tools.
- Check that the correct RTW89 firmware is embedded by the build.
- Do not mix restored networking kexts from different OCLP releases.

### Open networks work but WPA2 fails

This is the current expected limitation. Password presentation can reach the
driver while authentication, key installation, or association completion still
fails. Repeated password attempts will not repair an incomplete driver path.

### Kernel panic or boot loop

1. Boot the recovery USB's known-good EFI.
2. Disable or remove the AirportRTW `Kernel -> Add` entry.
3. Disable the restored Skywalk/IO80211 entries and matching Skywalk block as a
   group if returning completely to the unpatched stack.
4. Restore the backed-up EFI if necessary.
5. Use OCLP's **Revert Root Patches** function if the installed root patch is
   responsible, then reboot.

Do not leave the stock Skywalk family blocked while also removing its restored
replacement.

## macOS and OCLP updates

Before updating macOS:

1. Update OCLP and review its Tahoe support status.
2. Keep the recovery USB available.
3. Back up the working EFI.
4. Expect the macOS update to remove root patches.
5. After the update, boot with temporary Ethernet/USB tethering and reapply
   OCLP post-install root patches.
6. Reboot and verify all three networking kexts again.

The official OCLP update guide recommends rebuilding/installing its OpenCore
changes before an OS update and reinstalling root patches afterward. See the
[official updating guide](https://dortania.github.io/OpenCore-Legacy-Patcher/UPDATE.html).

## Uninstall AirportRTW

1. Boot from the recovery EFI if the normal system is unstable.
2. Remove the AirportRTW `Kernel -> Add` entry and kext.
3. If no other driver needs them, remove the restored
   `IO80211FamilyLegacy`/`IOSkywalkFamily` entries and the Skywalk block
   together.
4. Remove AirportRTW-specific `rtw89_` boot arguments.
5. Revert OCLP root patches if they are no longer required by other hardware.
6. Restore your desired SIP and `SecureBootModel` settings.
7. Reset NVRAM and reboot.

## Repository layout

- `AirportRTW/` — kext glue, compatibility layer, firmware, and build system.
- `AirportRTW/rtw/rtw89/` — Linux RTW89 sources used by the compatibility layer.
- `AirportRTW/rtw/rtw88/` — Linux RTW88 sources retained for future support.
- Generated builds are written under `AirportRTW/build/` and ignored by Git.

Version 0.5.21 was the last observed build where the System Information GUI
advertised AirDrop as supported. This was a framework classification effect,
not functional AirDrop/AWDL support.
