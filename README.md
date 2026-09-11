# AirportRTW

macOS Wi-Fi driver for supported Realtek RTW89 PCIe cards.

## Compatibility

Supports macOS High Sierra (10.13) through macOS Tahoe (26).

Supported cards:

- RTL8851BE
- RTL8852AE
- RTL8852BE
- RTL8852BTE
- RTL8852CE
- RTL8922AE

## Builds

Build every release kext with:

```sh
./scripts/build_release_kexts.sh
```

The unsigned outputs are placed in `build/releases/Release`:

| macOS | Kext folder |
| --- | --- |
| High Sierra 10.13 | `High Sierra/AirportRTW.kext` |
| Mojave 10.14 | `Mojave/AirportRTW.kext` |
| Catalina 10.15 | `Catalina/AirportRTW.kext` |
| Big Sur 11 | `Big Sur/AirportRTW.kext` |
| Monterey 12 | `Monterey/AirportRTW.kext` |
| Ventura 13 | `Ventura/AirportRTW.kext` |
| Sonoma 14.0–14.3 | `Sonoma14.0/AirportRTW.kext` |
| Sonoma 14.4 or newer | `Sonoma14.4/AirportRTW.kext` |

## macOS Tahoe

Tahoe support is experimental and uses the Ventura 13 kext with a restored legacy Wi-Fi stack. Keep a working recovery USB and back up your EFI first.

1. Copy `AirportRTW.kext` from the Ventura 13 build to `EFI/OC/Kexts`.
2. Add current, mutually compatible builds of `Lilu.kext`, `AMFIPass.kext`, `IOSkywalkFamily.kext`, and `IO80211FamilyLegacy.kext`. Obtain the restored Apple networking components through [OpenCore Legacy Patcher](https://dortania.github.io/OpenCore-Legacy-Patcher/), not from unofficial kext archives.
3. In OpenCore `Kernel -> Add`, load the kexts in this order: Lilu, AMFIPass, IOSkywalkFamily, IO80211FamilyLegacy, then AirportRTW. For AirportRTW use `Contents/MacOS/AirportRTW` as `ExecutablePath` and restrict the entry to Darwin `25.0.0`–`25.99.99`.
4. In `Kernel -> Block`, block `com.apple.iokit.IOSkywalkFamily` with strategy `Exclude` for Darwin `25.0.0`–`25.99.99`, allowing the restored version to load.
5. Set `Misc -> Security -> SecureBootModel` to `Disabled`, boot through OpenCore, and apply OCLP's **Post-Install Root Patch**. OCLP determines the required SIP/AMFI changes; do not copy security values from an unrelated machine.
6. Reboot and verify the stack with `kmutil showloaded | grep -Ei 'AirportRTW|IO80211|Skywalk'`.

Root patches are normally removed by macOS updates and must be reapplied. OCLP's Tahoe wireless work remains in development; check its [Tahoe support tracker](https://github.com/dortania/OpenCore-Legacy-Patcher/issues/1167) before updating.

## Credits

Special thanks to the [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm) project. Its modular architecture provided the foundation we adapted to connect the Realtek backend to AirportRTW, making support for Realtek Wi-Fi cards possible.
