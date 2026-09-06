# RTL8852AE native net80211 backend

This backend follows the `iwn`/`iwm`/`iwx` ownership model. Its embedded
`rtw89_softc.sc_ic` is the authoritative OpenBSD `ieee80211com`.

The Linux-derived rtw89 code below this boundary is a hardware and firmware
library. It must not own a parallel scan cache, MLME state machine, station
database, or key store. In particular, AirportRTW's transitional
`RTW88IEEE80211` and legacy net80211 mirror are not part of this backend.

The device matcher, PCI transport, firmware boot, native net80211 callbacks,
TX/RX data path, key programming and BlockAck hooks are wired for hardware
validation. The compatibility layer never exposes its Linux `ieee80211_*`
types to the translation unit that owns OpenBSD net80211.

Initial hardware scope:

- Realtek RTL8852AE (`10ec:8852`)
- Realtek RTL8852AE alternate ID (`10ec:a85a`)
- PCIe station mode
- 2.4 GHz and 5 GHz

## Import boundary

The first import from AirportRTW is intentionally limited to the upstream
rtw89 PCI/core and RTL8852A modules below. USB, SDIO, BE-generation helpers,
other chips, the AirportRTW frontend, `RTW88IEEE80211`, and the legacy
net80211 mirror are excluded.

Core modules:

- `core`, `mac80211`, `mac`, `phy`, `fw`, `cam`, `efuse`
- `regd`, `sar`, `coex`, `ps`, `chan`, `ser`, `acpi`, `util`
- `pci`

RTL8852AE modules:

- `rtw8852ae`
- `rtw8852a`
- `rtw8852a_table`
- `rtw8852a_rfk`
- `rtw8852a_rfk_table`

The Xcode project is maintained by `tools/wire_rtw89_xcode.py`. It adds the
backend to every kext source phase, applies the rtw89 compatibility prefix only
to driver C files, and adds `10ec:8852`/`10ec:a85a` to every personality.
Running it repeatedly is safe.

Run `python tools/validate_rtw89_backend.py` before moving the checkout to a
Mac. It verifies source-phase coverage, per-file compatibility flags, PCI
personalities, Xcode project structure, and byte-for-byte embedded firmware
integrity.

## macOS validation

Build the desired `AirportRTW` or `AirportRTW` scheme in Xcode. Before loading,
confirm the machine reports PCI ID `10ec:8852` (or `10ec:a85a`) and remove any
other Realtek Wi-Fi kext that claims it. The first hardware pass should verify:

1. firmware decompression and PCI interrupt/NAPI startup in the kernel log;
2. passive and active scan results on both bands;
3. open and WPA2-CCMP association, DHCP, ping and sustained bidirectional TX;
4. sleep/wake followed by a fresh scan and reassociation.

This Windows checkout cannot run Xcode or load a kext, so hardware behavior
and macOS SDK ABI still require that first Mac build/test pass.
