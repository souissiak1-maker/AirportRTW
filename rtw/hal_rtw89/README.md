# RTL8852AE native net80211 backend

This backend follows the `iwn`/`iwm`/`iwx` ownership model. Its embedded
`rtw89_softc.sc_ic` is the authoritative OpenBSD `ieee80211com`.
Its class and files are named `RTWCore89`. The standalone Ethernet frontend
is `RTWEthernetController`, while its product remains `RTWCore.kext`.

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

The Xcode project's backend C++ source coverage is maintained by
`tools/wire_rtw89_xcode.py`. Linux-derived C modules are compiled separately by
`scripts/build_rtw89_c_archive.sh` with their compatibility prefix. Running the
wiring utility repeatedly is safe; it does not regenerate OS-specific frontends.

Run `python tools/validate_rtw89_backend.py` before moving the checkout to a
Mac. It verifies target/source coverage and frontend isolation, PCI personalities,
Xcode project structure, C archive inputs, and embedded firmware integrity.
See `docs/NATIVE_WIFI_PORT.md` for the experimental Sequoia/Tahoe frontend and
the separate AppleVTD/DMA review.

## macOS validation

Build the desired OS target with `scripts/build_release_kexts.sh`. Before loading,
confirm the machine reports PCI ID `10ec:8852` (or `10ec:a85a`) and remove any
other Realtek Wi-Fi kext that claims it. The first hardware pass should verify:

1. firmware decompression and PCI interrupt/NAPI startup in the kernel log;
2. passive and active scan results on both bands;
3. open and WPA2-CCMP association, DHCP, ping and sustained bidirectional TX;
4. sleep/wake followed by a fresh scan and reassociation.

This Windows checkout cannot run Xcode or load a kext, so hardware behavior
and macOS SDK ABI still require that first Mac build/test pass.


## HE / Wi-Fi 6 negotiation

`RTWCore89` publishes the probed hardware's station HE capabilities to the
shared net80211 controller. It chooses the capabilities for the association's
2.4/5 GHz band and limits the advertised channel width to the bridge's 80 MHz
maximum. The `-nohe` boot argument keeps the HT/VHT path for comparison.

net80211 retains authentication, association and HE negotiation. Its HE element
parsers validate the fixed/MCS/PPE and operation lengths before reading them;
negotiation verifies common MCS support and the AP's basic MCS set. Wider APs
are narrowed to the supported primary 80 MHz segment. RTW88 does not acquire
HE mode merely because it has VHT channels.

The hardware bridge passes the negotiated peer HE capabilities and intersected
MCS/NSS maps to the Linux station, and programs HE BSS state, BSS colour,
operation parameters and MU EDCA when advertised. HE state is cleared on
leave. PHY reporting uses negotiated node flags and reports Auto while not
associated; `RTW89NegotiatedPHY` provides an IORegistry diagnostic at RUN.

The local `Airport_RTW89` reference informed the HE state and MCS checks, but
its separate MLME is not imported. This does not implement SAE, 6 GHz, EHT,
MLO or channels wider than 80 MHz. Physical ax association, fallback,
reconnection and throughput still require tests on hardware.
