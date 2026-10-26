# RTW88 PCIe HAL in the combined AirportRTW kext

The normal AirportRTW kext now includes **both RTW88 and RTW89 HALs**. The shared
factory selects the hardware backend from the PCI vendor/device ID, before
attaching it. The networking frontend and net80211 architecture are shared.

RTW88 matching covers five PCIe models:

| Model | PCI IDs | Bands / protocol |
|---|---|---|
| RTL8821CE | 10ec:c821, 10ec:b821 | 2.4/5 GHz, HT/VHT |
| RTL8822BE | 10ec:b822 | 2.4/5 GHz, HT/VHT |
| RTL8822CE | 10ec:c822, 10ec:c82f | 2.4/5 GHz, HT/VHT |
| RTL8723DE | 10ec:d723 | 2.4 GHz only, HT |
| RTL8814AE | 10ec:8813 | 2.4/5 GHz, HT/VHT |

Existing RTW89 matching remains available. Unknown IDs and other PCI vendors
are rejected. USB and SDIO are outside this PCIe backend.

Band availability, HT/VHT capabilities and stream counts come from the probed
Linux hardware specification and efuse data. The native channel table excludes
unsupported bands; association intersects the peer's MCS masks with the local
card's capabilities. RTL8814A's upstream driver chooses two or three spatial
streams based on its RF configuration; the port does not assume four streams.
All five RTW88 models still require physical hardware validation.

`RTWCore88` owns its net80211 controller and forwards hardware operations through
`Rtw88LinuxBridge` and `Rtw88PciTransport`. The existing net80211 scan, MLME,
security and replay logic and native frontend are retained. The donor's
independent `RTW88IEEE80211` state machine is not imported.

Implemented paths include probe/unwind, enable/disable, firmware and private
MAC programming, software-driven scans, peer/channel setup, key installation
and removal, hardware CCMP with RX normalization, software crypto for other
net80211-supported ciphers, TX backpressure, RX delivery, per-TID queues,
Block Ack callbacks, multicast filters, EDCA and lifecycle cleanup. HT/VHT data
channel widths are negotiated up to 80 MHz. Physical RTW88 operation, reconnect,
sleep/wake and sustained throughput remain unverified. WoWLAN and HE/802.11ax
are not implemented by this RTW88 HAL.

## Build and install

```sh
bash scripts/build_release_kexts.sh AirportRTW-Tahoe AirportRTW-Sequoia
python3 tools/validate_rtw88_backend.py --bundles
```

The ordinary Xcode targets compile both native HALs and both hardware archives.
One bundle per OS is produced at
`build/releases/Release/{Tahoe,Sequoia}/AirportRTW.kext`. Install the same bundle
on either supported card family; PCI matching chooses the HAL automatically.
The old `scripts/build_rtw88_kexts.py` command delegates to this combined build
for CLI compatibility. Historical `build/rtw88` outputs are obsolete and are
not the combined release.

## Runtime isolation

The two HALs have distinct C++ classes, contexts and transport instances.
`Rtw88Namespace.h` isolates all RTW88 driver/compatibility C exports, including
IRQ state, workqueues, hardware registration, DMA operations and firmware
loading, under `airportrtw88_`. Its bridge and transport use those private APIs;
the RTW89 backend retains its existing APIs. The validator checks both archives
for unisolated/colliding exports and verifies that both probes and HAL classes
are present in each linked native binary with no unresolved backend symbols.
`RTWHALFamily` on the PCI device records which backend the factory selected.

## Provenance

The hardware source comes from the supplied local
`Realtek88LegacyAirport/rtw88-stable` archive. `UPSTREAM.json` records hashes of
the imported driver files and firmware and the fetched comparison revision.
Original file notices and `driver/COPYING` are retained. The compatibility and
net80211-to-hardware adapter derive from AirportRTW's existing RTW89 port, with
RTW88-specific hardware setup and queue handling. The synchronous thread-call
cancellation shim comes from the supplied `Airport_RTW88/src/compat` reference.
Firmware is embedded unmodified in compressed form and its Realtek notice is
included both here and in each generated bundle's Resources directory.
