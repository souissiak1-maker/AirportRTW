# RTW88 HAL reference and integration boundary

Initial hardware target: **RTL8822CE**, PCI IDs `10ec:c822` and `10ec:c82f`.
The RTW88 HAL is now included alongside RTW89 in the normal Tahoe/Sequoia
kext. The shared frontend selects RTWCore88 or RTWCore89 from the PCI ID.
Earlier separate-variant build notes below are historical. Hardware tests
remain pending. See `rtw/hal_rtw88/README.md` for build and installation details.

## Sources inspected

- Local reference: `/Users/senmiko/Desktop/Github/Airport_RTW88` (source archive,
  without Git metadata). Its README marks the project archived; its build
  workflow identifies the separate Linux driver dependency below.
- Driver dependency: `https://github.com/thegwchr/rtw88-stable.git`, inspected at
  `d029a677c49266fad86750714eb5612becd134d3`. The relevant source directory is
  `drivers/net/wireless/realtek/rtw88`. Pin this revision rather than silently
  following the dependency's moving branch.
- Reference firmware: `firmware/rtw8822c_fw.bin`. Retain the firmware's license
  and the original notices on imported C sources and compatibility files.

The reference's Makefile expects the driver under a separate `rtw88-stable`
sibling directory. That dependency was absent locally; it was fetched into a
temporary directory for inspection without modifying the reference folder.

## Preserve the itlwm architecture

`ItlHalService` remains the hardware-service boundary. The existing net80211
controller owns discovery, nodes, authentication, association, security policy,
key/replay state, and Block Ack negotiation. The native Sequoia/Tahoe frontend
continues to own Apple request/event translation.

Use the donor's PCI/MMIO, DMA, interrupts, firmware loading, chip initialization,
hardware key programming, channel/rate setup and hardware TX/RX. Do not import
`RTW88IEEE80211` as the networking state machine: it has a separate MLME and
security/data encapsulation path that would duplicate net80211 ownership.

The current RTW89 backend exports historical `rtw88_*` helper names and generic
`rtw_pci_probe/remove` entry points. Linking an unmodified second compatibility
runtime into the same kext would introduce symbol collisions and shared-global
ownership conflicts. Isolate backend symbols/lifetimes, or explicitly factor a
shared transport/compatibility boundary, before enabling runtime selection.

RTW88 requires its own key, RX layout and aggregation audit. Its RX status marks
hardware decryption without advertising stripped IV/MIC flags; the RTW89 CCMP
normalization policy must not be assumed valid without checking the RTW88 data
layout. Use the actual RTL8822CE firmware/chip specification when probing rather
than passing the RTW89 bridge's null PCI ID argument.

## Integration sequence

1. Establish an isolated RTW88 C archive with pinned driver sources, firmware
   and preserved notices, without changing the working RTW89 release.
2. Implement the RTW88 `ItlHalService` backend and PCI/DMA transport ownership.
   Forward hardware operations to RTW88 and keep MLME in net80211.
3. Wire native factory selection and PCI matching only with a linkable backend.
4. Validate attach/enable/disable/unwind, scan/cancel, association/key lifetime,
   DHCP, multicast, negotiated HT/VHT width and Block Ack on RTL8822CE.
5. Validate reconnect, sleep/wake, sustained traffic and coexistence with RTW89
   build configurations before reporting RTW88 support as working.

## Reference compilation check

On 2026-10-20, the reference Makefile successfully compiled `main.c`, `pci.c`,
`rtw8822c.c`, `rtw8822c_table.c` and `rtw8822ce.c` from the pinned dependency
against the donor compatibility headers and AirportRTW's MacKernelSDK. Outputs
were isolated under `/tmp/airportrtw-rtw88-probe`; the driver dependency and logs
also remained under `/tmp`. This validates the donor/compiler starting point,
not a linked AirportRTW RTW88 backend or working RTL8822CE hardware.

## Additional local references

The subsequently added `Realtek88LegacyAirport` folder contains both
`rtw88-stable/drivers/net/wireless/realtek/rtw88` and the macOS transport/shims
in its legacy macOS subproject. It therefore supplies a local copy of the previously
missing hardware dependency. The top-level Github directory also contains the
Realtek AirPort Family README and project/third-party licensing notices.

Comparison with the fetched revision found identical `rtw8822c.c`,
`rtw8822ce.c`, `mac80211.c` and `rx.c` files. Local `pci.c` additionally clears
PCI driver data after probe failure and removal. Local `main.c` changes
watchdog rearming and disables runtime power-saving transitions when the
compatibility layer cannot provide full station iteration. Those are donor
behavior differences to review, not changes to copy unconditionally.

The donor’s legacy README also describes reconnect/STA/Block Ack teardown,
deferred TX ADDBA until data after port authorization, and bounded TX queue
watermarks. These are relevant comparison points for the new HAL. Its legacy
Apple frontend and independent MLME remain outside the integration boundary.

## Implementation validation

The RTW88 driver archive and both native bundles compiled and linked. Binary
checks found the RTW88 chip specifications and RTW88Core, no RTW89 PCI probe,
and no unresolved RTW88 backend symbols. PCI tables, imported source hashes,
firmware presence/licensing and native bundle matching passed the validator.
Per-TID TX queues are allocated and freed, software crypto covers ciphers
not offloaded to CCMP CAM, and driver callbacks use synchronous cancellation.
These are code/build checks; RTL8822CE scan/join/DHCP, aggregation and lifecycle
behavior are not yet hardware-validated. No EFI files were changed.

## Combined RTW88/RTW89 kext

The separate-variant build described above is superseded by a single kext per
macOS version. Normal Xcode targets compile both HAL classes and link both
hardware archives. `RealtekHalFactory.hpp` selects the backend using the common
PCI ID classifier in `RealtekPciIds.hpp`; neither family is sent through the
other's hardware probe. The factory publishes `RTWHALFamily` for verification.

All 431 RTW88 driver/compatibility C exports are isolated under `airportrtw88_`,
including independent hardware, IRQ, workqueue and firmware globals. RTW89
retains its existing interfaces. Archive validation rejects colliding exports,
and native bundle validation requires both HALs and both hardware probes with
no unresolved backend symbols. PCI matching includes the union of supported
IDs, and the firmware notice is copied by Xcode's resources phase.

Use `scripts/build_release_kexts.sh` and the normal `build/releases/Release`
bundles. The old RTW88-specific Python build command now delegates to the normal
combined build. No standalone RTW88 variant is needed. Hardware validation is
still required on RTL8822CE and after installing the combined build on RTW89.


## RTL8723DE and RTL8814AE extension

The combined kext now also matches RTL8723DE (`10ec:d723`) and RTL8814AE
(`10ec:8813`) through `RTWCore88`. Their chip implementations, calibration and
power tables, PCI wrappers and the shared 8723X support are imported unchanged
from the same local rtw88-stable reference as the original core. The two new
firmware files are from upstream linux-firmware; their hashes and source are
recorded in `UPSTREAM.json`. All new C exports use the RTW88 private namespace.

The native bridge queries actual band availability and efuse stream counts.
RTL8723DE exposes no 5 GHz channels or VHT. RTL8814AE keeps the donor's RF and
stream configuration and is not limited to the original two-stream association
shortcut. These are software implementations pending scan/join/DHCP, TX/RX,
crypto, aggregation and lifecycle tests on the actual cards.
