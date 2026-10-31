# MtkWireless AWDL reference audit

Local reference: `../MtkWireless`, revision `98d9442` (Release 1.0.6).

The README reports bidirectional Tahoe AirDrop hardware transfers. This is
reference-project evidence, not validation of AirportRTW or Realtek hardware.
The Wi-Fi core is GPL-2.0; its separately licensed Bluetooth implementation
must not be imported as part of the Wi-Fi adaptation.

## Useful integration examples

- `kext/Wifi/vendor/AirportMtkWlan/AirportMtkAwdlInterface.cpp`:
  native control requests, native action delivery, service loop and radio grants.
- `rust/mtk-wlan/src/awdl/timeline.rs`: availability windows, reservation lead
  estimation, multicast rendezvous and queue lifetime calculations.
- `rust/mtk-wlan/src/awdl/protocol.rs`: bounded data framing, per-stream
  duplicate windows and channel/synchronization state.
- `docs/AIRDROP-PERFORMANCE.md`: hardware evidence for sequence rollover,
  receive aggregation and transfer-rate limitations.

## Implemented adaptation

AirportRTW's shared `DataCodec` now accepts the observed eight-byte RFC1042
length envelope before Apple AWDL SNAP on a non-aggregated QoS frame. The
length must equal the entire remaining MSDU. The decoder does not scan for
inner signatures, accept nested wrappers, or relax source/BSSID/IPv6 checks.
No reference implementation code was copied. Plain framing remains supported.
A separate maximum receive length accounts for the extra eight bytes without
changing the transmit format or IPv6 MTU.

Host ASan/UBSan tests cover every IPv6 size from 40 through 1428 bytes, exact
round trips, incorrect envelope lengths and truncated headers. Existing receive
registration and native datapath tests also pass.

## Remaining integration

A-MSDU parsing still needs a bounded, whole-aggregate validation pass before any
subframe delivery. The current decoder deliberately rejects aggregates.
Native control-provider binding, hardware-confirmed channel scheduling, peer
admission/teardown, clock integration and end-to-end hardware verification are
still incomplete. MediaTek firmware ROC commands cannot be used on Realtek.
No support capabilities were enabled and no finished AWDL kext was produced.
