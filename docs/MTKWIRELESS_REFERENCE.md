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

The shared codec now provides a separate two-pass A-MSDU inspection API:
all subframes, source addresses, declared lengths, envelopes and IPv6 bodies
must validate before any views are exposed. Single-frame inspection continues
to reject aggregates. Radio delivery and peer duplicate-window integration of
this API remain pending. Tests cover mixed wrapped/plain subframes, capacity,
malformed tails, source spoofing and trailing padding without a next subframe.
Native control-provider binding, hardware-confirmed channel scheduling, peer
admission/teardown, clock integration and end-to-end hardware verification are
still incomplete. MediaTek firmware ROC commands cannot be used on Realtek.
No support capabilities were enabled and no finished AWDL kext was produced.

## Shared election and software-clock engine

`RTWAwdlElection.hpp` adapts the hardware-independent State/Peer election and
clock discipline from the last C++ reference before its Rust port:
MtkWireless revision `d0919a374aac38d1703d50b2cd6430db8dbd7f08`, path
`kext/Wifi/vendor/include/AWDL/AwdlProtocol.hpp`, original file SHA-256
`1bfefc9053c3e59cd36a250d19a45aad13d248cb88918134be8290d8c3055645`.
The original GPL-2.0-or-later code is adapted under GPL-2.0; provenance is
retained in the header. Schedule/role/native-clock tests adapt the local
reference's GPL-2.0-or-later protocol-test.cpp at `98d9442`.

The adaptation uses AirportRTW's shared bounded decoder. Initialization takes
an explicit caller channel plan; no hardcoded channel is selected. It omits the
reference's older replay/data codec, firmware ROC/token implementation and
fabricated default identity/capability TLVs. Synchronization serialization takes
explicit wire-clock values instead of casting host time to RF TSF.

The engine owns a bounded 16-peer discovery table, loop-aware election,
explicit native parent/clock selection, bounded drift corrections, holdover,
counter rollover, and deferred control updates while a window is open. Native
management is the default: an observed peer cannot independently select itself
as synchronization parent. Data peer authorization/replay remains separate.

Host tests cover all supported presence sizes, channel schedules, 16-bit counter
rollover, follower expiry/loops, native selection/acquisition, rejected root
changes, deferred clock correction and resource bounds. They do not validate RF
latency, physical synchronization or end-to-end discovery. A concrete Realtek
RuntimeBackend and native event/radio binding remain incomplete.

The local reference test file used for adaptation has SHA-256
`e2c7441bf7645af43839f29df69d2e8f91ab1e0f6d29de04d68dbbac82b9789b`. Its checkout revision is recorded
above; this hash identifies the actual test contents independently of Git
tracking of vendored tests.
