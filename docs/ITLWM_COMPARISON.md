# Local itlwm comparison — 2026-10-19

Compared `/Users/senmiko/Desktop/Github/itlwm` at `738d4c6` with AirportRTW
`bfc50a3` plus the current Wi-Fi debugging changes. The itlwm checkout was read
only. The port provenance in NATIVE_WIFI_PORT.md names the older donor commit
`7e50738b80e65630040e2da22d464d0d13c847d3`; the current donor has later fixes.

## Shared native frontend

All nine headers in each of `include/Airport/macOS15` and `macOS26` match
ignoring whitespace. Controller, Skywalk, InfraProtocol and workqueue ABI
headers are therefore not a naming-related difference in these checkouts.
Both projects have explicit Sequoia/Tahoe targets using `AIRPORT_WCL` and native
WCL methods/messages. The scan request decoder and beacon metadata layout are
shared. Renaming does not implement the hardware-facing parts of that contract.

## Later donor functionality missing from AirportRTW

| Area | Local itlwm | AirportRTW |
| --- | --- | --- |
| Native channel information | `getCHANNELS_INFO`, gated `copyWCLChannels`, 0x2720 `NativeChannelInfo` layout | `getCHANNELS_INFO` returns unsupported; the separate `getWCL_CHANNELS_INFO` is implemented |
| Traffic counters | `getWCL_TRAFFIC_COUNTERS`, per-AC counters and timestamp | Method returns unsupported |
| Scan home/away timing | WCL setter, HAL hook, Intel firmware timing/fragmentation | Method returns unsupported; Realtek dwell timer is 120 ms |
| Link quality | Additional native quality updates and link-state reporting | Earlier snapshot/beacon reporting implementation |
| AppleVTD | `AIRPORT_VTD` and Intel DMA lifecycle implementation | No equivalent verified Realtek mapper implementation |

Relevant donor commits: `36d5e28` (channel information), `94a7b41` (traffic
counters), `572f195` and `03d6edf` (scan timing), `a01d1d5` (link quality),
`153f6cf` and `9bc4b4d` (AppleVTD). Their presence in donor history is not a
hardware-validation claim for AirportRTW.

## Backend integration differences found during hardware debugging

- Realtek `attachNet80211` zeroes `ieee80211com`. Installing the frontend event
  callback before this attach erased it; registration was moved after attach.
- Realtek advertises `RX_INCLUDES_FCS`. Its bridge bypasses Linux mac80211, so
  it must remove the four-byte FCS itself. Removing it eliminated the measured
  undersized-IE errors. Intel's receive pipeline is a different implementation.
- Realtek chip initialization encountered a MAC already powered on while the
  fresh software POWERON flag was clear. The macOS power-off guard prevented
  recovery. Adopting confirmed MAC_ON into the software flag restored attach.
- Realtek receive callbacks attempted valid WCL result messages outside the
  native gate: 66 posts returned `kIOReturnNotPermitted`, while ScanDone posts
  succeeded. The current scan-gate build replays the retained cache before
  gated completion. Hardware validation of that build is still pending.
- Intel installs `iwx_bgscan`; Realtek lacks `ic_bgscan_start`. Connected
  Realtek scans currently use cached results rather than off-channel discovery.

## Porting boundary

The missing native channel-info method is a direct frontend port candidate.
Traffic counters need matching Realtek/net80211 accounting. Scan timing,
background scans, DMA/AppleVTD, reset and RX handling require Realtek-specific
implementations; Intel hardware code cannot be made equivalent by renaming.
Do not replace the Realtek backend with the donor's Intel HAL or discard the
measured recovery, event-registration and FCS fixes.

## Implementation progress after comparison

Native `getCHANNELS_INFO` and `getWCL_TRAFFIC_COUNTERS` have now been ported.
Realtek TX submission and validated net80211 RX data update the per-AC counters.
Host protocol checks cover channel layout/bounds and traffic counter snapshots.
Both new methods, scan-gate result delivery, and association still need hardware
validation. Background scans, home/away timing, enhanced link quality, and
AppleVTD remain outstanding. Keep changes uncommitted until the agreed
implementation and hardware checks are complete.
