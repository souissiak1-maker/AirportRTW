# Native AWDL receive metadata audit

This audit corrects the earlier assumption that native metadata offset +44 was a
radio timestamp. It is a signed RSSI field on the inspected local native family.
No driver reads or writes private peer-manager ivars; offsets below document
binary research only. Runtime code packs the driver's metadata header and calls
the exported interface entry point.

## Inspected binaries

- IO80211Family 1200.13.1, SHA-256
  `c24e8f9d95ca2f5c59b61334d3ff75cf83727a4ef9723cbdbb386dd62c957d35`.
- AppleBCMWLANCoreMac 1.0.0, SHA-256
  `c4a9243489dfeb56773c686435594a5d1ce8d0b19a884e1122acac2e14a75d21`.

These hashes identify local files, not compatibility with every Tahoe build.
Future native ABI changes require rechecking the consumed metadata fields.

## Evidence for signed RSSI at +44

In local `IO80211AWDLPeerManager::actionFrameProcessInput`, file offsets 0x8b6dc
and 0x8b6fe load metadata +0x2c. They compare it with manager ivars +0x281c using
signed `jge` / `jl` branches. The latter field is written as -70 (0xffffffba) in
`initParamsToDefaults` at 0x44727. `determineAndSetEdgeRssiThreshold` also writes
negative signal thresholds at that location (including 0x5da0a / 0x5db1e).
A low RSSI can therefore prevent creation of a peer; this is not timestamp aging.

The local Broadcom `handleActionFrame_rx` passes metadata at stack base -0x78.
For its v1 event it loads event +0x34, byte-swaps the firmware value, and stores it
at -0x4c, which is metadata +44 (0x15ec55 through 0x15ec5c). The v2 branch does
the analogous conversion from event +0x38 at 0x15ec97 through 0x15ec9e. The final
call passes exactly 0x48 bytes (0x15ef88 through 0x15ef9d).

The earlier RTL8814Native notes labeled this field a timestamp despite marking
its meaning uncertain. AirportRTW inherited that interpretation in comments;
those comments are now corrected. Clock conversion remains necessary for radio
scheduling/timeline events, but must not be applied to this RSSI field.

## Implemented metadata packing

`RTWAwdlNativeRxMetadata.hpp` packs an owning 72-byte header containing:

- Actual source MAC at +0, checked for nonzero unicast.
- The provider's supplied 12-byte `apple80211_channel` at +12.
- Measured negative RSSI in native x86 little-endian signed form at +44.

Unknown fields are zero. The helper does not invent timestamps, infer bandwidth,
select a channel or assert regulatory permission. The provider must supply the
actual validated channel descriptor. A zero/positive or out-of-range signal is
rejected rather than being used to fabricate a strong signal. This implements
the fields established by this audit, not a claim that every unknown field has
been characterized or that hardware peer discovery has passed.

## Native workloop adapter

The concrete interface can queue these actions from a receive worker. The
native datapath owns copies of the complete frame and all 72 metadata bytes in
a separate 16-slot ring. Producers only copy/signal; no native family call or
blocking workloop gate runs on the HAL receive worker. The event drains actions
before bulk Ethernet RX. Native buffer allocation and bpfTapInput happen on the
native workloop, with the original caller storage free to disappear immediately.
A heap scratch slot avoids adding a 4 KiB frame above the native parser stack.

Disable/stop discards pending actions. Native callback rejection drops one
frame without retrying indefinitely. Resource factories unwind every added
allocation; event delivery retains the datapath through callback-driven stop.
Tests cover caller storage reuse, overflow, malformed/incorrect metadata lengths,
allocation rollback, action priority, reset, rejection and stop from a callback.
The native interface also retains itself during a native input call.

No native Control provider currently binds the HAL receiver to this interface.
The provider, peer policy, native synchronization controls and timed radio
scheduler are still required. There is no end-to-end discovery test and no
AWDL/AirDrop capability advertisement.


## Additional explicit event-clock field

A subsequent native audit confirms that actionFrameReport loads/byte-swaps
metadata +48 independently of RSSI +44. The packer can now copy an explicitly
valid RX clock into +48 in big-endian order. It leaves the field zero otherwise;
it never treats the HAL's raw device clock as interchangeable with the native
event domain. See AWDL_NATIVE_WINDOW_EVENTS.md for the audited instructions,
window event layouts and remaining backend clock responsibilities.
