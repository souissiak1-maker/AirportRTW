# AWDL feasibility and implementation boundaries

Baseline 68f35fa; assessment only. No AWDL capability flags, awdl0 interface,
Apple binary hooks or claims of functional AirDrop are added.

## Observed implementation state

Both Rtw88LinuxBridge and Rtw89LinuxBridge allocate a single station VIF with
NL80211_IFTYPE_STATION and manage a single current AP/station association.
Their scan entry/exit changes receive filters and channel ownership for scanning.
There is no shared AWDL peer table, availability-window scheduler or AWDL data
encapsulation path in these bridges. Sharing one radio between infrastructure
and AWDL requires deliberate channel scheduling and lifecycle arbitration;
reusing scan channel switching without this can disrupt the working AP link.

The local RTL8814Native Source/AirLayer/AWDLInterface.cpp explicitly describes
stage 1: optional role-6 interface creation, queues with no data-path action,
and unsupported AWDL requests. Its README says AirDrop is unavailable. It is
useful as interface/ABI research, not evidence of a working AWDL implementation.
Private symbols and hardcoded layout offsets are version-specific and must not
be copied into our common core without per-target validation and fallback.

## Architecture to preserve

Shared protocol owns peer discovery, synchronization, election, availability
windows, frame validation/encapsulation and teardown. RTWCore exposes optional
radio capabilities; RTWCore88/89 implement hardware-specific operations. Native
Tahoe/Sequoia frontend owns role-6 interface and Skywalk packet queues. No USB
backend, duplicate supplicant, or protocol implementation inside a HAL.

## Staged acceptance gates

1. Radio feasibility: per-HAL management action TX/RX, timestamp precision,
   off-channel duration/switch latency, filtering, secondary MAC/VIF limits,
   STA coexistence, regulatory constraints, cancellation and suspend safety.
   Presence of Linux APIs does not prove these operations work in our bridge.
2. Protocol host tests: bounded AWDL TLV parser, malformed/truncated frames,
   peer lifetime, election/synchronization, availability-window schedule and
   wraparound; use independent captures/specification research as references.
3. Native interface: validated ABI by supported OS, working TX/RX completion,
   ownership and backpressure; clean failure and teardown. Interface creation
   alone is not a feature milestone for AirDrop.
4. Radio discovery and data: peer discovery with actual Apple device, channel
   synchronization, IPv6 neighbor discovery and traffic while STA remains usable.
5. Product validation: bidirectional AirDrop transfers, reconnect, concurrent
   AP traffic, suspend/resume and negative/unplug paths. Advertise support only
   after the implemented path meets these gates.

## Immediate next work

Measure and expose radio capabilities before introducing an active scheduler.
RTL8814Native documents are a useful checklist, but its stage-1 scaffolding does
not fill the missing protocol/data path. PMF audit work is isolated separately
on experiment/rtw88-pmf-audit; neither project depends on enabling flags early.

## Stage 1 implemented: passive shared action-envelope parser

include/AWDL/RTWAwdlFrame.hpp now validates complete unencrypted, unfragmented
802.11 vendor action frames with Apple OUI 00:17:f2, AWDL type 8 and nonzero
version. It walks the 16-byte body header followed by u8/LE16 TLVs with bounded
lengths and no allocation. Unknown/repeated/zero-length TLVs are accepted;
malformed/truncated TLV envelopes are rejected. Contents are not yet decoded
into synchronization, channel scheduling, election or trusted peer state.

The two HAL receive callbacks invoke the same passive observer only in Debug
builds. It adds no TX, off-channel operation, filter change, event-source lock,
virtual interface or packet consumption. Frames retain their existing receive
path. The observer stores no addresses or payloads. Watchdog publication uses
existing controller properties; the sanitized collector explicitly whitelists:
RTWAwdlValidActions, MalformedActions, SyncEnvelopes, ChannelEnvelopes,
LastFrequency, LastVersion and LastSubtype (all prefixed RTWAwdl).

Counters indicate framing only. SyncEnvelopes/ChannelEnvelopes mean a TLV type
was present, not that its body or schedule was semantically valid. Last fields
are best-effort metadata, not a synchronized packet trace. Existing hardware
filters may discard AWDL frames; zero counters do not prove no nearby peer or
lack of hardware support. No monitor/promiscuous mode is enabled for the test.

Host tests cover prefix truncation, invalid envelope/version, oversized TLVs,
unknown/duplicate/zero-length TLVs, protected/fragmented exclusions, observer
counts and 20,000 deterministic randomized buffers under ASAN/UBSAN. Synthetic
framing tests are not Apple-device interoperability or air-capture validation.

References used for format research (no OWL code copied):
- https://github.com/seemoo-lab/owl (GPL-3.0 user-space reference; Linux daemon
  interfaces are not imported into this GPL-2.0/BSD kernel module).
- Local RTL8814Native/Docs/AWDL_FRAME_WIRE_FORMAT.md and stage-1 interface notes.

Next gates remain: independent on-air capture validation, per-HAL radio
capability measurement, timing/election/channel handling, native role-6 queue
integration, and bidirectional Apple-device traffic. Stage 1 does not enable
AirDrop, create awdl0, or justify advertising AWDL support.

## Stage 1 receive-filter experiment

The initial passive test returned zero AWDL counters on the local RTW89 system.
That alone is not a parser bug or proof that the AP radio channel carries AWDL.
The driver configure_filter callbacks reveal other-BSS/address and multicast
filtering separate from the observer. A new Debug-only opt-in property,
RTWAwdlDiscovery (boolean on the AirportRTW controller personality), requests
FIF_OTHER_BSS, FIF_BCN_PRBRESP_PROMISC and FIF_ALLMULTI via normal HAL callbacks.
It does not request bad-CRC reception or alter TX/channel/regulatory settings.
The source default is off; the dedicated test package enables the property on
NetworkController. It is ignored by Release builds.

A shared policy combines discovery, scanning and ordinary multicast settings.
Both bridges retain discovery after scan completion and multicast updates;
when disabled they restore the current ordinary multicast/scan policy.
Existing wiphy-lock ownership is preserved without nested acquisition. The
power-down path marks the applied state false; enable reapplies the opt-in.

RTWAwdlFilterRequested and RTWAwdlFilterAccepted report requested policy and
flags accepted by the callback, not a hardware register read-back. New counters
ActionFrames, VendorActions and AppleVendorActions show earlier classification
boundaries without retaining addresses or payload. All have RTWAwdl prefix.
Existing receive validation remains in place. Broader reception can increase
interrupt/CPU load and must be tested for normal AP traffic and sleep behavior.

The host test executes both production helper functions with simulated driver
callbacks to verify filter transitions, multicast coexistence, rejected flags,
power-off/missing-ops guards and single wiphy-lock ownership. It does not prove
hardware filtering, timing, power transitions or AWDL interoperability.

Capture with a nearby Apple device actively showing AirDrop. Same-channel RX
is a prerequisite; common discovery channels include 6/44/149 (reference:
RTL8814Native/Docs/AWDL_ETAPAS_2_A_4.md), but no automatic hop/scheduler is added.
If counters stay zero, first check channel and boundary counters; do not infer
that enabling a support flag or creating awdl0 would solve it. Full AWDL/AirDrop
remains unavailable.

## Bounded multi-channel discovery test

The filter test received ordinary action frames but no Apple vendor actions on
local RTW89. This does not yet justify an associated off-channel scheduler:
the existing net80211 scan transition explicitly disassociates its station.
Using that transition while claiming STA coexistence would regress connectivity.

`tools/awdl_discovery/run.py` instead runs up to three ordinary CoreWLAN scans
only after the user disconnects. It requires known INIT/SCAN state, no valid
port and the accepted discovery filter before compilation and before each scan.
The OS/driver owns channel selection and regulatory restrictions; there is no
hardcoded RF channel or forced disconnection/reconnection. Each scan has a
20-second timeout and a concurrent bounded sanitized registry capture. Scan
results and addresses are never printed. An auto-join can race the precheck:
disable automatic joining for the test; this tool is not a kernel channel arbiter.
A scan is not synchronized AWDL listening and can miss peer transmissions.

Run with the current discovery-filter test kext, a nearby Apple device actively
showing AirDrop, and Wi-Fi powered on but disconnected:

    python3 tools/awdl_discovery/run.py --interface en2 --output /tmp/awdl-discovery.json

Use the actual Wi-Fi interface name. Xcode command-line tools are required.
This is a diagnostic companion to the existing kext, not a new AWDL/AirDrop
implementation. No automatic hardware scan is run during development checks.

## Shared transmit template and radio ownership foundation

`RTWAwdlTxTemplate.hpp` owns and validates up to 4096 bytes of action body,
retaining the previous template if a replacement is invalid. It builds a complete
24-byte management header with explicit AWDL source/destination/BSSID, a 12-bit
sequence number and per-transmission LE32 time fields. It does not borrow ioctl
memory, allocate, send, select channels, or infer the radio clock's units. Template
subtypes are restricted to 0/3. Native template request layout and clock-domain
conversion still need integration; this class is not yet called by the HALs.

`RTWAwdlRadioCoordinator.hpp` models exclusive asynchronous channel leases,
explicit switch completion, bounded deadlines, return-home retries and stale
callback invalidation after shutdown. It denies associated excursions unless
concurrent-station support is explicitly supplied. It is bookkeeping only:
providers must implement regulatory checks, serialize/quiesce physical switches,
restore the entire home channel definition (including width and center frequency),
and handle cancellation and suspend. A generation token prevents stale software
callbacks from advancing state; it cannot undo an in-flight hardware command.
The coordinator is not yet attached to either HAL and creates no radio timer.

Host tests exercise template ownership, replacement failure, bounds, maximum
length, sequence/timestamp serialization, invalid addresses, lease exclusivity,
unsupported coexistence, timeout, restoration failures/retry, overflow and stale
completions with ASAN/UBSAN. These tests are not interoperability validation.

Native integration audit: the repository's common IO80211VirtualInterface header
is the older IOService-derived class. The local RTL8814Native reference instead
declares Tahoe's Skywalk-derived virtual/AWDL protocol chain and 63 AWDL methods,
with declarations researched against Darwin 25.6. The local running kernel is
25.5. Reusing the old class declaration for native Tahoe would dispatch through
incorrect virtual slots. A matching native AWDL class/queue/peer-manager contract
must be established before instantiation; no guessed vtable offsets or synthetic
AWDL support bits are introduced here. Election/synchronization, native queues,
radio operations and AWDL IPv6 data transport remain unimplemented.

## Native Tahoe ABI and IPv6 wire codec implementation

The native Tahoe controller now includes a separate Skywalk-derived virtual/AWDL
protocol declaration. It preserves the older frontend's class declaration and
adds no global header replacement. The new declaration adapts GPL-2.0
RTL8814Native AWDLInterface.h (DrogaBox, 2026), with return types matched to our
existing native base declarations and opaque ABI aliases retained for inherited
slots whose parameter types are not modeled. Opaque uintptr_t declarations are
not approved callable APIs. No concrete AWDL interface is instantiated yet.

`rtw_awdl_native_abi_test.py` compiles a virtual-call probe with the Tahoe target
response file, validates class-size assertions, the virtual-interface boundary,
setMacAddress pure slot and all 63 consecutive AWDL request slots. An optional
`--family` argument inspects the x86_64 Mach-O slice, symbols and external
relocations from an on-disk family binary. It verifies the actual pure slots and
init/setLinkState boundary. This optional check passed against the local Darwin
25.5 IO80211Family; it is not blanket verification of every method signature,
queue ownership rule or future Tahoe release. The combined-HAL Debug Tahoe build
passed after including the declaration in the real native controller.

`RTWAwdlData.hpp` independently implements unencrypted, unfragmented single-MPDU
AWDL IPv6 framing, both QoS and ordinary-data receive forms, explicit AWDL BSSID,
Apple LLC/SNAP and sequence handling. It bounds the IPv6 MTU to 1428, validates
IPv6 lengths, and rejects unsupported protected/HT-control/aggregate frames.
It does not handle A-MSDU, choose admitted peers, deduplicate, transmit or deliver
Skywalk packets. It is not yet wired into the HAL receive/transmit paths.
Tests cover round trips, maximum MTU, invalid headers, truncated prefixes and
20,000 randomized buffers under ASAN/UBSAN. They do not establish on-air interop.
Wire-format research references (protocol facts only; no GPL-3.0 code imported):
https://github.com/seemoo-lab/owl/blob/master/src/frame.h
https://github.com/seemoo-lab/owl/blob/master/src/tx.c

Remaining radio integration finding: RTW89 exposes Linux remain_on_channel and
cancel_remain_on_channel, but compat ieee80211_ready_on_channel and
ieee80211_remain_on_channel_expired are currently no-ops. The latter notification
occurs before the driver's restore sequence, so it must not be treated as proof
that RF has returned home. RTW88 does not provide equivalent ops in its current
mac80211 callback table. Neither existing software scan path supplies a safe
associated AWDL scheduler. These differences need actual per-HAL implementations,
not a shared capability flag or an unconditional success return.
