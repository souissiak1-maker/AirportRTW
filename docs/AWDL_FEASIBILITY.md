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

## Radio timing transport and availability arithmetic

Both Linux RX drivers already mark RX_FLAG_MACTIME_START and provide the low
32 bits of their radio RX timestamp (RTW88 tsf_low, RTW89 free_run_cnt). The native
receive callback previously discarded this field. Both bridge/core contracts now
carry the raw low word and its validity separately, through the same CRC-checked
frame callback. Zero is a valid timestamp; absence must use the validity bit.
No hardware register reads, timer callbacks or new locks are added to RX.
The Debug AWDL observer retains the timestamp only for validated AWDL action
frames and publishes TimedActions and LastRadioTimestamp numeric fields. It
still observes rather than consumes frames. All callers are built together;
this internal callback is not a public ABI or a packet buffer ownership change.

`RTWAwdlClock.hpp` provides relative 32-bit radio timestamp extension with explicit
reset, out-of-order rejection and rejection of gaps long enough to make wrap
count ambiguous. Radio time is not host monotonic time. Calibration between
these clock domains, and freshness of peer synchronization, remain necessary.
The helper is not yet used to arm a radio timer or accept a master's epoch.

AvailabilityClock implements accepted-epoch/counter arithmetic, TU conversion,
16-bit availability counter wrap, guard intervals, boundary deadlines and
checked overflow. Invalid configuration preserves the prior accepted schedule;
reset invalidates it. The caller must establish the epoch in a single clock
domain before use. Tests cover timestamp/counter wrapping, ambiguous gaps,
backward host samples, interval boundaries, guards, reset and UINT64 overflow.
This arithmetic is not a synchronization/election algorithm or radio scheduler.

No new user hardware test package is produced for this intermediate work. Full
native queue delivery, peer-manager event/template integration, election/sync
integration, per-HAL off-channel execution and end-to-end AirDrop remain open.

Native template contract checked against the local Darwin 25.5 family binary:
`IO80211AWDLPeerManager::updateSyncFrameTemplate(bool)` builds service/election
and other TLVs into a 512-byte stack buffer, writes its pointer into request+8
and its populated length into request+4, then issues ioctl 151. Its buffer does
not contain the 16-byte vendor-action envelope. `TxTemplate::replaceTlvs` now
validates and copies this TLV-only form and constructs an explicit versioned
subtype-0/3 envelope. Complete radio bodies continue using `replace`. Invalid
updates preserve the previous template. Neither API borrows the native pointer.
This adapter is not a native setter implementation or an action transmitter;
dynamic synchronization parameters still require the radio-side engine.
Research disassembly: `/tmp/awdl-native-template-contract.txt` (local-only,
reproducible using lldb disassemble by the function's exported symbol).

## Workqueue cancellation prerequisite

Both HAL compatibility queues previously implemented cancel_work_sync by setting
pending=0 without unlinking queued entries or waiting for a running callback.
Requeue after such cancellation could insert a still-linked node twice. Queue
flush also checked only list emptiness, so a callback already removed from the
list could continue after a caller believed the queue was drained.

The queue now tracks its currently executing work independently of the work
object. Pending cancellation unlinks under the owning queue lock; synchronous
cancellation waits for a running callback and blocks its requeue during the wait.
Queue drain waits for execution as well as queued entries. A worker does not
access work memory after calling its function, permitting self-freeing work.
Delayed work remembers its requested queue instead of always dispatching to
system_wq and initializes its reusable timer once.

Contracts: stop producers before draining/destroying a queue; keep the owning
queue alive during cancellation; serialize migration of a work object between
queues; never synchronously wait while holding a callback's required lock.
Self-waits do not block the single worker. Work owner publication uses atomic
release/acquire operations. These are prerequisites, not AWDL radio operations.

The threaded host test executes both production implementations with IOLock and
kernel-thread adapters under ASAN/UBSAN. It checks queued cancel/requeue list
integrity, running drain, cancellation's requeue gate, delayed target routing,
self-requeue and self-free. The host timer is manually fired: these tests do not
validate XNU thread-call cancellation. In particular, the existing RTW89 local
thread_call_cancel_wait shim uses a fixed delay; timer cancellation/barrier and
wiphy-work serialization require separate work before enabling the AWDL ROC
scheduler. This milestone must not be described as making all timer teardown
safe or providing functional AWDL.

## Native packet resources and action ingress

The Tahoe target now compiles AirportRTWAwdlDatapath.cpp. This resource layer
creates real native TX submission/completion and RX completion queues with one
pool per direction, disabled until its owner enables them. The concrete role-6
interface still must register the queues and attach the radio runtime. No current
controller path constructs the resource layer or advertises AWDL support.

TX borrows native packet bytes only for the synchronous sender callback. The
sender must copy before reporting acceptance; busy leaves the unconsumed suffix
owned by the native submission queue. Invalid/unsupported Ethernet frames are
consumed as drops, so an IPv4/malformed head cannot indefinitely block IPv6.
Completions are batched below queue capacity, and failed completion hands packets
back to the correct pool exactly once. Native view bounds include buffer count,
offset, length and address-addition overflow.

RX copies validated IPv6 Ethernet frames into a 64-slot staging ring under an
interrupt-safe lock and signals a software interrupt source. Family pool/queue
operations happen on the native workqueue, outside radio locks. Allocation,
preparation and enqueue failures release the packet through its own pool. Radio
TX-ready notification also signals the workqueue rather than entering its gate.
The parent must keep the sender alive and quiesce its callbacks before final
release; the sender cannot reentrantly tear down the native datapath. Stop is
idempotent. Factory failures explicitly stop partial resources before release to
break potential queue/pool owner-reference cycles.

Host tests execute the actual transport source with family/IOKit adapters and
ASAN/UBSAN: every allocation and addEventSource failure, owner-retaining pool
cycles, staged RX, overflow, allocation/prepare/length/enqueue failure, TX busy,
invalid TX, completion failure and repeated teardown. These adapters are not
hardware or real-family lifetime tests. The combined-HAL Tahoe build passes;
all 17 imported packet APIs were found in the installed IOSkywalkFamily.
Local enqueuePackets disassembly confirms TX completes packets directly and RX
routes them to networking; the idle completion actions take no packet ownership.

AirportRTWAwdlActionInput.cpp implements native action-buffer ownership transfer.
It rejects malformed/protected/fragmented actions, mismatched source metadata and
any metadata size other than 72, before allocating. It uses the family's concrete
IO80211MallocBuffer factory (48-byte options, capacity first), copies the action
body and hands it to VirtualInterface::bpfTapInput as DLT 12. The native family
owns the buffer after handoff, including rejection paths. The caller supplies verified source/channel/RSSI metadata; native metadata +44
is signed RSSI, as corrected in the receive-adapter audit below. This helper
does not report peer acceptance. Host tests cover header
bounds, malformed input, allocation failure and asynchronous ownership. Buffer
factory, options and returnBuffer semantics were checked in the local family's
MallocBuffer/Pool disassembly. No vtable indices or fabricated IO80211Buffer
objects are used by this helper.

Both components are inactive until role-6 lifecycle and radio integration are
implemented. Their presence in the binary is not working AWDL/AirDrop.

## Concrete native role-6 lifecycle

AirportRTWAwdlInterface now implements the concrete native IO80211AWDLProtocol
class, queue registration/getters, role-6 naming, enable/disable, MAC changes,
controller publication and teardown. Native family base queue getters return
null in the local binary; the concrete interface overrides them to return the
actual packet resources. All 63 protocol requests synchronously forward to a
controller-owned Control provider and propagate its result. There are no
unconditional-success placeholder control handlers. Native request payloads are
borrowed only during dispatch and retain their family-defined layout.

The factory requires every protocol/radio capability plus ready hardware,
rejects invalid MACs and an existing controller AWDL interface before allocation,
and prepares the provider before native base start. Partial prepare is followed
by shutdown, partial native initialization uses the appropriate base cleanup,
and failed publication terminates/detaches the partial service. Stop runs under
the native workqueue gate, stops producers before packet resources, clears the
controller pointer only if it still owns it, and is idempotent. A provider must
quiesce callbacks synchronously on shutdown and may not reentrantly tear down
from packet send. Address changes reach the provider before updating native MAC
state. Data callbacks use the bounded datapath; action callbacks must already be
on the native workqueue with verified source/channel/RSSI metadata.

The native WME category forward declaration now uses an opaque 32-bit enum,
allowing a correctly typed submission-queue getter instead of an incomplete
struct parameter. Existing method symbol names and slot positions are unchanged.
The concrete ABI test checks all 63 overrides in their expected slots; inspection
of the built object's inherited native imports found their provider symbols in
the installed IO80211Family/IOSkywalkFamily (excluding the separately linked
AirportRTW action-ingress helper).

Host tests execute the actual interface code against lifecycle adapters: every
capability gate, failed prepare/start/registration/publication, all 63 requests
and result propagation, offline enable, MAC failure/success, packet enable/disable
and repeated stop/termination. They do not validate real family matching or
on-air behavior. Real Tahoe compilation checks the class is concrete and its
native inheritance/overrides type-check against the target headers.

No production controller path calls the factory yet. There is no concrete
Control provider for RTW88 or RTW89; clock/protocol integration, radio scheduling,
peer hardware state and quiescent radio teardown still need implementation.
The normal capability advertisement and VIRTUAL_IF_CREATE unsupported result
remain unchanged until that provider exists. This is inactive frontend
implementation, not functional AWDL/AirDrop.

## Multiple interface and peer registry

Both HAL compatibility layers now compile the same bounded registry implementation
(four interfaces, 32 peers per HAL). Secondary registration has explicit failure
results; existing primary-station APIs retain their behavior without clearing
secondary state. Peer lookup matches the owning interface and the by-ifaddr
variant honors the hardware and local address. Duplicate live peer identities
within one interface and pointer migration between interfaces are rejected.
Removing an interface removes only its own peer entries, not their allocations.
The bridge remains responsible for hardware removal and freeing memory.

A recursive registry lock covers mutation and iterator callbacks, so removal
waits for in-flight iterators before the caller frees a peer. Iterator callbacks
must not free registry entries. Borrowed lookup pointers are not protected after
lookup returns: their callers still need teardown exclusion throughout use.
This does not supply RCU or solve cross-driver lock ordering. Future secondary
radio operations must serialize peer removal with all driver users before freeing.

Host tests cover per-interface lookup with identical remote MACs, primary-only
cleanup, bounded capacity, duplicate rejection, slot reuse, hardware mismatch,
reset and removal waiting for a live iterator under ASan/UBSan. The new API is
namespaced for the RTW88 archive to preserve combined-HAL linkage. No secondary
hardware VIF or peer is created yet; this removes a compatibility-layer blocker,
not the remaining radio/protocol implementation.

## Secondary hardware interface lifecycle

The RTW88 and RTW89 bridges now expose add/remove operations for a separate
AWDL MAC identity. They allocate their own ad-hoc VIF/private area, link-0 BSS
record, canonical AWDL BSSID and (RTW88) driver-private TX queue, then invoke the
real driver add-interface callback. Registration occurs only after hardware
setup succeeds. BSSID programming uses the driver's link/BSS update callback;
missing lifecycle or BSSID callbacks reject creation. Allocation, hardware-add
and registry failures unwind in reverse order. Power-down removes the secondary
interface before infrastructure teardown or hardware stop. Invalid/duplicate MACs,
repeated creation, stopped hardware and active scanning reject creation.

This interface explicitly requests no ordinary IBSS beacon. RTW88 skips the
reserved beacon page and beacon-function enable while keeping automatic beacon
TSF updates disabled. RTW89 clears beacon TX and beacon RX clock synchronization
for this mode. Infrastructure and ordinary ad-hoc interfaces retain their previous
policy. RTW88 also releases the allocated MAC ID on exhausted-port and unsupported
interface-type failures, which matter when a second hardware port is requested.
The donor provenance record documents these intentional changes.

Host tests execute the shared lifecycle against allocation/driver adapters,
checking exact allocation/free sizes, failure cleanup, registration ordering,
BSSID notification and idempotent removal. Separate tests execute production
RTW88 add-interface code and RTW89 register policy functions to check ordinary
modes, non-beaconing mode and failed-add MAC-ID cleanup. These are software tests,
not proof of firmware acceptance or RF behavior on every chip.

The protocol provider does not call these entry points yet. They allocate a radio
identity only: no peer is admitted, no channel is changed, no packet is transmitted,
and no native AWDL capability is advertised. The eventual caller must serialize
operations and quiesce TX, ROC and receive producers before removal; this helper
does not provide a DMA/ROC completion barrier. Timed channel scheduling, peer
hardware admission and native protocol control remain unfinished.

## Action TX and RTW89 peer hardware contexts

Both bridges now have a serialized action-frame submission entry point using
only the secondary hardware VIF. It requires running hardware, a registered
non-beaconing ad-hoc interface and no scan. The shared implementation validates
the complete action/TLV envelope, supported PSF/MIF subtype, local source MAC,
canonical BSSID and unicast or broadcast destination before allocation. The
requested frequency must match both current hardware channel state and the
secondary interface channel record. Disabled, no-IR, radar and no-OFDM channels
are rejected; channel 14 and non-2.4/5 GHz bands are excluded. This does not
relax regulatory flags or perform channel switching.

The skb owns a copy before the driver TX callback runs. It has no station/key,
no aggregation and no protected payload; unicast requests real TX status and
broadcast disables ACK. RTW89 uses an injected legacy rate descriptor for OFDM
6 Mbps. RTW88's management selector explicitly uses OFDM 6 Mbps for this mode,
including on 2.4 GHz; ordinary interfaces retain their previous rate selection.
Submission success transfers ownership to the driver and is not an RF ACK or
proof that the driver transmitted a frame rather than dropping a full queue.
Future scheduling must establish the actual RF lease and bounded submission
rate before calling; the software channel record is not an RF readback.

The RTW89 peer audit found that mapping a VIF to ad-hoc MAC mode was insufficient:
firmware role create/remove, per-peer address-CAM allocation and MAC-ID release
were conditional on AP/TDLS mode. Explicit non-beaconing ad-hoc mode now follows
the separate-peer context path. Each peer owns an address CAM and firmware MAC
ID but uses the interface's canonical BSSID CAM. It is not mislabeled TDLS and
does not borrow the infrastructure station context. Station and ordinary ad-hoc
predicates are unchanged. Hardware peer admission/lifetime and partial firmware
failure recovery still need integration before enabling any native capability.

Host tests execute the action submission implementation, including malformed
input, source/BSSID identity, channel/regulatory rejection, band-specific rate
indices, allocation failure, descriptor flags and ownership after caller-buffer
reuse. Production RTW89 selectors and role add/remove functions run against host
adapters for all station/AP/ad-hoc/TDLS combinations and firmware command errors.
Production RTW88 management-rate selection is tested with force-lowest mode.
These tests do not emulate firmware or prove on-air timing. The native provider,
RX dispatch, peer admission and synchronized radio scheduling remain unfinished;
there is still no production caller and no AWDL/AirDrop support advertisement.

The Linux-specific shared C++ helpers use internal linkage per translation unit.
Although their source is shared, RTW88 calls namespaced compatibility functions
and RTW89 calls its own compatibility functions; ordinary external inline
coalescing can select the wrong backend. A two-translation-unit host link test
checks that interface creation, registry updates and cleanup stay with the
calling HAL. Existing AP-mode address-CAM selection is preserved independently
of the new non-beaconing ad-hoc predicate, including other AP-mode roles.

## HAL receive handoff and common radio entry points

RTWCore now exposes secondary interface creation/removal, action submission and
receive registration through one hardware-independent contract. RTWCore88 and
RTWCore89 implement it using their separate bridges; native protocol code need
not downcast to a chip-specific core or import Linux/private Apple types into
shared HAL state.

Each bridge owns an RX registration lock allocated during attach. Successful
secondary interface creation opens registration with its MAC. Registered receivers
are retained OSObjects; replacing, clearing or closing registration waits for a
live synchronous callback, then releases ownership outside the lock. Removal and
power-down close registration before removing the secondary VIF. Driver/PCI
teardown must stop RX producers before the registration lock is destroyed.
Control operations must remain serialized on the controller workloop.

CRC-validated receive frames are classified before the normal net80211 handoff.
The separate receiver accepts supported AWDL PSF/MIF envelopes with canonical
BSSID, or fully validated IPv6 AWDL data framing, addressed to the secondary
station or a group and from a nonzero remote unicast source. Other traffic follows
the existing path. Callbacks borrow the skb only during the call and may copy or
enqueue, never wait for a workloop, reenter the HAL or change registration. Raw
RSSI/frequency and the device timestamp with a separate validity bit are retained;
no native-family timestamp or successful peer admission is invented.

DataCodec::inspect exposes a validated borrowed view used by both classification
and decapsulation; it avoids allocating a scratch Ethernet packet on the kernel
stack. When the secondary receiver is closed, an atomic gate avoids taking the
registration lock on ordinary RX. Tests cover allocation failure, object retain/
release, replacement, callback/close concurrency, destructor execution outside
the RX lock, address/framing rejection, IPv6 classification, zero-but-valid raw
clock values and the disabled fast path. Existing codec malformed-frame/fuzz
checks still pass. These are host ownership tests, not hardware latency or native
family delivery tests.

No native Control provider binds this receiver yet. It is an implemented HAL RX
endpoint, not completed native AWDL RX delivery. Radio-clock conversion, binding to the native
workloop event adapter, peer admission and timed channel scheduling remain before
an end-to-end discovery prototype can run. AirDrop support advertisement remains
disabled and no intermediate hardware installation is requested.

## RTL88WiFi reference integration

See [RTL88WIFI_REFERENCE.md](RTL88WIFI_REFERENCE.md) for the pinned source,
license/provenance, adopted wire decoding and the mechanisms still under audit.
The shared synchronization decoder is used by the Debug observer in both HALs;
`RTWAwdlSyncDecoded` and `RTWAwdlSyncDecodeFailures` expose numeric parsing
results. No untrusted peer clock or channel is adopted by observation, and no
Supported flag or host-clock fallback was imported.

## Native action receive queue and RSSI correction

The concrete Tahoe interface now stages owned action/metadata copies through a
16-slot native-workloop queue. Native action input runs outside HAL/spin locks,
actions precede bulk data, disable/stop discards pending work, and heap scratch
avoids a large parser-stack copy. The producer's buffers may be reused as soon
as enqueue returns. Callback-driven stop retains the datapath/interface safely.

The local native metadata +44 field is signed RSSI, not a timestamp. The manager
compares it with a negative RSSI threshold, and Broadcom converts its firmware
signal field before storing there. `queueRadioAction` now packs the measured
RSSI, actual source and supplied native channel descriptor. Radio-clock mapping
remains a separate scheduling concern. See
[AWDL_NATIVE_RX_METADATA.md](AWDL_NATIVE_RX_METADATA.md) for binary hashes,
function evidence, unknown-field limits and tests. The native Control provider
and scheduler remain absent, so these components are still inactive in the
production controller; no discovery or transfer success is claimed.


## Native control runtime

`AirportRTWAwdlRuntime.hpp` now implements `Control` with an owning configuration
snapshot and a `RuntimeBackend` contract. It validates native synchronization,
parent state, channel sequences, presence, election metric/ID, RSSI thresholds,
action mode and borrowed frame templates. Backend configuration is atomic:
failures preserve the accepted configuration. Reads use backend snapshots, and
channel queries report the backend's current channel rather than a requested
channel. Unknown/opaque requests return Unsupported, including AWDL_CONFIG.

Open rollback, activation, address changes, TX validation and shutdown are
implemented. Closing must quiesce producers and restore the infrastructure
channel before releasing radio resources. Frame-template request memory is
copied and validated before backend invocation, then erased; the backend must
retain its own copy. The runtime should be heap-owned in the kernel because
its template scratch storage is 4 KiB.

This is a concrete native control adapter, not a completed AWDL engine. No
RTW88/RTW89 RuntimeBackend exists yet, no production factory caller installs
this provider, and no capability flags were enabled. The missing backend must
integrate clock acceptance, timed radio ownership, native RX binding, peer
lifecycle and data TX/RX. Peer/election reporting beyond the supported requests,
advertiser updates and native timeline events also remain incomplete.

The runtime regression executes the production class with a fault-injected
backend and actual ioctl structure declarations, under ASan/UBSan. It checks
capability gating, partial-open cleanup, atomic configuration, regulatory
rejection (including aliased 6 GHz numbers), copying borrowed payloads, failed
template replacement, TX bounds, device loss and idempotent shutdown. The real
native-header compilation verifies ABI sizes; host adapters do not validate RF
behavior or constitute AirDrop interoperability evidence.

Combined-HAL Tahoe Debug and Release builds pass with the control adapter
header included by the native interface translation unit. Nothing was
installed to EFI or published.


## RTW89 secondary-interface ROC power-save admission

The driver ROC path previously sent its nullfunc through the requesting VIF.
For AWDL's quiet ADHOC VIF, `rtw89_core_send_nullfunc` deliberately returns
without transmitting: only associated station VIFs have an AP to notify.
It therefore provided no infrastructure power-save handshake.

ROC admission now finds associated station links sharing the requesting
channel context, sends PS=1 through those links and requires successful TX
completion before the retune sequence. Missing station links, missing request
links and another live ROC owner reject admission. Failure attempts PS=0 for
all affected stations on the home channel, resumes the paused context and
returns the error through the mac80211 ROC operation. The secondary VIF is
never used to fabricate a successful AP notification. ROC end likewise sends
PS=0 through the associated stations. Expiry notification now occurs after
restoration/wake calls, rather than before them.

The regression executes the production admission/end functions with radio/TX
adapters under ASan/UBSan. It covers a secondary requester, multiple station
links, unrelated channel contexts, disconnected stations, a failed second
PS notification, failed rollback wake, concurrent ownership and missing links.
Backend source-isolation/provenance checks also pass.

This change is RTW89-only and does not implement RuntimeBackend or an RTW88
radio scheduler. It does not resolve the remaining compat wiphy-work
serialization/cancellation problem, establish timestamp calibration, propagate
all retune/restore hardware errors, or constitute on-air AP/AWDL validation.
The native provider is still not installed and no support flags were enabled.

## Shared election engine and captured synchronization regressions

The shared decoder previously rejected both retained iPhone synchronization
captures from MtkWireless. It now separates synchronization-source and election
root identities, and uses the explicit operating-class channel list when an
embedded legacy list describes center channels. Shape conflicts remain invalid;
6 GHz operating classes are rejected by the supported profile. Sanitized
fixtures/provenance are documented in AWDL_CAPTURE_FIXTURES.md.

RTWAwdlElection.hpp now supplies a hardware-independent peer/election/software
clock engine adapted from the reference C++ implementation, using our decoder.
It requires a caller-provided initial plan, defaults to native-controlled peer
selection, maintains bounded peer ownership, freezes controls during an open
window, and accepts explicit wire clocks when serializing synchronization.
The reference's older replay implementation and MediaTek ROC code were omitted.

The engine is not yet bound to native availability-window events or a concrete
RTW88/RTW89 RuntimeBackend. Radio timestamp/event-domain integration and channel
ownership remain gates. No AirDrop capability was enabled or end-to-end behavior
claimed. Host tests and actual native-header compilation cover this component;
they do not establish on-air interoperability.

Both combined-HAL Tahoe Debug and Release builds pass with the shared engine
header compiled through the native runtime. Runtime/interface/datapath/action
regressions and both backend validators also pass.


## Checked manual RTW89 radio reservations

The RTW89 driver now provides a separate manual ROC entry for a quiet secondary
ADHOC VIF. It rejects scans, overlapping owners, disallowed/passive/DFS/no-OFDM
channels, unsupported bands and visits above 100 ms. A successful return means
the driver completed channel programming; it does not assert an RF ACK or
physical synchronization. The native owner must arm its bounded deadline before
entry and serialize reserve/restore calls on its workloop.

Manual visits do not queue a compatibility ROC expiry worker or emit legacy
ready/expired callbacks. This lets the native scheduler own expiry without two
independent timer paths. Channel-programming errors now propagate; failed entry
attempts home restoration, and restoration/wake errors retain recovery ownership
instead of announcing a completed return. Retrying restoration remains possible.
The saved infrastructure chandef stays in the driver channel context; it is not
replaced by a synthesized 20 MHz home channel.

The RTW89 bridge exposes reserve/restore primitives and verifies the live radio
channel before action submission. Off-channel action TX no longer mistakes the
saved infrastructure chandef for the current channel. It rechecks the current
regulatory table before submitting, rather than trusting only the lease's copied
channel flags. RTW88 keeps its existing current-channel behavior.

Primary software TX uses an atomic gate before dequeue. Reserve pauses new
submissions and drains existing guards before taking WiphyGuard or switching.
The wait is bounded; timeout restores normal queue progress without attempting a
radio visit. Successful home restoration reopens the gate and invokes TX wake
outside WiphyGuard. Recovery errors keep it closed. This gate does not drain
hardware DMA queues and is not a replacement for driver channel-context pause.

Host tests execute the production driver/glue and bridge functions with injected
TX, retune, restore and wake failures. They verify bounded admission, single
expiry ownership, recovery state, regulatory rejection, queue ownership and
cross-HAL action-helper isolation. A threaded sanitizer test exercises the
cross-atomic pause/drain handshake.

These primitives do not yet install a native RuntimeBackend or timer owner.
Teardown/device-reset recovery, all scan/join arbitration, peer/data TX binding,
native availability events and remaining compatibility-work lifecycle issues
still need integration before active use. No capabilities were enabled.

## Backend build failure propagation

All three Xcode backend archive phases now use `set -euo pipefail`. Previously a
failed RTW89 archive script could be followed by successful RTW88/SAE scripts,
masking the failure with the phase's final zero status. A preliminary build in
this work exposed a missing include through this behavior; that output was
rejected and rebuilt after correcting the include and failure propagation.

The regression executes each real shell-phase script with failing archive
adapters and verifies later archives are not run. Earlier retained election,
ROC power-save and native-payload build logs were also checked and contain no
compiler errors.

The final combined-HAL Tahoe Debug and Release builds pass with no compiler
errors. The Release executable contains the new reservation/restore symbols.
Both backend validators and the radio, submission-gate, failure-propagation
and cross-HAL helper tests pass. No EFI was changed and nothing was published.


## Shared window scheduler and native event/timer transport

RTWAwdlWindowScheduler now coordinates the election engine with checked radio
visits and an explicit integration driver. It validates full window coverage,
suppresses start events after late/failed/wrong-channel visits, freezes native
controls while a window is open, balances end events across cancellation and
reentrant callbacks, and preserves recovery ownership when restoration fails.
Clock loss or a failed end handoff requires native reset; it does not invent
clock values or continue a broken timeline. TX opportunity checks enforce edge
guards and multicast slots independently of peer authorization.

AirportRTWAwdlInterface supplies the timer lifecycle and real native event
handoff. The Tahoe start-event ID is corrected from 42 to 41 based on the native
binary's jump table. RX metadata can now carry an explicitly valid big-endian
clock at +48, separate from signed RSSI +44. The actual clock mapping remains
an integration contract rather than a cast of raw radio timestamps.

Host tests compose the actual scheduler with the actual interface timer/event
methods and fault-injected radio behavior; they also test timer/resource errors,
shutdown from a callback, counter wrap, failed restores and lost clocks. Native
header compilation verifies existing slots and per-target event IDs. Details
and pinned native evidence are in AWDL_NATIVE_WINDOW_EVENTS.md.

No production RuntimeBackend or controller factory caller was installed. The
HAL adapter, peer/data binding, scan/join arbitration and reset/teardown recovery
still need completion. No AWDL capability was advertised or AirDrop claimed.
