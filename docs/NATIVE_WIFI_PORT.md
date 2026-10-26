# Native Sequoia/Tahoe frontend port

## Scope and provenance

The frontend and Apple ABI declarations originate from jzrodriguez98/itlwm
commit `7e50738b80e65630040e2da22d464d0d13c847d3`, incorporating laobamac's
implementation. Copyright notices are retained. The donor repository is not
required to build AirportRTW after this port.

Catalina, Big Sur, Monterey, Ventura and the two Sonoma targets retain their
controller/interface sources. The Sequoia and Tahoe targets use separate
controller/interface sources under `AirportRTW/WCL/`, with unique header names
to prevent Xcode header-map collisions with older targets. Apple headers dispatch
to macOS15/macOS26 only when `AIRPORT_WCL` is defined. Shared net80211 changes
are conditional on that flag.

## Realtek integration

- `RTWCore` owns the existing Realtek hardware/net80211 backend. The former
  standalone controller is `RTWEthernetController`, still in `RTWCore.kext`.
- Realtek power-up success/failure and power-down generate native driver
  availability notifications. No Intel firmware initialization task is assumed.
- Native scan requests feed the software scanner. Requested SSIDs, active/
  passive policy and channel restrictions are honored. Beacon/probe events
  publish scan metadata and IEs; explicit discovery does not auto-associate.
- While connected, scans return cached results because `ic_bgscan_start` is not
  implemented by this Realtek backend. Discovering new APs off-channel while
  retaining the current link requires additional hardware integration.
- WCL joins configure the existing net80211 SSID, BSSID and WPA parameters.
  Existing Realtek association and key callbacks remain the hardware path.
  WPA2-Personal uses net80211's handshake. Enterprise PMK delivery is inherited
  but unverified and must not be advertised as tested.
- Association failures, deauthentication, link authorization and fresh associated
  beacons feed WCL completion/link events.
- Private MAC changes update BSD and net80211, then restart the interface so
  Realtek add_interface programs the new vif address into its MAC table. The
  efuse/permanent address stays unchanged. Failed restarts restore the old
  software address and attempt recovery. This path still requires hardware
  validation. HE is not advertised until Realtek HE/rate support is tested.

## AppleVTD/DMA review — separate from root patching

The DMA transport has intentionally not been replaced as part of the frontend
port. Neither compiling WCL nor avoiding userspace root patches establishes
AppleVTD compatibility.

Findings in `Rtw89PciTransport.cpp` and `compat/linux/dma-mapping.h`:

1. `allocateDMA` prepares an `IOBufferMemoryDescriptor`, then returns
   `getPhysicalAddress()` to the hardware. There is no device-specific `IOMapper`
   or `IODMACommand` IOVA translation.
2. Streaming mappings allocate bounce buffers and copy at ownership boundaries.
   Bounce buffers alone do not provide IOMMU mappings.
3. `dma_set_mask`, `dma_set_coherent_mask` and their combined variant return
   success without recording/enforcing a device mask. The allocator currently
   constrains physical backing to a 32-bit mask.
4. Linux-derived PCI TX/RX paths can allocate/map buffers during operation and
   under synchronization. `IODMACommand::prepare` can block; replacing
   `getPhysicalAddress()` with a mapping call in those contexts is not sufficient.
   The bundled SDK explicitly documents the context restriction.
5. Deferred freeing already avoids releasing descriptors with preemption
   disabled, but mapping lifetime, reset quiescence and buffer reuse still need
   validation against the hardware queues.

Required implementation for verified VT-d operation:

- Obtain the PCI device's mapper and establish mapped `IODMACommand` resources
  in a context where mapping can sleep.
- Preallocate mapped packet/ring resources, return device-visible IOVAs, and
  enforce DMA masks and segment/alignment restrictions.
- Keep mappings alive until hardware has completed or stopped DMA. Quiesce
  interrupt/TX/RX/reset activity before reclaiming resources.
- Implement direction-aware synchronization and preserve streaming copy-back
  semantics, including failure and reset paths.
- Validate with AppleVTD active: firmware load, scan, sustained bidirectional
  traffic, pool exhaustion, power cycling, sleep/wake, and detach/reset recovery.

There is no claim of working AppleVTD support from this change. A follow-up DMA
implementation should be reviewed and tested separately from the Wi-Fi frontend.

## Already-powered-on MAC recovery

A Tahoe hardware boot failed before interface registration at
`probe-chip-info-failed`, returning Linux `-EBUSY` (-16). Persistent diagnostics
identified `MAC-already-powered-on`: register `0x03f0` read `0x02200105`, with
power-state bits `0x0300` equal to `MAC_AX_MAC_ON` (1).

The new driver instance had not set `RTW89_FLAG_POWERON`. The macOS power-off
guard therefore skipped the power-off recovery in `rtw89_mac_pwr_on`, and its
second power-on attempt encountered the same state. When the hardware check
confirms MAC_ON, the macOS path now sets POWERON so that the existing recovery
can execute. The guard remains in place for devices not confirmed powered on.
A subsequent Tahoe boot confirmed HAL attachment and Wi-Fi interface
registration succeed with this recovery change.

Startup/transport/chip checkpoints are stored on the PCI wrapper/device in
IORegistry so controller teardown and kernel log rollover do not erase them.
The C archive build phases always run: previously, empty input lists with a
declared archive output allowed Xcode to reuse stale C objects after edits.

## Native scan event registration

After power recovery, hardware counters showed 151 channel changes, 43 received
beacon/probe frames and five cached networks while the native network list was
empty. The frontend installed `ic_event_handler` before HAL attachment, but
`RTWCore::attachNet80211()` clears `ieee80211com`, erasing that callback.
The native frontend now installs the event handler after successful HAL attach,
before enabling the adapter. This preserves beacon, scan-completion and driver
availability notifications. The resulting native network list still requires
hardware validation.

## RX frame trailer handling

After installing the native event callback, airportd still reported zero scan
results. Hardware counters showed 99 beacon/probe frames and 98 undersized IE
errors. RTW89 advertises `RX_INCLUDES_FCS`, while the native receive bridge
previously forwarded the complete skb to net80211. The four-byte CRC trailer
was included in the IE bytes passed to WCL's strict validator. The bridge now
removes the FCS when the hardware flag requires it and rejects frames too short
to contain a valid minimum control header plus FCS. A subsequent boot confirmed the undersized IE counter remains zero with 274
beacon/probe frames received and six cached networks. airportd still returned
zero results, so native result delivery and data traffic remain unverified.

## Scan result workqueue gate

WCL delivery diagnostics recorded 68 beacon callbacks and 66 valid result posts,
with no invalid IE/channel rejections. Result posts returned `0xe00002e2`
(`kIOReturnNotPermitted`), while the scan-completion post succeeded. RX callbacks
run outside the native workqueue gate. Results are now replayed from the retained
net80211 cache during successful gated scan completion, before posting ScanDone.
The replay honors requested channels and directed SSIDs. RX still updates BSS
snapshots but does not post scan results outside the gate. Acceptance of the
result messages and appearance in the native network list require hardware
validation of this change.

## Validation

`python3 tools/validate_rtw89_backend.py` parses the OpenStep project, verifies
eight OS target configurations and frontend isolation, resolves schemes, checks
Realtek personalities and C archive inputs, and verifies embedded firmware
against the six source binaries. `tools/wire_rtw89_xcode.py` is idempotent and
maintains only Realtek C++ backend source-phase coverage; C driver files remain
in the dedicated C archive.

CI builds Debug/Release for each OS target on an Intel macOS runner. It also
compiles host-side WCL request/layout regression checks for both ABIs. These
checks do not prove that private Apple class layouts match every OS update.

The development host is Windows: Xcode compilation, linking and loading have
not been executed locally. The CI workflow is prepared, not a reported successful
CI run. Initial hardware validation must include cold boot, scans on both bands,
open/WPA2 association, DHCP, traffic, disconnect/reconnect, Wi-Fi power toggling
and sleep/wake. Repeat existing smoke tests on older OS builds to detect shared
net80211 regressions.

## Project header dependencies

The first channel/counter parity boot failed at net80211 attachment. Inspection
found net80211 objects from 20:17 reused alongside a newly built RTWCore after
`ieee80211com` gained traffic counters. Local include directories had been
listed under `SYSTEM_HEADER_SEARCH_PATHS`; dependency files omitted the shared
header, allowing inconsistent layouts in the linked binary. Local include
roots now use `HEADER_SEARCH_PATHS`, and validation checks this setting. Both
native targets must be rebuilt after this setting change before further tests.

## Join notification context

The rebuilt channel/counter bundle successfully scanned on Tahoe. Join tests
then recorded successful over-the-air authentication/association, but native
AssocComplete, LinkStatus and FirstBeacon posts returned `kIOReturnNotPermitted`.
ConnectComplete returned success. Join notifications now use a bounded,
preallocated FIFO drained by a native workqueue timer. Payloads are copied
before returning from RX, and publication never blocks RX while acquiring the
native gate. Timer ownership is retained across producer scheduling and detached
under the FIFO lock on stop. The queue fix requires hardware validation.

The same test counted 2,851 software RX decryption failures. This is a separate
unresolved data-path issue; Wi-Fi TX ACKs for DHCP do not establish that DHCP
responses or a lease were received.

## Receive-only CCMP fallback

The join FIFO hardware test recorded successful native AssocComplete, LinkStatus,
FirstBeacon and ConnectComplete posts (all status zero), but no IPv4 lease and
556 RX decryption failures. Hardware-installed keys previously lacked software
contexts and had SWCRYPTO clear, so net80211 rejected still-encrypted packets
requiring software decryption. Realtek CCMP keys now retain an AES context under
a separate SWDECRYPT flag; hardware TX remains selected by keeping SWCRYPTO
clear. RX fallback is permitted only for CCMP with a valid context and uses the
existing MIC and PN/replay validation. Context allocation failures remove the
hardware key and fail installation. Rekey frees the old context without erasing
the replacement key material. Deletion frees both hardware and software state.
This fallback, DHCP and data traffic still require hardware validation; separate
CCMP integrity/replay counters are exposed for that test.

## Full software CCMP data path

The receive-only fallback test reached an active link but a self-assigned IPv4
address, with nine CCMP integrity failures and no observed DHCP lease. To remove
the unverified security CAM path from the next hardware test, CCMP now uses
net80211 for both TX encryption and RX decryption, like the existing TKIP path.
RTWCore explicitly encrypts SWCRYPTO frames before native transmission; the
bridge skips hardware-key selection and IV reservation for those frames. The
CCMP MIC, packet-number and replay checks remain in net80211. The earlier
receive-only flag and policy change were removed. `RTW89SoftwareCCMP` identifies
this mode in IORegistry. Hardware validation of DHCP/traffic and performance is
pending. DHCP-specific TX counters currently classify plaintext frames at the
Linux bridge and therefore do not count software-encrypted DHCP frames; total
TX/data counters and actual lease/traffic checks must be used for this mode.

## RTW89-only CCMP receive normalization

Comparison with the local Airport_RTW89 data path confirmed that hardware RX
retains the CCMP IV and MIC. net80211's hardware-decrypt path removes the IV and
validates PN, but requires its caller to remove the MIC. The RTW89 Linux bridge
now strips the MIC only for a hardware-decrypted data frame with an installed
CCMP key and intact IV/MIC flags. It retains the IV for net80211 replay checks,
rejects truncated or invalid CCMP layouts, and never strips ciphertext from a
frame not marked decrypted. A portable layout check covers normal, QoS, four-
address/HT-control, multicast key IDs and malformed/truncated frames. CCMP has
returned to hardware CAM, while TKIP retains HAL-selected software crypto.
Native Apple frontend and shared net80211 crypto code are unchanged by this
step. Hardware validation remains pending. New HAL counters distinguish
hardware-decrypted RX, protected RX needing software, and stripped CCMP MICs.

## Connection-specific RX diagnostics

The hardware test confirmed MIC normalization is running (103 stripped MICs),
with zero reported CCMP integrity/replay errors, but DHCP still produced only
a self-assigned IPv4 address. DHCP TX acknowledgements are 802.11 ACKs, not
DHCP leases. The global protected/software counter also includes overheard
traffic, so it cannot identify a key failure on this connection by itself.

The next diagnostic build counts downlink data from the associated AP addressed
to the current vif or a group: protected frames, missing hardware decryption,
invalid CRC/ICV status, readable SNAP payloads, and UDP 67-to-68 replies. These
counters are cumulative over the loaded driver's lifetime, including reconnects.
Additional properties expose TX source/vif address mismatches, net80211 port
validity, unauthorized/protection-off drops, and data passing net80211 decrypt.
No packet contents or key material are logged. This step changes observation
only; it does not claim to fix DHCP. Changes remain in the RTW89 HAL.

## Private MAC synchronization

The connection diagnostic test reported 188 TX source/vif address mismatches,
30 hardware-decrypted frames, 35 data frames passing net80211 decryption, a
valid controlled port, and no observed DHCP replies. Inspection found that
native `setHardwareAddress` called `if_setlladdr`, which updates only
`ic_ac.ac_enaddr`; `ic_myaddr` is a separate array. HAL enable programs the vif
from `ic_myaddr`, while data encapsulation copies the Ethernet source address.
Private address changes therefore left MLME/hardware using the old address.

The native address setter now updates both arrays and restores both on failure.
This is a frontend bookkeeping correction, with no shared net80211 or HAL
architecture change and no hardcoded MAC address. Each adapter/network can use
its own current address. The existing TX mismatch and DHCP RX counters remain
available to validate the fix after reboot. DHCP restoration is not yet verified.

Hardware validation on 2026-10-20 confirmed zero TX address mismatches,
two observed DHCP replies, and an active en2 IPv4 address of 192.168.1.36/24.
The controlled port was valid, 269 frames were hardware-decrypted with MIC
normalization, and CCMP integrity/replay counters were zero. This verifies
association and DHCP after private MAC synchronization; sustained traffic,
throughput, reconnect and sleep/wake remain to be tested.

## HAL throughput negotiation

The throughput test build removes the fixed 20 MHz data-channel setting. Card
HT/VHT capabilities and MCS maps are exported through the bridge into net80211;
channel flags now permit HT40 and VHT80 on the existing primary-channel list.
Authentication remains at 20 MHz. On association, the negotiated primary,
center frequency and contiguous width (20/40/80 MHz) are programmed before
firmware station/rate setup. Invalid primary/center layouts fail association.
Peer HT/VHT and MCS limits replace the previous copy of the card's own station
capabilities; stream counts are bounded by the supported HT MCS mask.

The previously empty station iterator now visits the registered AP station,
with registration/unregistration serialized against in-flight callbacks. This
restores RX PHY/rate status and other station-iteration consumers. Ordinary,
unfragmented unprotected Block Ack actions from the current AP, addressed to
the current station with a valid controlled port, can reach net80211 directly
without being consumed by native raw-management listeners. Frames requiring
management protection retain the standard input path. Firmware aggregation
is still enabled only after the net80211 Block Ack handshake succeeds.

Portable channel-layout and per-stream MCS intersection tests were added.
Backend validation, both native protocol ABI tests and RX layout tests passed.
Xcode's automatic cache-access approval review timed out twice, and sandboxed
xcodebuild failed before compilation when creating its build-session file.
Validation therefore rebuilt the complete C archive with the repository script,
recompiled all six native objects whose dependency files reference the HAL
headers using Xcode's response files and private prefix header, and replayed
the recorded linker commands into separate Tahoe/Sequoia test bundles under
`build/releases-throughput`. Both compiled/linked and passed plist validation.
The ordinary release bundles were retained. Hardware validation of negotiated
width, aggregation, DHCP stability and speed is pending. This step does not
implement HE/6 GHz, 160 MHz, or dynamic channel-width changes after association.

## Periodic reconnect: native beacon-health delivery

The throughput build established a 40 MHz link and successful RX/TX Block Ack
agreements. The reported periodic reconnect also appeared in logs before that
build's reboot. Kernel WCL logs explicitly report `missed beacons timeout`
approximately 60 seconds after link-up (for example 06:40:28 to 06:41:28 on
2026-10-20), despite ongoing driver beacon/data reception and valid crypto.

Periodic LQM/beacon-health updates were still posted directly from the RX
callback, outside the required native workqueue gate. They now use the existing
copied FIFO and gated timer delivery, like the corrected join events. Queue
payloads accommodate both native LQM layouts as well as connection events,
with static size checks. A failed enqueue retains the outstanding beacon delta
for a subsequent update. `RTWWCLLqmPostStatus` and `RTWWCLLqmPostCount` expose
actual native delivery results. No synthetic beacons are reported and the
native missed-beacon timeout remains enabled. Both ABI tests cover zero/nonzero
beacon-health snapshots; sustained connection validation remains pending.

The HAL's user-visible firmware version is now `AirportRTW 2.1.0`. This labels
the AirportRTW build; it does not change the bundled Realtek firmware blobs.
