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
