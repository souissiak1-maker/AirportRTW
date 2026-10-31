# RTL88WiFi reference audit

Reference: X1REN41L/RTL88WiFi, local checkout revision
`8cebe79209d05e8760e17603af6a344941920381`.

- Source: `driver/RTL88WiFi/src/kext/RTW88AWDLProtocol.hpp`
- Source SHA-256: `451ee4c26ca67b7cc7a297350aac6ebdeaa1bc1a5fccf2ae29f3fb06f5d7a4bb`
- Original source SPDX: GPL-2.0 OR BSD-3-Clause. The repository's combined
  distribution is GPLv2; see its [NOTICE](https://github.com/X1REN41L/RTL88WiFi/blob/8cebe79209d05e8760e17603af6a344941920381/NOTICE.md).
- AirportRTW adaptations in `include/AWDL/RTWAwdlSync.hpp` use GPL-2.0-only,
  retaining the original source/license/revision attribution in the header.

This checkout explicitly documents no working AirDrop/Continuity and no observed
AWDL peer, despite a Supported label. It is a development reference, not evidence
of a working implementation. The README lists Sonoma 14.8.9 as its tested OS;
its legacy-family interface/control handlers are not a native Tahoe ABI contract.

## Adapted now

The wire synchronization/channel decoder is shared by both HALs. It understands
the reference's full 16-entry channel lists in simple, legacy and operating-class
representations, synchronization parameters, election-v2 and version records.
Wire field layouts were cross-checked against the public
[OWL frame definitions](https://github.com/seemoo-lab/owl/blob/master/src/frame.h)
and [channel encoding definitions](https://github.com/seemoo-lab/owl/blob/master/src/channel.c).
No GPLv3 OWL implementation code was imported.

Changes from the reference include explicit malformed/unsupported outcomes,
owned output records committed only after validation, retained operating classes
and both self/master counters/metrics, and rejection of conflicting embedded and
standalone channel lists. The AP-alignment field remains distinct from the AW
counter; wire TX timestamps remain in the sender's clock domain. Full lists with
no duplication/fill expansion are the supported subset. An unavailable slot stays
zero, and channel 255 is never accepted as a concrete channel. Decoder success
is not regulatory authorization, peer admission, clock acceptance or RF success.

The Debug passive observer records numeric decode success/failure counters only.
Unsupported or malformed semantic data does not change normal RX routing or
cause a radio retune. The sanitized collector permits only these numeric counters.
Tests cover all supported encodings, truncated/duplicate/contradictory TLVs,
presence validation, owning fields, unknown versions and malformed-frame fuzzing.
A separate local compilation compares valid decoded fixtures with the pinned
reference header. It does not validate live Apple packets or RF synchronization.

## Useful next references

- `RTW88AWDLManager.cpp`: bounded queues, stale-packet handling, separate PSF/MIF
  scheduling, peer expiry and separating Apple-supplied control from fallback.
- `RTW88IEEE80211.cpp`: AP power-save notification, exclusive radio ownership,
  restoration of the complete home channel configuration after off-channel use.
- `RTW88AWDLProtocol.hpp`: two-pass A-MSDU validation before delivering any
  subframe; synchronization and peer-window concepts.
- `RTL88WiFiAWDL.cpp`: control-request inventory and explicit unsupported cases.
  Every native Tahoe layout and callback contract still requires independent
  validation before reuse.

## Kept out of production policy

- Capability flags that produce a Supported label without working discovery.
- Assuming a fixed 6 ms sleep proves AP buffering or RF switch completion.
- Assigning host receive time directly to the radio/native timing domain.
- Copying hardcoded fallback device capabilities/version/service identity.
- Treating an opaque private channel-sequence blob as a decoded RF schedule.

The native provider, calibrated timing, peer admission, native RX event adapter
and synchronized HAL channel scheduler remain unfinished. The AWDL feature stays
unadvertised. This audit does not claim working discovery or AirDrop.
