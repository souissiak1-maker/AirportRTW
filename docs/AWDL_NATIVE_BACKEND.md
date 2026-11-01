# Native backend integration status

`AirportRTWAwdlBackend.hpp` connects the shared native runtime, peer manager,
window scheduler, action templates and bounded Ethernet queue to `RTWCore`.
The protocol implementation stays independent of the RTW88/RTW89 HALs.

Implemented native controls include election limits/state, regulatory-checked
master channels, the actual 6 Mbps action/data transport rate, canonical BSSID,
configuration commit, broadcast MI templates, bounded unicast MI requests and
native advertiser selection. Request payload pointers are borrowed only during
the synchronous call. Supplemental templates are copied into owned storage;
synchronization/election TLVs are generated from current scheduler state.
Advertiser selection requires an exact, recent RX observation (peer, root,
counter, countdown, presence and software RX timestamp). Cached selections do
not make an older clock sample appear newly received. Unknown MI option modes
and partial slot bitmaps return Unsupported.

Native preparation now happens before `IO80211VirtualInterface::init`, because
that initializer can invoke configuration getters. Preparation cannot access
the native workqueue or start asynchronous producers. Partial initialization
still calls shutdown exactly once before releasing the interface.

## Experimental native publication

The native Tahoe controller now implements role-6 creation, duplicate-request
recovery, native enable/disable and teardown before primary Wi-Fi shutdown.
Publication is opt-in through the controller personality's `RTWAwdlEnabled`
boolean. It requires the complete hardware capability mask; RTW89 now provides
serialized work dispatch, tracked callback cancellation and reader grace periods
(see `AWDL_CALLBACK_LIFETIME.md`). RTW88 still provides no AWDL hardware capability
mask and cannot enter this path.

The AWDL request capability is advertised only with opt-in and the full HAL mask.
The factory registers genuine native queues and the native MAC agent. BSD
attachment is deferred until registration succeeds. Raw transport checksum and
segmentation assists remain disabled. Heap providers follow interface lifetime,
including an in-flight dispatch that re-enters teardown.

The experimental package is intended for the first native registration/discovery
test. A successful build and the supported indication do not establish an AirDrop
file transfer. Actual native peer-manager configuration, off-channel operation,
discovery and bidirectional transfer remain hardware validation requirements.
No new RTW88 AWDL or legacy-macOS AirDrop support is claimed.

## Evidence

- `tests/rtw_awdl_backend_test.py`: production backend/runtime/interface controls
  with a hardware adapter; verifies capability rejection, real transaction
  ownership, getters/setters, channel policy and MI rejection/disable behavior.
  The adapter supplies quiescence only for these host lifecycle tests.
- `tests/rtw_awdl_native_action_test.cpp`: owned template lifetime, fresh election,
  preserved identity TLVs, stale tree removal and atomic capacity rejection.
- `tests/rtw_awdl_interface_test.py`: includes a getter invoked reentrantly during
  native base initialization and rollback after every initialization stage.
- Native ABI compilation checks the backend against the real Tahoe headers,
  retains all 63 AWDL slots and verifies older target layouts remain unchanged.

The native control layouts/flow and supplemental-TLV adaptation use the GPL-2
Wi-Fi implementation in local MtkWireless revision
`98d9442076939dd3a0360eed27bdcfb5681c3078` as a reference. No Bluetooth code is
imported. The 56-byte election payload offsets were additionally checked against
Darwin 25.5's IO80211Family image in the boot kernel collection.


BSD preparation tests inject base-preparation errors, offload setter errors,
a setter that silently retains enabled bits, and supported-mask setter errors.
They verify failed preparation is reported and unrelated capabilities survive.
Native base start is tested with BSD deferral already active; successful
publication releases that deferral only after controller and queues are ready.


Native MAC getter audit: the Darwin 25.5 boot-family implementation of
`IO80211SkywalkInterface::getSelfMacAddr` loads MAC bytes into RAX and returns
that value; it does not return an address pointer. The Tahoe header is corrected
to return `ether_addr`, with a compile-time type assertion. Registration writes
the native MAC agent and checks the returned value before exposing queues/BSD.
Failure of either setter or readback unwinds the interface.
