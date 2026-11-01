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

## Publication remains disabled

The RTW89 HAL currently declares frame transport, manual radio visits and peer
stations, **not** quiescent removal. RTW88 declares none of these AWDL hardware
capabilities. The native factory requires all capabilities, including a genuine
producer/lifetime barrier; it cannot publish this backend yet. There is no new
controller factory call and no AirDrop-supported flag enabled by this work.

In particular, the compatibility layer's delay-based replacement for
`thread_call_cancel_wait` is not a synchronous lifetime barrier. Wiphy workers
also do not yet implement upstream's mutex/cancellation ordering. Adding a
mutex around their callbacks alone would deadlock cancellation under that mutex.
These require a coordinated work/timer lifetime implementation before enabling
native publication. BSD attachment is deferred until queue registration and
controller publication; checksum/segmentation assists are disabled and the BSD
offload/capability masks are checked after preparation. Actual discovery and
bidirectional transfer testing remain outstanding. Build or host-test
success does not establish functioning AirDrop.

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
