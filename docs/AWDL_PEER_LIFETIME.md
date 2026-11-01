# RTW89 native AWDL peer lifetime

The native peer/data backend is not complete or activated. These changes prepare
its error paths; they do not advertise AirDrop support or allocate a peer on the
running system.

## Firmware role creation and failed-add ownership

Quiet ADHOC (`no_beacon`, non-TDLS) peers use a firmware role separate from the
infrastructure station. Source inspection found that failed default CMAC/DMAC
setup after ROLE_CREATE reached station-add cleanup, unlinking the peer and
recycling its MAC ID without sending ROLE_REMOVE.

`rtw89_core_sta_link_add` now marks the role as potentially owned before sending
CREATE. CREATE/default-CMAC/default-DMAC failure attempts REMOVE and preserves
the original error. Successful cleanup clears ownership; failed cleanup retains
it. `__rtw89_ops_sta_add` retains the link/MAC-ID in that case rather than
unsetting/recycling them. Duplicate quiet-ADHOC adds reject with EBUSY before
reinitializing the station or acquiring another MAC ID. Ordinary station/AP/TDLS
creation follows its existing error paths.

A native allocator must call `rtw89_macos_awdl_peer_retained(vif, sta)` under
WiphyGuard after failed add. A retained station and VIF must remain allocated.
Retry the NONE -> NOTEXIST remove transition; if cleanup continues to fail,
explicit device fencing/reset and driver callback quiescence are required before
freeing. Retained recovery is not successful peer admission. The bridge allocator and device shutdown integration are described below.
Native controller/data binding and on-device recovery testing remain pending.

The role flag reflects firmware command submission ownership. A successful H2C
submission is not an RF or firmware semantic acknowledgment. Hardware tests must
validate actual discovery/data behavior and failure recovery.

## CAM cleanup during partial/retried association

Address/BSSID CAM deinitializers now check whether the record owns an allocated
entry before clearing its bitmap bit. A zeroed failed peer's default index zero
must not clear the infrastructure entry. Likewise, retried cleanup must not clear
an entry that another owner reused after the first cleanup.

## Validation

Host ASan/UBSan tests execute the production role add/remove functions with each
command failing, failed rollback and successful retry. Separate tests execute the
actual station-add function and retained-state query, checking link/MAC-ID
ownership, duplicate add, MAC-ID exhaustion and link allocation failure. CAM
tests execute the production deinitializers for every index, zeroed records and
reuse between cleanup retries. These are driver contract tests, not on-device
AirDrop validation.

## Concrete RTW89 bridge allocator

RTWCore now exposes a hardware-independent peer result, capacity, add/remove and
checked interface-quiesce contract. RTWCore89 delegates to a bounded 16-entry
bridge pool. Capacity is capped by the chip MAC-ID namespace after its MLO
partition, reserving both VIF IDs (for example, 14 for RTL8922A with 32 IDs and
a two-link MLO partition). Runtime allocation failures still propagate when
other users consume IDs. RTW88 returns Unsupported/zero until its implementation is supplied;
it does not inherit RTW89 chip state or claim those capabilities.

The bridge allocates mac80211 station private storage with overflow checks,
initializes the default link and a conservative one-stream/20-MHz/OFDM peer,
registers it after NONE and before AUTH/ASSOC, and returns success only after
AUTHORIZED. No HT/HE capabilities, aggregation agreement or RF ACK is fabricated.
Duplicate live adds are idempotent. Registry/capacity/allocation/driver errors are
propagated, and upward failures unwind the completed states. A failed initial
add uses the driver's retained-state query before deciding it is safe to free.

Removal withdraws the peer registry entry, flushes receive BA ownership, then
walks completed states downward. Failure retains the exact station/state for
retry. Recovery blocks new peers, AWDL radio readiness and action submission.
The native caller must stop peer TX producers before removal; this API does not
replace the native queue/submission drain or solve all scan/join arbitration.

Checked quiesce closes the HAL receive registration, restores an outstanding
manual radio visit, removes every peer, then removes the secondary VIF. Failure
keeps that VIF allocated. A failed power-down stops the device and blocks enable
until full detach, retaining infrastructure allocations too. Detach removes the
PCI core before releasing VIF storage. A preallocated intrusive record transfers
the remaining pool/VIF/station allocations to transport teardown, which releases
them after its compatibility-worker shutdown, without allocating on the error
path or issuing hardware operations after PCI removal.

This establishes explicit ownership/order relative to the existing driver and
transport shutdown APIs. It does not certify every compatibility cancellation
primitive as a full barrier. Broader worker quiescence, native peer completion,
data TX/RX binding and hardware recovery tests remain required before activating
the native AWDL factory. No complete RuntimeBackend/capability advertisement is
installed by this change.

Allocator tests execute the production bridge with every upward/downward
transition failing, initial retained role, registry failure, allocation overflow,
16-peer exhaustion, duplicate/local/group addresses and ROC restoration failure.
Shutdown tests execute actual power-down/detach and the transport's deferred
release section, injecting firmware-delete/restore failures and checking that
retained memory outlives both PCI removal and modeled worker shutdown. The
existing compatibility implementation itself is not modeled as proven by that
ordering test. ASan/UBSan catch leaked/double-freed fixture allocations.
