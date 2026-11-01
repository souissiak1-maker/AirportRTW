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
freeing. Retained recovery is not successful peer admission. The production
allocator and device-reset recovery path still need integration.

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
