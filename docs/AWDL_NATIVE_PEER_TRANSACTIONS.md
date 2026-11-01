# Native Tahoe AWDL peer transactions

`NativePeers` is the concrete cache/traffic owner for a RuntimeBackend. The
controller/backend supplies this object to `RuntimeBackend(&peers)` and keeps it
alive through every in-flight request. Runtime binds it after opening the HAL
VIF, enables it after backend activation, revokes it before disable, and transfers physical peer ownership
to backend close on shutdown. The peer hardware contract is shared through RTWCore;
RTWCore89 uses its real allocator and RTW88 continues returning Unsupported.

Cache add/update invokes the HAL before committing admission and posting native
completion. Cache deletion revokes its reference, retaining hardware while an
active traffic reference still owns it. Ending traffic retains a cached peer.
A failed installation emits no completion. Failed removal revokes admission,
keeps recovery owned by the HAL, and makes the session unready. Traffic switches
install the new destination before releasing the old one; a clean failed install
preserves the old owner, while failed old-owner cleanup blocks data admission.

Disable/shutdown revoke authorization immediately. Reentrant peer mutation during
completion returns Busy. Runtime defers backend close until the outer request
returns; a completion callback cannot close the VIF while the peer transaction
still uses it. Controller ownership must still keep Runtime/NativePeers alive
until callbacks return; deleting these C++ objects inside callbacks is invalid.
The interface is pinned through in-flight calls and backend closure. On shutdown,
the session forgets native references without first deleting hardware peers:
backend close must stop producers and quiesce its entire HAL VIF/peer pool. This
avoids removing a peer before that producer drain. Ordinary disable first stops
backend activation, then releases the session's peer references.
Control requests, MAC changes and enable/disable enter the interface workloop
gate, sharing serialization with native timers and deferred radio input. A
lifecycle lock pins the loop before stop can release it; the lock is dropped
before waiting on the loop gate to avoid lock inversion. The
current interface MAC is read for local-peer rejection, including randomized
address changes made while disabled.

## Native completion evidence

The local IO80211Family 1200.13.1 binary SHA-256 is
`c24e8f9d95ca2f5c59b61334d3ff75cf83727a4ef9723cbdbb386dd62c957d35`.
File-only x86_64 inspection maps AWDL reportDataPathEvents event 51 to 0x5ab16.
It reads operation +4 and MAC +8..+13, and delegates to the base peer manager
when its normal cache-control routing is enabled. This implementation does not
patch that private routing flag.

The base path reaches `handleCacheControlMessages` (0x11983c), which reads
operation +4 at 0x11984b, recognizes delete indication 3 at 0x11984e and add
indication 1 at 0x119857. Add indication looks up the peer from MAC +8 at
0x11998d. MtkWireless's local native implementation uses the same 0x1d0-byte
zeroed record, version 1 and operation 1/3. Its code is a reference for this flow,
not proof of Realtek interoperability. Unknown key/cipher fields remain zero for
the unencrypted AWDL peer path; no key material is echoed from opaque requests.

The native interface posts only while enabled/registered and retains itself
through reentrant delivery. Queued native event copying follows the previously
audited postMessage path. A handoff is not a semantic native-manager, firmware or
RF acknowledgment. Native manager configuration/capability routing still needs
integration; the transport does not establish it by emitting an event.

## Integration tests and remaining work

The composition test executes the actual native interface, Runtime, NativePeers
and completion packer together, using the existing family lifecycle adapters and
a fault-injected PeerHardware. It checks hardware-before-event ordering, cache /
traffic reference ownership, capacity, clean and retained errors, traffic switches,
recursive mutation, concurrent requests racing stop, lock allocation failure,
disable during installation, shutdown from completion and
randomized MAC updates. Separate RTW89 pool tests exercise the real bridge and
driver ownership paths; this composition test does not emulate radio hardware.
The optional native ABI audit also verifies completion operation offset/values in
the installed family binary.

No production controller constructs the full runtime backend yet. Discovery-only
membership, duplicate windows, AWDL data TX/RX and the remaining native scheduler /
control bindings are still incomplete. Native factory/support flags remain off;
this is not a working AirDrop kext or an on-device test result.
