# Native Tahoe AWDL control payload audit

AirportRTW previously retained older AWDL control payload layouts in the
shared ioctl header. Those layouts are unsuitable for the native Tahoe
control provider, even though its method slots were already correct.

## Corrected native-only layouts

| Payload | Older layout | Tahoe layout |
| --- | --- | --- |
| Synchronization parameters | 20 bytes | 24 bytes, non-election-master field at +20 |
| Synchronization state | 8 bytes | 24 bytes, parent MAC +8, flags +16, mode flags +20 |
| Election RSSI thresholds | 16 bytes | 20 bytes, signed peer threshold +16 |
| Action transmit mode | 12 bytes | 8 bytes, 32-bit mode |
| Channel sequence | descriptors +16, 3-byte stride | descriptors +12, 12-byte channel stride, total 400 bytes |
| OOB request | inline data +48 | borrowed pointer +48, total 56 bytes |

Definitions are selected only for `__IO80211_TARGET == __MAC_26_0`.
No older target payload definition was replaced.

## Evidence

Local file-only LLDB inspection of
`/System/Library/Extensions/IO80211Family.kext/Contents/MacOS/IO80211Family`,
version 1200.13.1 (SHA-256
`c24e8f9d95ca2f5c59b61334d3ff75cf83727a4ef9723cbdbb386dd62c957d35`),
confirmed exact request-size checks:

- `getAWDL_SYNC_STATE`: 0xf8bae compares request length with 0x18.
- `getAWDL_SYNC_PARAMS`: 0xf8608 compares request length with 0x18.
- `getAWDL_AF_TX_MODE`: 0xf97e5 compares request length with 8.
- `getAWDL_ELECTION_RSSI_THRESHOLDS`: 0xf8c10 compares with 0x14.
- `setChannelSequenceUnconditional(bool)`: allocates/copies 0x190 bytes,
  writes channel descriptors at +0xc and flags at +0x14 with 12-byte stride.

Parent/flags fields, borrowed OOB pointer and descriptor layout were also
cross-checked with local MtkWireless revision `98d9442`, its native interface
implementation and its Tahoe ioctl declarations. Size checks alone do not
establish the semantics of every unknown field. Unknown fields remain opaque;
this audit does not authorize returning success for unsupported controls.

## Validation and remaining work

The native ABI regression compiles the real header, checks all listed native
sizes/offsets and then compiles the older target layouts separately. Native
virtual-slot checks and interface/datapath/action-input tests pass. Combined
RTW88/RTW89 Tahoe Debug and Release builds pass. Cross-HAL helper
isolation tests also pass.

These changes do not implement the missing control provider, radio scheduler,
peer admission or hardware synchronization. Native capability advertising stays
disabled. They must not be described as completed or working AirDrop support.

## Peer-traffic record and backend transactions

The same IO80211Family binary exposes a concrete difference from the older
header and the local MtkWireless declaration. Native Tahoe's user request
wrapper at 0x105e89 requires 0xb8 (184) bytes. In
`IO80211AWDLPeerManager::setAwdlPeerTrafficRegistration`, 0x861dc addresses the
inline MAC at +4; 0x85f2b reads name length at +12; 0x86039 addresses the name at
+16; 0x85f38 limits it to 128 bytes; 0x862e1 reads activity at +0xa8. The path at
0x88d26 copies the full 0xb8 bytes. `populateTrafficRegV2` separately accesses
parameters at +0x90..+0xb2; their semantics remain opaque here.

The Tahoe-only declaration now preserves the full record, uses a six-byte inline
MAC and a 128-byte name, and retains opaque parameter/tail bytes. The older
172-byte pointer-based declaration is unchanged for older targets. This avoids
casting a remote address into a kernel pointer or truncating the native record.
It does not establish support for every native traffic parameter.

The native runtime now validates and dispatches peer cache operations 0/2/6
and bounded traffic records to backend transactions, propagating errors. It
rejects local/group/zero active-peer addresses, invalid activity/name lengths
and peer writes while disabled. Cache operations copy only the verified
version/op/MAC prefix, not key material in the opaque request tail. Capacity is
reported only when the backend supplies it. The default backend implementations
return Unsupported; no hardware peer, cache completion or capability is faked.
The concrete production hardware/data backend remains unfinished.

Regression tests compile the real native/legacy declarations, verify the native
size and offsets, and execute runtime requests under ASan/UBSan. They cover
inline address bytes, caller-storage mutation, preserved opaque traffic bytes,
backend failures, unsupported operations, capacity and disabled-state behavior.
