# Native Tahoe availability-window events and clock fields

This audit uses the local x86_64 IO80211Family 1200.13.1 binary, SHA-256
`c24e8f9d95ca2f5c59b61334d3ff75cf83727a4ef9723cbdbb386dd62c957d35`.
It is file-only inspection, not a live kernel debugger session.

## Confirmed native fields

`IO80211AWDLPeerManager::reportDataPathEvents` subtracts 41 before indexing its
jump table at 0x5d5b0. Entries for events 41/42/43 target 0x5ae0d, 0x5ac83 and
0x5ae81 respectively. The event-41 path reaches `monitorTimeline` at 0x5c585
and `logAWStart` at 0x5c689. Event 42 is a different window-extension path.
The common header previously labeled start as 42; the corrected value is
selected only for Tahoe, preserving older targets' existing value.

`monitorTimeline` consumes a 36-byte start record, including counter at +0,
parent/root addresses at +8/+14 and a big-endian clock at +20 (load/bswap at
0x5dc75/0x5dc78). Its channel descriptor occupies +24..+35. Native end uses a
40-byte record, with its big-endian end clock at +4. Undetermined end flags,
counts and statistics are zero; no synthetic beacon counts are supplied.
The layouts were also cross-checked against MtkWireless's native implementation.

`IO80211AWDLPeer::actionFrameReport` reads the 72-byte metadata's channel at
+16 and loads/byte-swaps +48 at 0x2c8ed/0x2c8f2. This is separate from signed
RSSI at +44. The RX packer now accepts an explicitly valid event-domain RX
clock for +48. It does not implicitly cast the HAL's raw TSF/free-running
counter into this domain. Without an explicit valid clock, the field remains
zero, preserving the earlier diagnostic-only packing behavior.

The software/hardware clock source and its stability remain a backend contract.
A backend must consistently timestamp RX, wire synchronization and window
events, and invalidate the mapping on reset/discontinuity. These offsets alone
do not establish that mapping or provide RF synchronization.

## Event and timer transport

AirportRTWAwdlInterface now offers native-workloop start/end handoff and an
owned IOTimerEventSource. It validates records, suppresses duplicate starts and
ends, and changes its open-window flag before calling native postMessage to
handle reentrancy. Disable can still balance an existing start; stopped bases
cannot receive new events. Timer allocation/add/arming failures propagate.
Stop cancels and removes the timer before stopping the native base, and timer
callbacks retain their owner/source through reentrant teardown.

The inspected `IO80211Glue::addEventToPendingQueue` allocates payload length
plus 32 bytes and copies caller bytes into the entry at +32 before enqueue.
This supports stack-owned event records across the WCL queued path. The void
postMessage API provides no peer-manager semantic acknowledgment; transport
methods report handoff only.

## Shared scheduler

RTWAwdlWindowScheduler couples the election engine to a serialized WindowDriver:
checked reservation results, verified current channel, effective channel policy,
explicit clock conversion, timer ownership and native event transport.

It arms expiry before entering a potentially slow synchronous radio operation.
Rejected visits produce no start. Early grants wait for the scheduled edge;
late/short/wrong-channel grants are restored without claiming availability.
Controls/clock are held through an open window and released after the matching
end handoff. TX eligibility includes edge guards and multicast rendezvous slots
0/10; it does not replace peer authorization or a final lease/deadline check under
the HAL submission lock. Radio restoration failure keeps
recovery ownership and prevents new visits. Lost event clocks or failed end
handoff require native reset rather than a fabricated closing timestamp.

The current radio profile caps preparation plus visit at 100 ms. Presence modes
that cannot fit are rejected; this is not support for every native presence mode.
A bounded eight-sample history adjusts preparation lead within this profile.
There is no RTW88 radio reservation implementation yet.

The host integration test runs the actual scheduler through the actual native
interface timer and event methods with a fault-injected radio adapter. Separate
radio tests exercise the production RTW89 primitive/bridge code. Native ABI
compilation verifies event IDs and existing virtual slots. This does not install
a production RuntimeBackend, complete peer/data binding or establish on-air
AirDrop. Factory/support gates remain disabled until those pieces are supplied.

The combined-HAL Tahoe Debug and final Release builds pass with no compiler
errors. Native ABI/family checks, byte-layout tests, scheduler/lifecycle
integration tests, datapath/action tests and backend validators pass. No EFI
was modified and no release was published.

## Production radio transport adapter

`RTWAwdl::Radio` now defines the shared MHz-based reservation/query contract.
RTWCore89 implements it using the RTW89 bridge. Queries hold the hardware lock
and report the confirmed ROC channel; the cached home chandef is not substituted
when restoration is uncertain. A failed reservation with a retained primary TX
gate returns RecoveryRequired. RTW88 inherits explicit unsupported defaults;
its action receive path is not evidence of bounded channel-visit support.

`AirportRTWAwdl::WindowDriver` connects this contract to the native interface's
window events and timer. Its clock is boot-monotonic microseconds, with explicit
32-bit wrapping for native wire fields. Its action-staging helper uses that same
software clock and never queries the HAL from inside the RX registration lock.
Device TSF/free-run values are not used as software clock values. RX accepts
passive-channel observations; only TX/window descriptions require effective HAL
policy and carry the active-channel flag. Channel conversion itself does not
authorize transmitting on any channel.

The production adapter compiles with the actual Tahoe SDK. Host tests execute
its methods with deterministic time, radio faults and the real shared scheduler;
separate bridge tests execute the actual RTW89 implementations. This remains an
adapter, not a controller-owned RuntimeBackend. No controller factory invokes
it yet. Peer admission, data/replay flow, scan arbitration and reset-safe teardown
must be integrated before activating native AWDL. No working-AirDrop claim is
made by these tests or builds.
