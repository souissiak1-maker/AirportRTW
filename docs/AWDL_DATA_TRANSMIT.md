# AWDL data submission and station ownership

RTWCore exposes a default-unsupported raw data submission contract. RTWCore89
implements it through the RTW89 bridge. RTWCore88 continues to reject it.
No AWDL data capability or native interface is published by this transport.

The caller supplies one encoded IPv6 AWDL QoS MPDU, an expected frequency, and a
software monotonic submission deadline. Production calls must run on the same
native workloop as radio reservation/restore and peer control.

The RTW89 bridge holds WiphyGuard and requires a live registered quiet secondary
VIF, an active manual visit, a paused and drained primary software producer gate,
a driver-confirmed current channel, and current transmit policy. Unicast also
requires the destination's registered, authorized, non-retiring hardware peer.
Multicast is limited to valid IPv6 33:33 address mapping. The codec rejects
protected, fragmented, non-IPv6 and malformed payloads. Infrastructure RSN port
revocation blocks the RTWCore89 entry point even before the next reservation.

The submission helper copies into a driver-owned skb and sets TX_OFFCHAN. Without
that flag RTW89 queues unicast in the station's roc_queue and transmits it after
returning home, outside the intended visit. The TX control carries the verified
station and secondary VIF. No primary hardware key or AMPDU is attached.

This initial transport uses injected legacy OFDM 6 Mbps / 20 MHz with one attempt
in the requested rate table, and leaves guard/airtime headroom at admission.
It does not establish negotiated AWDL HT/VHT rates, high throughput, or a hard
RF transmit deadline. The deadline is checked before allocation and immediately
before driver ownership transfer. Success means ownership transfer, not RF ACK
or successful peer delivery; the underlying void tx operation can still drop.

Before channel restore, the checked PCI/MAC drain waits for queued frames. Before
peer removal during a visit, the same drain must succeed before registry removal,
firmware-role deletion, or station memory release. On failure the retiring peer
and its registration remain allocated, recovery is required, and new data is
rejected. After successful restore the data has already drained. This ordering
must remain intact when a concrete native data backend is attached.

Tests execute the real submission helper, the real RTW89 bridge, the real
primary-authorization wrapper, and real peer pool teardown with deterministic
adapters under ASan/UBSan. They cover policy/lease/peer failures, deadlines that
expire during allocation, packet-copy ownership, port revocation, multicast
mapping, and retention after failed transmit drain. Hardware AWDL data exchange
is not yet validated. The completed v4 hardware probe exercised secondary VIF
startup, ten listening intervals on channel 36, and successful cleanup; it did
not send data or publish the native AWDL interface.
