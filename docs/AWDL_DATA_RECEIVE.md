# Native AWDL data receive chain

The real native interface now supplies a HAL receive callback. With the interface
as the HAL's retained registration owner, it only converts the receive frequency,
samples the software monotonic clock, and copies into bounded queues. It never
calls the family, MLME, or HAL control functions on NAPI. Raw device TSF is not
substituted for the native receive clock.

Actions and raw data have separate rings. Actions drain first on the native
workloop. The raw data ring has 16 heap-owned slots plus heap scratch, each able
to hold an 11,454-byte MPDU. Complete aggregate validation is limited to 32 MSDUs.
Malformed tails never deliver a valid prefix. Disable/stop discards staged frames;
partial allocation and callback-triggered teardown unwind the queues and pools.

On native delivery Runtime pins the interface through the backend callback.
Receive metadata must have the verified source and 72-byte layout. The 32-bit
software receive timestamp is expanded against the current monotonic clock;
frames older than three seconds are dropped. The data engine validates outer
addressing, the whole frame/aggregate and each destination before changing
history or sending Ethernet packets. Native cache/traffic membership authorizes
the sender; observation alone does not authorize data in this implementation.

NativePeers owns 17 duplicate windows per physical peer (TID 0..15 and non-QoS).
The window implementation is adapted from the GPL-2.0-only MtkWireless Wi-Fi
Rust source at 98d9442076939dd3a0360eed27bdcfb5681c3078. It keeps 64 recent MSDUs,
learns the observed 4095 -> 0 rollover, retains full 16-bit streams when upper
bits occur, and restarts after idle. This is duplicate suppression, not
cryptographic replay protection. Peer removal/re-addition resets the windows;
independent cache and traffic references preserve a still-admitted peer's history.

Accepted packets are copied into the actual native Ethernet receive queue through
a checked local adapter. No native class/vtable is forged. Reentrant revocation
is checked per subframe; engine reset is deferred through an active delivery so
it cannot clear borrowed views mid-callback. Borrowed views and Ethernet scratch
are cleared when delivery returns. Address changes update receive addressing.

Production-source host compositions cover the interface callback -> staging ->
Runtime -> NativePeers -> decoder -> Ethernet adapter chain, metadata mismatch,
per-TID duplicate rejection, cache re-add, stale frames and 32-bit clock wrap.
Codec tests cover aggregate atomicity, stream rollover and reentrant reset.
Datapath tests cover bounded rings, allocation failures and teardown in callbacks.

The owning concrete native radio backend still must bind/unbind this callback,
feed election observations, schedule TX, and implement the native discovery
controls before capability publication and hardware AirDrop testing. These
receive changes alone do not enable or establish working AirDrop.
