# RTL8822CE Monterey authentication diagnostics

The MSI selection test (commit 2e4e5ce) was tested on HP RTL8822CE
10ec:c822, subsystem 103c:85f7, macOS 12.7.6. It selected interrupt index 1,
registered it successfully, completed HAL attachment and created en1.
This confirms the startup fix on that machine; connection still fails.

The follow-up failed-join capture used UUID
4961ED1E-9F91-387B-99D0-486F503C7ED2 and recorded one authentication TX,
one reported authentication TX acknowledgment, zero authentication RX and
zero association TX, with 111 raw receives and 145 interrupts.
These observations do not establish whether an authentication response was
absent on air, filtered below the bridge, or lost during host processing.

The next Debug build adds the following metadata, without changing MLME:

- RTW88AuthBridgeCount: authentication frames entering the Linux-to-HAL bridge,
  after FCS-length handling, before CRC rejection.
- RTW88AuthBridgeBadCRCCount: those frames flagged with failed CRC/PLCP.
- RTW88AuthHALSeen and InputStage: arrival at the HAL and processing boundary.
- AuthFrameLength, Frequency, StateAtReceive, Algorithm, Sequence, Status:
  bounded header/body metadata; the six-byte authentication body is read only
  when present. No password, key, or raw payload is recorded.
- AuthDestinationMatches, SourceMatches, BSSIDMatches: comparisons with the
  current station/target addresses; addresses themselves are not exported by
  these properties.
- AuthStateBeforeInput/AfterInput: whether net80211 advances during input.

Counters are cumulative; last-frame metadata is overwritten by later auth
frames and is not an ordered packet trace. Zero bridge auth frames cannot
prove that the AP did not transmit; hardware filtering remains possible.

Test: install the new Monterey Debug kext, reboot, make one manual join,
wait for failure, run the supplied collector immediately, and return the ZIP
with security type, band/channel if known, and approximate attempt time.
No boot-arg changes are required. Restore the saved Release kext afterward.

## Hardware snapshot at authentication transmit

The follow-up build reads the selected VIF port MAC/BSSID registers and RCR
under the device mutex immediately before submitting each authentication TX.
It does not write registers or change receive filters.

RTW88AuthSnapshotValid must be 1 before interpreting the other fields.
RTW88AuthHardwareChannel is the driver's active channel cache, not an RF
measurement; RequestedChannel is the configured channel. RCR is the hardware
receive-configuration register. Port identifies the selected VIF port.
AddressMatchMask bits compare the transmitted source with VIF address (1),
driver port MAC (2), and read-back hardware MAC (4), then the transmitted
BSSID with driver port BSSID (8) and read-back hardware BSSID (16).
All matches produce 31. No raw addresses are added to these properties.
The snapshot is retained across later scans; unlike LastReceiveFrequency,
these fields describe authentication TX time.
