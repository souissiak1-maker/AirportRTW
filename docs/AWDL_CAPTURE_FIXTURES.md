# Sanitized AWDL synchronization captures

Derived from the local MtkWireless reference at revision `98d9442`:
`kext/Wifi/vendor/tests/awdl/fixtures/iphone-election-transition.bin` and
`iphone-v9-psf.bin`. Both original observations were rejected by AirportRTW's
previous shared synchronization decoder.

The files in `tests/fixtures/awdl` retain only the action envelope and TLVs
4 (synchronization), 18 (channel sequence) and 24 (election). The 802.11
header is rebuilt with test MACs; every address in retained TLVs is replaced
consistently. TX clock fields are zeroed. Other TLVs, service identities and
payloads are removed. These are packet-format observations, not captures from
an AirportRTW hardware test.

- `iphone-election-transition.bin`, 203 bytes, SHA-256
  `70ed97453fd56155166890c24548cde95522575967b6b27b98c44ae144e2f0f0`:
  synchronization clock source differs from the elected root; embedded legacy
  channel 151 coexists with explicit channel 149 / operating class 128.
- `iphone-v9-psf.bin`, 203 bytes, SHA-256
  `441613b3946c1185f705883fbe25ba8e2b9ea9f1aa542cfc6d963cbb5f3cd0a8`:
  an explicit operating-class channel sequence supplies the primary-channel
  interpretation independently of the embedded legacy descriptors.

The decoder now preserves `syncMaster` separately from the elected `master`.
When an encoding-1 embedded list accompanies an encoding-3 standalone list,
matching count/stride are still required; the explicit list supplies channels.
Other contradictory lists remain malformed. Operating classes are checked
against the supported 2/5 GHz profile so a 6 GHz channel number cannot alias a
2.4 GHz channel. This check does not replace HAL regulatory authorization.
Only up to three zero padding bytes are accepted on a known channel list.

The election test retains a follower's observation while rejecting it as a
parent when it advertises our own address as root. Parsing an observation
does not authorize a peer, adopt its clock or permit a radio transmission.
