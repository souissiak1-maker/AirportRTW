# Issue 7: RTW88 rate reporting test

The Apple rate and MCS getters previously used `ni_txmcs`, which the RTW88
firmware RA-report handler does not update. The driver could therefore pass
traffic at changing hardware rates while reporting a fixed MCS-derived value.
This does not establish that firmware rate adaptation itself was stuck.

The RTW88 bridge now reads `rtw_sta_info.ra_report.txrate` while holding the
same station-iteration lock used by the C2H RA handler and station unregister.
A shared, hardware-independent sample contains the actual mode, MCS, NSS,
width, guard interval, and bitrate in 100 kbps. Family-specific extraction
remains in the RTW88 HAL. Apple frontends consume this sample instead of
changing net80211's software rate-control state.

Until a firmware report arrives, the getters return not-ready rather than a
rate calculated from an untouched MCS field. Reassociation to a newly allocated
station cannot reuse the previous station's sample. Other HALs retain their
existing getter behavior until they implement the optional sample interface.

The HT/VHT bitrate calculation was cross-checked against Linux v6.12
`cfg80211_calculate_bitrate_ht` and `cfg80211_calculate_bitrate_vht` in
https://github.com/torvalds/linux/blob/v6.12/net/wireless/util.c . The older
compat-layer bitrate estimate is not used for the OS-facing calculation.
The public Apple rate field exposes integer Mbps; the HAL retains 100 kbps
precision. VHT MCS reporting uses the actual reported stream count and GI,
not the hardware maximum or advertised SGI capability.

The old `RTW88TxReportCount`/status/attempt properties were never populated;
they were not counters proving that firmware RA reports had stopped. Those
properties are no longer published. Debug builds expose the real RA snapshot
through `RTW88RALiveValid`, mode, MCS, NSS, bandwidth, short GI, and bitrate.
Release builds remain quiet and do not publish those debug properties.

## Validation

- Numeric HT/VHT/legacy rate fixtures, invalid inputs, width/NSS/GI changes.
- Production C snapshot-reader fixture: changing firmware reports, no station,
  no sample, and a fresh peer after reconnect; AddressSanitizer/UBSan enabled.
- Production early-return fixtures for all three Apple frontend implementations:
  live rate/MCS values, unknown reports, and unchanged other-HAL fallback.
- Build native Tahoe/Sequoia, Sonoma Skywalk, and Ventura legacy targets.

## Hardware test still required

On RTL8821CE, join a network, run sustained traffic, and compare the live
`system_profiler SPAirPortDataType` transmit rate/MCS before and during traffic.
A stable AP can legitimately keep one rate; the important distinction is a
valid firmware sample versus the previous default MCS calculation. Reconnect
and change bands to check that the report follows the active peer. If reports
never become available, investigate C2H RA delivery rather than reintroducing
a synthetic rate.

This patch does not change firmware rate selection, aggregation policy,
regulatory settings, SSID/BSSID privacy behavior, or RX decryption. Those
remaining findings in issue 7 require separate investigation and testing.
