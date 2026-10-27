# Issue 7: native RTW88 diagnostics

This diagnostic branch is based on e1b0c9c, without the speculative RTW88
pre-SAE rollback from experiment/rtw88-69e5-join. Both HALs and the latest
rate/MCS, country and Locale work are included. Hardware validation of the
RTL8821CE join remains pending. No throughput or decrypt behavior is changed.

## What was established

- The native SSID/BSSID getters already return the current net80211 BSS while
  RUN. They now reject null output buffers and missing controller/BSS state
  safely. This does not prove the reporter's nil identities are fixed.
- RTW88RxDecryptFailures is net80211 is_rx_wepfail: software decryption failed
  while receive protection was enabled. It is not a total hardware CCMP failure
  count. Replay and integrity errors have their own counters.
- RTW88RxConnectionUndecrypted counts protected downlink frames from the current
  AP that lack RX_FLAG_DECRYPTED, before net80211 software processing. It does
  not establish that those packets were subsequently dropped. Counters are
  cumulative; compare snapshots and successful RX/protected RX denominators.
- Apple documents the password argument as required for WPA/WPA2 Personal:
  https://developer.apple.com/documentation/corewlan/cwinterface/associate(to:password:).
  A nil-password keychain fallback is not part of the documented contract.
- Privacy filtering is a separate possible cause of nil identity fields. No
  permission or privacy bypass is introduced by this diagnostic build.

## Tester procedure

Install the diagnostic Tahoe kext in the existing native-stack configuration
and reboot. Record kmutil showloaded output to identify the executable UUID.
The version remains 2.2.0, so version alone cannot distinguish these binaries.

Copy collect_wifi_diagnostics.py to a convenient location. In Terminal run:

```sh
python3 collect_wifi_diagnostics.py --output issue7-join.json --samples 30 --interval 2
```

During that minute make exactly one manual WPA2 join attempt with the correct
password, then leave the connection state unchanged until sampling finishes.
Share issue7-join.json, the loaded UUID, the attempt's outcome and channel.
The collector excludes passwords, arbitrary strings/blobs, packet payloads and
SSID/BSSID values; identity properties are recorded only as lengths/presence.
Do not substitute a full IORegistry or unfiltered kernel-log dump.

The Debug configuration enables existing auth/association TX/RX counters, last
association response status/AID, net80211 state, key/cipher status, EAPOL-stage
metadata and decrypt/replay/integrity counters. The collector selects numeric
metadata only. If no numeric RTW88 fields appear after several samples, verify
the loaded UUID and selected HAL before interpreting zero/missing counters.

For successful association, repeat sampling during a bounded transfer to
compare live PHY reports, protected RX, software/hardware decrypt processing
and successful delivery. This does not isolate a campus WAN throughput limit;
a controlled local-LAN measurement is needed before changing rate/aggregation
behavior. CoreWLAN nil identity must be compared with interface registry field
presence and the caller's location authorization, not inferred from menu UI.

Build: CONFIGURATION=Debug bash scripts/build_release_kexts.sh AirportRTW-Tahoe
Tests: rtw_identity_getter_test.py and wifi_diagnostic_collector_test.py.
