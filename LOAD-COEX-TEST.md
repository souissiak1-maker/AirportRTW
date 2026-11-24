# AirportRTW 2.3.3 RTL8852CE load coexistence test

This entire source tree is based on V2.3.3 at
`eaeab26ffd9b8842ba4c47134f1687d868a0ae47`. Its changes are also included as
`rtw89-load-coex.patch` for reviewing or applying to a separate clean checkout.

The patch retains the earlier A2DP scoreboard transition fix. With the full
watchdog disabled, RTL8852C now samples host TX/RX traffic on the existing
two-second timer. Coexistence reacts when the aggregated busy state or traffic
direction changes. The decision uses the updated WLAN busy bit, which the
normal coexistence path writes to the hardware scoreboard. This path skips
the watchdog's throughput-offload commands and the station role report.

## Build on macOS with full Xcode

From the extracted source directory, run:

```bash
bash build-airportrtw-load-coex.sh
```

The script runs the focused coexistence test, then builds the x86_64 Sequoia
Release target. The output is
`build/releases/Release/Sequoia/AirportRTW.kext`. Keep a copy of the working
kext before replacing the entire installed `AirportRTW.kext` bundle.

## Test with AirPods

Play a local audio file with the same AirPods and hotspot. Compare idle Wi-Fi
to sustained upload and download, using the same source and load as before.
The test harness verifies driver policy dispatch and scoreboard ordering.
It cannot measure Bluetooth airtime or audio stability.

For optional diagnostics, run this while the transfer is in progress:

```bash
ioreg -l -w 0 | grep -E '"RTW89Coex(Flags|Reason|Action|H2CFailures)"'
```

In `RTW89CoexFlags`, bit 8 (256) means WLAN busy, bit 9 (512) means the
driver sees A2DP, and bit 10 (1024) means the busy direction includes download.
