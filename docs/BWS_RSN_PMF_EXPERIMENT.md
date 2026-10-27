# Legacy mixed-mode RSN / modern hotspot experiment

Branch experiment/bws-rsn-pmf-compat, based on 95af8f0. BWS_RDC and WPA3 hotspot hardware tests passed on RTW89.
The unsuccessful RF-refresh change from 18dc0fb is not included.

The working 559c9e68 HAL did not advertise IEEE80211_C_MFP. Commit 35b664a
enabled it for SAE/PMF. The existing RSN writer bases MFPC and the optional
Group Management Cipher suffix on that local capability, so it also changed
ordinary WPA2 requests even when the AP did not advertise PMF. BWS_RDC's
advertisement has a TKIP group cipher and no PMF. This is a concrete request
difference, not proof that the AP rejects or mishandles those optional fields.

This experiment suppresses optional PMF advertisement only for RSN peers with
a selected TKIP group cipher, no advertised MFPC, no required-PMF policy and
no SAE AKM. It omits the corresponding Group Management Cipher suffix too.
It does not disable required PMF or SAE, change local PMF capability, select
a weaker pairwise cipher, alter WPA1 construction or restore the old firmware
station lifecycle. AES-group hotspot requests retain the current behavior.
Country/Locale/rate/MCS work and the diagnostic collector remain included.

The production-writer test checks the expected legacy body bytes and preservation
of required PMF, SAE, AES-group peers, WPA1 and PMKID. No password or key material
is involved in those vectors. Hardware validation must retry BWS_RDC, then the
previously working hotspot, on the same binary. This is not a proven fix.

Use the matching Debug Tahoe kext. Reboot and verify its UUID, attempt BWS_RDC
once, and collect the retained handshake counters. If it still fails before
EAPOL reception, do not infer a password problem or stack rejection from that
alone. Compare actual transmitted request metadata and station setup next.
No README changes or publication are part of this experiment.

## Hardware milestone: 2026-10-27

RTW89 RTL8852AE on the native Tahoe stack loaded test UUID
EFBD3BD1-2FA2-3FE6-BE63-FD0093099E2A (code commit 0c46ea3).
airportd recorded BWS_RDC join result error=0 and IPv4 acquisition.
The retained diagnostics showed association status=0, RUN, PortValid=true,
EAPOL RX/handler activity, TX submitted=6 and acknowledged=6 across the
recorded attempts, handshake stage=8 and error=0. DHCP provided an IPv4
address and three probes to the assigned gateway succeeded with zero loss.

The earlier build without this RSN change associated but received no detected
EAPOL and timed out; the separate RF-refresh experiment also failed. This
supports the RSN compatibility change for this AP, without proving the AP's
internal reason. The AP supplied no accepted country in this run, so world
country/Unknown Locale is expected. Internet throughput, sustained stability,
the modern hotspot and RTW88 remain unverified for this patch.

## Modern hotspot regression test: 2026-10-27

The same loaded UUID EFBD3BD1-2FA2-3FE6-BE63-FD0093099E2A connected to the
modern hotspot configured as WPA3-Personal with Wi-Fi 6 enabled. Native System
Information reported WPA3 Personal, 802.11ax, channel 4 / 20 MHz, 286 Mbps and
MCS 11. Diagnostics showed SAE-specific negotiated PHY=802.11ax, handshake
stage=8/error=0, EAPOL RX and acknowledged TX, PortValid=true, and the node's
MFP-negotiated flag set. DHCP succeeded and three assigned-gateway probes
returned with zero loss (one reply had elevated latency). Country TN and Locale
ETSI remained populated. These are successful connection/local-traffic tests
for BWS_RDC and the WPA3 hotspot on one binary; sustained throughput/stability,
hotspot WPA2 regression testing, and RTW88 hardware remain unverified.

## WPA2 hotspot regression test: 2026-10-27

The same UUID EFBD3BD1-2FA2-3FE6-BE63-FD0093099E2A successfully reconnected
after the modern hotspot changed from WPA3 to WPA2-Personal. Native reporting
showed WPA2 Personal, 802.11ax, channel 4 / 20 MHz, 286 Mbps / MCS 11, TN / ETSI.
Diagnostics showed RSN selected, AES/CCMP TX cipher, PortValid=true, handshake
stage=8/error=0 and acknowledged EAPOL TX. DHCP succeeded. This verifies WPA2
and WPA3 hotspot association plus BWS_RDC on the same binary; switching between
BWS_RDC and the hotspot, Wi-Fi power-cycle reconnect, sustained transfer and
RTW88 hardware still require testing.
