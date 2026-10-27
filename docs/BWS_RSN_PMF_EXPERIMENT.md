# Legacy mixed-mode RSN / modern hotspot experiment

Branch experiment/bws-rsn-pmf-compat, based on 95af8f0. Hardware testing pending.
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
