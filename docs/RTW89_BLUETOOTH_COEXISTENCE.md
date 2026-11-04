# Automatic RTW89 Bluetooth coexistence

The frontend previously called rtw88_force_wifi_only() after probe. That latched
a global boolean used by every rtw89_core_start(), forcing BTC_MODE_WL even
when Bluetooth firmware and a driver were active. WLAN-only antenna/grant
selection could therefore prevent Bluetooth reception while Wi-Fi was on.

The fix removes the frontend override, latch, exported override API and outdated
assumption that Bluetooth cannot run on macOS. Every core start now initializes
the existing chip engine in BTC_MODE_NORMAL. This includes starts after Wi-Fi
power cycling or resume. RTW88 remains independent and is unchanged.

Normal mode already reads the Bluetooth scoreboard at initialization and reacts
to BT scoreboard/info C2H notifications. A disabled BT half selects the existing
BT-off/WLAN-only grant action; enabling BT or starting its firmware later can
select the chip-specific shared-radio policy. No USB presence heuristic, boot
argument, binary patch or new userspace helper selects this policy.

Existing firmware mailbox polling remains bounded. Its timeout behavior is
tested with a silent and a delayed responder; neither test proves a physical
MMIO access can recover from a platform-level bus fault. No new hardware-error
fallback or periodic RF polling is introduced.

Passive engine observations are copied to the existing bridge context; the
watchdog publishes changed scalar snapshots under RTW89Coex* IORegistry keys.
Mode 0 is normal. Flags indicate BT enabled/patch/mailbox, manual override,
Wi-Fi-only/BT-only, RF off and init status. Event counters distinguish absent
Bluetooth information from a Bluetooth controller that has actually reported.
No IOKit calls are made under the BTC engine locks and no frame data is retained.

Tests execute the production init, scoreboard and dispatcher code with hardware
adapters, covering BT absent/off, late enable/firmware, invalid scoreboard,
2.4/5 GHz policy dispatch, repeated starts and firmware layouts 0/2/7. Actual
scan, pairing, simultaneous transfer/audio and long-term operation remain
hardware tests; no claim is made before those results.
