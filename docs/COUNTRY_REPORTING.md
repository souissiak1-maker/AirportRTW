# Regulatory country reporting

Both HAL country getters now read the effective driver domain under the wiphy
lock. RTW88 uses `regd.regulatory->alpha2`; RTW89 uses
`regulatory.regd->alpha2`. Missing domains report `00` (world), with a terminating
NUL. A programmed country is no longer hidden by the HAL's startup `00` cache.

The Apple frontends report that effective domain. They no longer substitute a
boot argument or a location string without applying it to the hardware. Country
set requests succeed only when the requested domain is already effective; other
requests return unsupported. This avoids claiming that an unapplied domain was
accepted. README and firmware versions are unchanged.

This is a reporting and API correctness fix, not a complete cfg80211 regulatory
implementation. The compatibility `regulatory_hint()` remains a stub. A world
configured card can still appear as Unknown in macOS. Geographic changes require
a validated regulatory rules source, channel/power-limit intersection with board
restrictions, safe synchronization with active scans/connections, and updates to
both the HAL and macOS channel lists. Simply invoking a notifier or copying an
AP country IE would not implement those requirements.

Validation: `python3 tests/rtw_country_snapshot_test.py` compiles and executes the
production C readers with ASan/UBSan for programmed/world/absent domains. Hardware
validation must check the new binary UUID and actual country after reboot.

## Local RTW89 AP-country experiment

Beacon/probe parsing retains a validated two-letter country (minimum full country
IE: three-byte country string plus a regulatory triplet). On successful RTW89
association, a known country is submitted to the driver's regulatory notifier
outside the wiphy lock; the notifier locks internally. Hardware-programmed
domains and COUNTRY_IE_IGNORE are respected. Unknown countries are ignored.
On disconnect an applied AP hint is cleared to world. Existing channel flags
are not relaxed. This selects RTW89's country-specific power tables; it does not
provide a geographic channel database or apply country triplets.

RTW88 only has the earlier effective-country reporting correction. The functional
AP-country experiment is RTW89-only pending hardware testing. The Apple setter
still rejects requests that were not applied. A router without a valid country
IE leaves the world domain in place.

Test: `python3 tests/rtw89_country_ie_test.py` (production helper, ASan/UBSan).

## Local RTW89 OS-country experiment

The shared optional HAL setter defaults to unsupported. RTW89 implements it
for recognized uppercase alpha2 codes using a USER regulatory request, checks
that the effective domain matches after the notifier, and rejects changes that
conflict with a board-programmed domain. RTW88 continues returning unsupported.
The native frontend defers country-change notification through the existing WCL
notification path. Same-domain requests do not generate notification loops.
Successful OS requests supersede AP hints and survive disassociation; the
driver's USER policy prevents a subsequent AP country from overriding them.
Requests received while the RTW89 hardware is stopped are rejected.

Three IORegistry properties on the controller record actual setter calls:
RTWCountryRequest, RTWCountryRequestApplied, RTWEffectiveCountry. They do not
prove a GPS/location origin; macOS supplies the request and may send none.
No GPS, network geolocation client or additional Location permission is added
to the kext. Existing channel flags are not relaxed and no regulatory database
is implemented. This applies the driver's power-table domain only.

Validation: `python3 tests/rtw89_os_country_test.py` compiles the production
setter with ASan/UBSan and verifies valid/unknown/invalid countries, programmed
domain conflicts and a notifier that fails to apply a request.

## Join-country trace

The local trace build publishes RTWAPCountry (validated country from the most
recent successful association, or `absent`), RTWAPCountryApplied (whether the
AP hint was accepted and has not since been reset/superseded), and
RTWEffectiveCountry (the current HAL domain). These are refreshed when the
country getter runs. RTWCountryRequest fields still record only actual OS setter
calls. An absent AP value does not distinguish a missing IE from one rejected
by validation. No country is invented from the host timezone or locale.

## Applied-domain notification

A scope guard compares the effective country before/after every RTW89 net80211
state transition, including early failure exits. A changed domain emits the
existing COUNTRY_CODE_UPDATE event after bridge locks have been released.
The native WCL handler defers onto its established off-workloop gated path,
reads the actual HAL domain, updates IO80211CountryCode, then posts the Apple
country-change message. Unchanged domains do not emit an event.

`tests/rtw_country_notification_test.py` executes the production guard under
ASan/UBSan for association, unchanged state, failure/reset and absent handler.
Hardware verification must compare RTWEffectiveCountry, IO80211CountryCode and
System Information; application privacy filtering may still affect the last.
