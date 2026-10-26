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

The original functional AP-country experiment was RTW89-only; the RTW88
extension is described below. The Apple setter
still rejects requests that were not applied. A router without a valid country
IE leaves the world domain in place.

Test: `python3 tests/rtw89_country_ie_test.py` (production helper, ASan/UBSan).

## Local RTW89 OS-country experiment

The shared optional HAL setter defaults to unsupported. RTW89 implements it
for recognized uppercase alpha2 codes using a USER regulatory request, checks
that the effective domain matches after the notifier, and rejects changes that
conflict with a board-programmed domain. RTW88 now implements the setter using its own state machine (see below).
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

## RTW88 extension (hardware testing pending)

RTW88 now retains the joined AP country, applies a known country through its
regulatory notifier, restores world after an AP-derived domain on disconnect,
and emits the same changed-domain event used by the native frontend. OS hints
use USER requests; the RTW88 SETTING state prevents AP/reset overrides.
PROGRAMMED states reject conflicting requests. Programmed-domain DRIVER hints reach the notifier after hardware start,
so the efuse domain is applied without writing registers during probe.
The driver mutex remains owned by the notifier; bridge calls serialize with the
wiphy lock. Existing channel flags are not relaxed. Imported driver files are
unchanged. Rtw88CountryCodes.h mirrors the donor table; the production-state
test verifies it matches exactly.

Validation: `python3 tests/rtw88_country_test.py` runs the real state handlers and
notifier with the new helpers under ASan/UBSan. Tests cover AP hints/reset, OS
priority, malformed/unknown codes, programmed-domain protection and probe hints.
RTW89 automatic AP application and native reporting were hardware verified with
TN. RTW88 hardware has not been tested; testers should check both HAL and native
country properties on association, switching APs, disconnect, and Wi-Fi toggle.
