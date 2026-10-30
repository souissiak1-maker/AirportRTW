# Native identity reporting investigation

This branch retains AWDL feasibility work but does not implement AWDL/AirDrop.
The test package uses the previously hardware-tested RTW88 capability mask
without MFP advertisement. It is WPA2-only for RTW88, not the PMF experiment.
RTW89 behavior is unchanged. Bundle and display version are 2.3.0.

The identity getters already copy the RUN node's SSID and BSSID. This change
clears output before returning an error so failed calls cannot leave stale
identity data, and records privacy-safe getter call/results on the controller:

- RTWIdentityNameCalls / RTWIdentityPeerCalls: cumulative getter calls.
- RTWIdentityNameResult / RTWIdentityPeerResult: last status, zero success.
- RTWIdentityNameLength: last successful SSID length, not the SSID.

The collector explicitly whitelists only these numeric fields. No identity,
key material, or privacy-bypass registry property is added. The counters are
shared by all callers, so success proves a getter can return valid data but
cannot by itself identify the CoreWLAN caller or prove privacy is the cause.
Additional application authorization/IPC-path testing may still be required.

This is not a verified fix for nil CoreWLAN identity or networksetup reporting.
AP country absent + no accepted OS domain remains 00/Unknown; do not replace it
with an invented country or relax channel restrictions. No TCP/HTTP transfer
fix is claimed. networkQuality -1005 requires transport-level comparison.

Test with the same native Tahoe stack and known WPA2 AP. First confirm joining,
DHCP and traffic. While running the collector, repeat the commands/API calls
that report nil or not associated. Return the JSON, exact API/command used,
loaded UUID and approximate time. Do not replace the working rollback EFI.

## Local Tahoe root cause confirmed (2026-10-30)

On RTL8852AE / Tahoe 25F71, networksetup GET SSID was rejected by airportd
before reaching the driver. The debug log explicitly records:
APP NOT AUTHORIZED FOR LOCATION SERVICES (status=0, proc=networksetup,
req=GET SSID), followed by err=1. The tool then prints not associated.
This proves the cause of this local networksetup failure; it does not prove
that all other callers or the remote RTL8821CE report have the same cause.

Disassembly of the local IO80211Family shows getSSID forwarding through
IO80211Glue::sendIOUCToWcl and WCLConfigManager::getSSID, which queries Apple's
BSS manager before falling back to the driver's interface getter. Absent
custom getter counters are therefore not evidence of a broken getter.

CoreWLAN's SDK header explicitly requires Location authorization for SSID,
BSSID and countryCode. A normal app should request that permission; no kext
patch should bypass it. tools/identity_check builds a small standalone app
with a usage description and an explicit authorization button. It requests
no coordinates, performs no scans, uploads nothing, and never changes the
Wi-Fi connection. The user must accept the OS prompt. An authorized app
returning nil still requires independent cache/driver investigation.

The app does not grant permissions to networksetup or change that tool's
wording. It provides an authorized way to inspect the same CoreWLAN identity.
No new kext is necessary for the confirmed local permission failure.
