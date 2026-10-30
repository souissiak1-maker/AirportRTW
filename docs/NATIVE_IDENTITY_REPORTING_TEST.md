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
