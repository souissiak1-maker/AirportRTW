#!/bin/zsh
set -eu
probe_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
probe_python="$(command -v python3 || true)"
if [[ -z "$probe_python" ]]; then
    print 'Python 3 is required for the sanitized collector.'
    exit 1
fi
probe_output="$HOME/Desktop/AirportRTW-AWDL-Probe-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$probe_output"
/usr/bin/sw_vers > "$probe_output/macos.txt"
# Only the matching driver's identity/UUID, never the entire extension list.
/usr/bin/kmutil showloaded 2>/dev/null | /usr/bin/grep -F 'com.senmiko.AirportRTW' > "$probe_output/loaded-kext.txt" || true
cp "$probe_dir/BUILD-IDENTITY.json" "$probe_output/expected-build.json"
print 'Collecting counters for 60 seconds. Keep Wi-Fi on; do not test sleep yet.'
"$probe_python" "$probe_dir/collect_wifi_diagnostics.py" --samples 30 --interval 2 --output "$probe_output/awdl-probe.json"
/usr/bin/ditto -c -k --keepParent "$probe_output" "$probe_output.zip"
print "Send this file: $probe_output.zip"
read -r '?Press Return to close.'
