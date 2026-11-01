#!/bin/zsh
set -eu
awdl_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
awdl_python="$(command -v python3 || true)"
if [[ -z "$awdl_python" ]]; then
    print 'Python 3 is required for this collector.'
    exit 1
fi
awdl_output="$HOME/Desktop/AirportRTW-Native-AWDL-$(date +%Y%m%d-%H%M%S).json"
"$awdl_python" "$awdl_dir/collect-native-awdl.py" --output "$awdl_output"
print "Send this status file: $awdl_output"
read -r '?Press Return to close.'
