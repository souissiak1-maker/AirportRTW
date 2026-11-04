#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
python3 collect-coex.py --output "$HOME/Desktop/AirportRTW-coex-$(date +%Y%m%d-%H%M%S).json"
