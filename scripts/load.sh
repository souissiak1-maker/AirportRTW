#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE="$ROOT/build/releases/${CONFIGURATION:-Debug}/RTWCore.kext"
sudo kextunload -b com.senmiko.RTWCore || true
sudo chown -R root:wheel "$BUNDLE"
sudo kextutil -v 6 "$BUNDLE"
