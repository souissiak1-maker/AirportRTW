#!/usr/bin/env python3
"""Compatibility entry point: build the single combined RTW88/RTW89 kext."""
import argparse
from pathlib import Path
import subprocess
ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platforms', nargs='*', choices=['Tahoe', 'Sequoia'])
    parser.add_argument('--incremental', action='store_true', help='Retained for CLI compatibility; Xcode manages incremental builds')
    options = parser.parse_args()
    platforms = options.platforms or ['Tahoe', 'Sequoia']
    subprocess.run(['bash', str(ROOT/'scripts/build_release_kexts.sh'),
                    *('AirportRTW-'+p for p in platforms)], cwd=ROOT, check=True)
    subprocess.run(['python3', str(ROOT/'tools/validate_rtw88_backend.py'),
                    '--bundles', '--platforms', *platforms], cwd=ROOT, check=True)
