#!/usr/bin/env python3
"""Collect bounded AirportRTW status without passwords, keys or packet payloads."""
import argparse
import json
import plistlib
from pathlib import Path
import subprocess
import time

COUNTRY_KEYS = {'RTWHALFamily', 'RTWAPCountry', 'RTWEffectiveCountry',
                'RTWCountryRequest', 'IO80211CountryCode', 'IO80211Locale'}
IDENTITY_KEYS = {'IO80211SSID', 'IO80211BSSID'}

def filter_registry(tree):
    entries = []
    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            fields = {}
            for key, item in value.items():
                # Never serialize arbitrary RTW strings, blobs, arrays or nested
                # diagnostic dictionaries: they can contain frame/key material.
                if (key.startswith(('RTW88', 'RTW89', 'RTWSAE', 'RTWLastIncompleteJoin'))
                        and isinstance(item, (int, bool))
                        and not any(token in key.lower() for token in
                                    ('password', 'pmk', 'ptk', 'gtk', 'kck', 'kek',
                                     'nonce', 'bssid', 'ssid', 'macaddress', 'header', 'payload'))):
                    fields[key] = item
                elif key in COUNTRY_KEYS and isinstance(item, str):
                    fields[key] = item
                elif key in IDENTITY_KEYS and isinstance(item, (str, bytes)):
                    fields[key + 'Length'] = len(item)
                    fields[key + 'Present'] = bool(item) and any(item if isinstance(item, bytes) else item.encode())
                elif key in {'RTWAPCountryApplied', 'RTWCountryRequestApplied'} and isinstance(item, (bool, int)):
                    fields[key] = item
            if fields:
                entries.append(fields)
            for item in value.values():
                if isinstance(item, (dict, list)):
                    visit(item)
    visit(tree)
    return entries

def snapshot():
    result = subprocess.run(['/usr/sbin/ioreg', '-a', '-l', '-w', '0'],
                            check=True, capture_output=True)
    return {'timestamp': time.time(), 'entries': filter_registry(plistlib.loads(result.stdout))}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--samples', type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.samples <= 120 or not 0.25 <= args.interval <= 60:
        parser.error('samples must be 1..120 and interval 0.25..60 seconds')
    records = []
    for index in range(args.samples):
        records.append(snapshot())
        if index + 1 < args.samples:
            time.sleep(args.interval)
    args.output.write_text(json.dumps({'samples': records}, indent=2) + '\n')
    print(f'Saved {len(records)} sample(s) to {args.output}')

if __name__ == '__main__':
    main()
