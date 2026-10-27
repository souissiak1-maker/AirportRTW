#!/usr/bin/env python3
"""Ensure the issue collector excludes key material and network identities."""
import importlib.util
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('collector',root/'tools/collect_wifi_diagnostics.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
fixture=[{'RTW88AuthTxCount':3,'RTW88RxDecryptFailures':2,
 'RTW88PMKWord':1234,'RTW88Key':'secret-key','RTW88Payload':b'secret-payload',
 'RTWSAEStage':5,'RTWSAEPassword':b'secret-password',
 'IO80211SSID':b'private-network','IO80211BSSID':b'\x01\x02\x03\x04\x05\x06',
 'IORegistryEntryChildren':[{'RTWEffectiveCountry':'TN','RTWAPCountryApplied':True,
 'RTWIncompleteJoins':[{'PMK':b'secret-pmk'}]}]}]
filtered=module.filter_registry(fixture);text=json.dumps(filtered)
assert filtered[0]['RTW88AuthTxCount']==3
assert filtered[0]['IO80211SSIDLength']==15
assert filtered[0]['IO80211BSSIDPresent']
assert filtered[1]['RTWAPCountryApplied']
for secret in ['secret-','private-network','PMK','Payload','Password','1234']:
 assert secret not in text
assert module.filter_registry([{'IO80211SSID':b'','IO80211BSSID':bytes(6)}])[0]['IO80211BSSIDPresent'] is False
print('PASS: diagnostic counters retained; keys, payloads and network identities excluded')
