#!/usr/bin/env python3
"""Validate RTW88 hardware isolation, matching, firmware and optional bundles."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HAL = ROOT/'rtw/hal_rtw88'
EXPECTED = {0xc822, 0xc82f, 0xb822, 0xc821, 0xb821, 0xd723, 0x8813}

def require(ok, message):
    if not ok: raise RuntimeError(message)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundles', action='store_true')
    parser.add_argument('--platforms', nargs='+', choices=['High Sierra', 'Mojave', 'Catalina', 'Big Sur', 'Monterey', 'Ventura', 'Sonoma14.0', 'Sonoma14.4', 'Sequoia', 'Tahoe'], default=['Tahoe', 'Sequoia'])
    opts = parser.parse_args()
    for path in ['AirportRTW/AirportRTW.cpp', 'AirportRTW/IOPCIEDeviceWrapper.cpp',
                 'rtw/RTWEthernetController.cpp']:
        frontend = (ROOT/path).read_text()
        require('#include <HAL/RealtekHalFactory.hpp>' in frontend and
                'createRealtekHal(device)' in frontend,
                path+': frontend must select both HALs through the shared factory')
    hardware = (HAL/'Rtw88Hardware.c').read_text()
    ids = {int(s,16) for s in re.findall(r'case (0x[0-9a-f]+):', hardware)}
    require(ids == EXPECTED, 'Probe IDs differ from supported PCIe cards')
    upstream = set()
    for chip in ['rtw8822ce', 'rtw8822be', 'rtw8821ce', 'rtw8723de', 'rtw8814ae']:
        upstream.update(int(s,16) for s in re.findall(r'PCI_DEVICE\(PCI_VENDOR_ID_REALTEK,\s*(0x[0-9A-Fa-f]+)\)', (HAL/'driver'/f'{chip}.c').read_text()))
    require(ids == upstream, 'Probe must match actual upstream PCI ID tables')
    for path in [ROOT/'rtw/Info.plist', *list((ROOT/'AirportRTW').rglob('*Info.plist'))]:
        info = plistlib.loads(path.read_bytes())
        matches = {int(token, 16) >> 16
                   for entry in info.get('IOKitPersonalities', {}).values()
                   for key in ['IOPCIMatch', 'IOPCIPrimaryMatch']
                   for token in entry.get(key, '').split()}
        require(EXPECTED <= matches, str(path)+': missing RTW88 PCI matches')
    require('id.driver_data' in hardware and 'rtw_pci_probe(pdev, &id)' in hardware,
            'RTW88 requires actual chip specification at probe')
    for fw in ['rtw8821c_fw.bin','rtw8822b_fw.bin','rtw8822c_fw.bin','rtw8723d_fw.bin','rtw8814a_fw.bin']:
        require((HAL/'firmware'/fw).stat().st_size > 20000, 'Missing/truncated firmware: '+fw)
    require((HAL/'firmware/LICENCE.rtlwifi_firmware.txt').is_file(), 'Missing firmware notice')
    require(not list(HAL.rglob('*IEEE80211.cpp')), 'Donor MLME must not replace net80211')
    bridge = (HAL/'Rtw88LinuxBridge.cpp').read_text()
    require('stationAdded' in bridge and 'hw->txq_data_size' in bridge, 'Missing queue allocation/unwind')
    require('rtw88LinuxSetMacAddress' in bridge, 'Missing private MAC programming')
    require('IODelay(500)' not in (HAL/'compat/rtw88_compat.c').read_text(),
            'Timer teardown must wait for callbacks rather than guessing a delay')
    manifest = json.loads((HAL/'UPSTREAM.json').read_text())
    for path, expected in manifest['files'].items():
        require(hashlib.sha256((HAL/path).read_bytes()).hexdigest() == expected,
                'Imported donor file changed without provenance update: '+path)
    if opts.bundles:
        for platform in opts.platforms:
            bundle=ROOT/f'build/releases/Release/{platform}/AirportRTW.kext'
            plist=plistlib.loads((bundle/'Contents/Info.plist').read_bytes())
            matches={int(x,16)>>16 for p in plist['IOKitPersonalities'].values() for x in p.get('IOPCIMatch','').split()}
            rtw89={0x8852,0xa85a,0xb852,0xb85b,0xb851,0xb520,0xc852,0x8922,0x892b}
            require(matches==EXPECTED | rtw89, platform+': incorrect combined PCI matches')
            if platform in ('Tahoe', 'Sequoia'):
                require('com.apple.iokit.IO80211FamilyLegacy' not in plist['OSBundleLibraries'], 'Unexpected legacy stack for native WCL target')
            binary=bundle/'Contents/MacOS/AirportRTW'
            symbols=subprocess.check_output(['nm',str(binary)],text=True)
            require('_ZN7RTWCore10gMetaClassE' in symbols,
                    'Missing shared RTWCore base class')
            require('RTWCore88' in symbols, 'Missing RTW88 HAL')
            for chip in ['8821c', '8822b', '8822c', '8723d', '8814a']:
                require('_airportrtw88_rtw'+chip+'_hw_spec' in symbols,
                        'Missing chip implementation: '+chip)
            require('_rtw89_pci_probe' in symbols and 'RTWCore89' in symbols, 'RTW89 backend missing from combined kext')
            require('_airportrtw88_rtw_pci_probe' in symbols, 'RTW88 probe is not isolated')
            unresolved=subprocess.check_output(['nm','-u',str(binary)],text=True)
            require(not any(line.strip().startswith(('_rtw','_airportrtw88')) for line in unresolved.splitlines()), 'Unresolved backend symbols')
            require((bundle/'Contents/Resources/LICENCE.rtlwifi_firmware.txt').is_file(), 'Packaged firmware notice missing')
            derived=ROOT/f'build/releases-obj/AirportRTW.build/Release/AirportRTW-{platform}.build/DerivedSources'
            exports=[]
            for archive in ['librtw88_c.a', 'librtw89_c.a']:
                output=subprocess.check_output(['nm','-gU',str(derived/archive)],text=True,stderr=subprocess.DEVNULL)
                exports.append(set(re.findall(r'^[0-9a-fA-F]+\s+[A-Z]\s+_(\w+)$',output,re.M)))
            require(exports[0] and all(n.startswith('airportrtw88_') for n in exports[0]),
                    'RTW88 compatibility exports must all remain private')
            require(not exports[0] & exports[1], 'RTW88/RTW89 archives have colliding exports')
    print('OK: RTW88 PCI matching, source provenance, firmware, isolation'+(' and combined native bundles' if opts.bundles else ''))

if __name__=='__main__': main()
