#!/usr/bin/env python3
"""Package the isolated Tahoe lifecycle diagnostic without touching normal releases."""
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    source=ROOT/'build/awdl-startup-probe/Release/Tahoe/AirportRTW.kext'
    binary=source/'Contents/MacOS/AirportRTW'
    if not binary.is_file() or b'RTWAwdlProbeRevision' not in binary.read_bytes():
        raise SystemExit('Build the opt-in Tahoe probe first; executable lacks probe diagnostics')
    output=ROOT/'build/diagnostics'
    output.mkdir(parents=True,exist_ok=True)
    folder=output/'AirportRTW-Tahoe-AWDL-Probe-v1'
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir()
    kext=folder/'AirportRTW.kext'
    shutil.copytree(source,kext)
    plist=kext/'Contents/Info.plist'
    info=plistlib.loads(plist.read_bytes())
    personality=info['IOKitPersonalities']['NetworkController']
    if personality['IOClass']!='AirportRTW':
        raise SystemExit('Unexpected controller personality')
    personality['RTWAwdlProbeEnabled']=True
    plist.write_bytes(plistlib.dumps(info,sort_keys=False))
    executable=kext/'Contents/MacOS/AirportRTW'
    uuid=subprocess.check_output(['xcrun','dwarfdump','--uuid',str(executable)],text=True).split()[1]
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    dirty=subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT,text=True)
    relevant_dirty=[line for line in dirty.splitlines() if line[3:]!='.DS_Store']
    if relevant_dirty:
        raise SystemExit('Commit source changes before packaging: '+str(relevant_dirty))
    identity={'source_commit':commit,'package':'Tahoe AWDL lifecycle probe v1',
              'configuration':'Release-optimized diagnostic','macos':'Tahoe / Darwin 25',
              'bundle_identifier':info['CFBundleIdentifier'],
              'bundle_version':info['CFBundleVersion'],
              'firmware_display':'AirportRTW'+info['CFBundleVersion'],
              'executable_uuid':uuid,'binary_sha256':sha(executable),
              'info_plist_sha256':sha(plist),'general_verbose_diagnostics':False,
              'awdl_probe_revision':1,'native_awdl_interface_published':False}
    (folder/'BUILD-IDENTITY.json').write_text(json.dumps(identity,indent=2)+'\n')
    for name in ('collect-awdl.command','TEST-INSTRUCTIONS.txt'):
        shutil.copy2(ROOT/'tools/awdl_startup_probe'/name,folder/name)
    shutil.copy2(ROOT/'tools/collect_wifi_diagnostics.py',folder/'collect_wifi_diagnostics.py')
    archive=output/(folder.name+'.zip')
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for path in sorted(folder.rglob('*')):
            if path.is_file():
                z.write(path,path.relative_to(output))
    (output/(archive.name+'.sha256')).write_text(sha(archive)+'  '+archive.name+'\n')
    print(archive)
    print(json.dumps(identity,indent=2))
if __name__=='__main__':
    main()
