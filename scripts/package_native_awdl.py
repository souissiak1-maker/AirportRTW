#!/usr/bin/env python3
"""Package the native Tahoe AWDL experiment separately from release assets."""
import hashlib,json,plistlib,shutil,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    source=ROOT/'build/releases/Release/Tahoe/AirportRTW.kext'
    binary=source/'Contents/MacOS/AirportRTW'
    if not binary.is_file() or b'RTWAwdlCreateStage' not in binary.read_bytes():
        raise SystemExit('Build the native Tahoe Release target first')
    dirty=subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT,text=True)
    if any(line[3:]!='.DS_Store' for line in dirty.splitlines()):raise SystemExit('Commit source changes before packaging')
    output=ROOT/'build/diagnostics';output.mkdir(parents=True,exist_ok=True)
    folder=output/'AirportRTW-Tahoe-Native-AWDL-v4'
    if folder.exists():shutil.rmtree(folder)
    folder.mkdir();kext=folder/'AirportRTW.kext';shutil.copytree(source,kext)
    subprocess.run([sys.executable,str(ROOT/'scripts/validate_kext_imports.py'),str(kext),
        '--report',str(folder/'IMPORT-VALIDATION.json')],check=True)

    plist=kext/'Contents/Info.plist';info=plistlib.loads(plist.read_bytes())
    personality=info['IOKitPersonalities']['NetworkController']
    if personality['IOClass']!='AirportRTW':raise SystemExit('Unexpected controller personality')
    personality['RTWAwdlEnabled']=True
    personality.pop('RTWAwdlProbeEnabled',None)
    plist.write_bytes(plistlib.dumps(info,sort_keys=False))
    executable=kext/'Contents/MacOS/AirportRTW'
    uuid=subprocess.check_output(['xcrun','dwarfdump','--uuid',str(executable)],text=True).split()[1]
    identity={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'package':'Tahoe native AWDL v4','configuration':'Release with experimental native AWDL opt-in',
        'bundle_identifier':info['CFBundleIdentifier'],'bundle_version':info['CFBundleVersion'],
        'firmware_display':'AirportRTW'+info['CFBundleVersion'],'executable_uuid':uuid,
        'binary_sha256':sha(executable),'info_plist_sha256':sha(plist),
        'native_awdl_hal':'RTW89 only','airdrop_transfer_verified':False}
    (folder/'BUILD-IDENTITY.json').write_text(json.dumps(identity,indent=2)+'\n')
    for path in (ROOT/'tools/awdl_native').iterdir():
        if path.is_file():shutil.copy2(path,folder/path.name)
    archive=output/(folder.name+'.zip')
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9)as z:
        for path in sorted(folder.rglob('*')):
            if path.is_file():z.write(path,path.relative_to(output))
    (output/(archive.name+'.sha256')).write_text(sha(archive)+'  '+archive.name+'\n')
    print(archive);print(json.dumps(identity,indent=2))
if __name__=='__main__':main()
