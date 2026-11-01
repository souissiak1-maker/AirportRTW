#!/usr/bin/env python3
"""Collect native AWDL registration status without network identity or payloads."""
import argparse,json,plistlib,subprocess
from pathlib import Path
KEYS=('RTWAwdlEnabled','RTWAwdlCreateStage','RTWAwdlCreateStatus','RTWAwdlInterfaceReady',
    'RTWAwdlStartupRadioBlockers','RTWAwdlStartupRadioFrequency','RTWAwdlStartupRadioReady')
def command(args,timeout=15):
    try:
        result=subprocess.run(args,capture_output=True,timeout=timeout,check=False)
        return result.stdout if result.returncode==0 else b''
    except (OSError,subprocess.TimeoutExpired):return b''
def registry(name):
    data=command(['/usr/sbin/ioreg','-r','-c',name,'-a','-l'])
    try:return plistlib.loads(data) if data else []
    except (ValueError,plistlib.InvalidFileException):return []
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    controllers=[]
    for entry in registry('AirportRTW'):
        controllers.append({key:entry[key] for key in KEYS if key in entry and isinstance(entry[key],(str,bool,int))})
    interfaces=registry('AirportRTWAwdlInterface')
    loaded=command(['/usr/bin/kmutil','showloaded']).decode(errors='replace')
    driver=[line.strip() for line in loaded.splitlines() if 'com.senmiko.AirportRTW ' in line]
    profiler=command(['/usr/sbin/system_profiler','SPAirPortDataType','-detailLevel','mini'],timeout=30).decode(errors='replace')
    # Keep only AirDrop's support indication, never adjacent SSIDs/BSSIDs.
    support=[line.strip() for line in profiler.splitlines() if line.strip().startswith('AirDrop:')]
    # Controller readiness is the last creation-request snapshot. BSD matching
    # may complete afterwards, so also check the actual kernel interface list.
    names=command(['/sbin/ifconfig','-l']).decode(errors='replace').split()
    bsd_interfaces=[name for name in names if name.startswith('awdl') and name[4:].isdigit()]
    ready=bool(bsd_interfaces)
    result={'status':'driver-not-loaded' if not driver else ('native-registered' if interfaces and ready else ('bsd-pending' if interfaces else 'native-not-registered')),
        'loaded_driver':driver,'controller':controllers,'native_awdl_interface_count':len(interfaces),'bsd_awdl_interfaces':bsd_interfaces,'system_information_airdrop':support}
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(args.output)
if __name__=='__main__':main()
