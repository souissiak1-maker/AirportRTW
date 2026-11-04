#!/usr/bin/env python3
"""Bounded RTW89 coexistence-state collector; excludes network/device identities."""
import argparse,datetime,json,plistlib,subprocess,time
from pathlib import Path
KEYS=('RTW89CoexMode','RTW89CoexFlags','RTW89CoexBTInfoUpdates','RTW89CoexBTScoreboardUpdates','RTW89CoexH2CFailures','RTW89CoexReason','RTW89CoexAction','RTW89CoexObservations')
def cmd(args):
 try:return subprocess.check_output(args,stderr=subprocess.DEVNULL,timeout=15)
 except (OSError,subprocess.SubprocessError):return b''
def sample():
 try:entries=plistlib.loads(cmd(['/usr/sbin/ioreg','-r','-c','AirportRTW','-a','-l']))
 except (ValueError,plistlib.InvalidFileException):return []
 return [{k:e[k] for k in KEYS if k in e and isinstance(e[k],(bool,int))} for e in entries]
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--duration',type=int,default=180);a=p.parse_args()
 if not 1<=a.duration<=900:p.error('duration must be 1–900 seconds')
 result={'schema':1,'mode_values':{'normal':0,'wifi_only':1,'bluetooth_only':2,'wifi_off':3},'flags':{'bt_enabled':1,'bt_firmware_patch_running':2,'bt_mailbox_available':4,'manual_control':8,'forced_wifi_only':16,'bt_only':32,'wifi_rf_off':64,'initialized':128},'loaded_driver':[s.strip() for s in cmd(['/usr/bin/kmutil','showloaded']).decode(errors='replace').splitlines() if 'com.senmiko.AirportRTW ' in s],'samples':[]};end=time.monotonic()+a.duration
 try:
  while True:
   result['samples'].append({'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'controllers':sample()})
   if time.monotonic()>=end:break
   time.sleep(min(2,max(0,end-time.monotonic())))
 except KeyboardInterrupt:pass
 finally:a.output.write_text(json.dumps(result,indent=2)+'\n');print(a.output)
if __name__=='__main__':main()
