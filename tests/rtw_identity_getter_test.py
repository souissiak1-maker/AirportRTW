#!/usr/bin/env python3
"""Exercise native identity getters through incomplete and complete joins."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'AirportRTW/WCL/AirportRTWSkywalkInterface.cpp').read_text()
functions=[]
for method in ['getSSID','getBSSID']:
 a=s.index(method+'(struct ');end=s.index('\n}',a)+2
 functions.append(s[a:end])
fixture=r'''
#include <cassert>
#include <cstring>
#include <cstdint>
#define AIRPORT_WCL 1
#define MIN(a,b) ((a)<(b)?(a):(b))
#define APPLE80211_VERSION 1
#define APPLE80211_ADDR_LEN 6
#define IEEE80211_S_RUN 4
#define kIOReturnError 1
#define kIOReturnBadArgument 2
#define kIOReturnSuccess 0
using IOReturn=int;
struct Node {unsigned ni_esslen;char ni_essid[32];unsigned char ni_bssid[6];};
struct ieee80211com {int ic_state;Node*ic_bss;};
struct apple80211_ssid_data {unsigned version,ssid_len;char ssid_bytes[32];};
struct apple80211_bssid_data {unsigned version;struct {unsigned char octet[6];}bssid;};
struct Hal {ieee80211com*ic;ieee80211com*get80211Controller(){return ic;}};
static Hal*fHalService;
'''+ '\n'.join('IOReturn '+fn for fn in functions)+r'''
int main(){
 Node node={};ieee80211com ic={0,nullptr};Hal hal={&ic};fHalService=&hal;
 apple80211_ssid_data ssid={};apple80211_bssid_data bssid={};
 assert(getSSID(nullptr)!=0&&getBSSID(nullptr)!=0);
 hal.ic=nullptr;assert(getSSID(&ssid)!=0&&getBSSID(&bssid)!=0);
 hal.ic=&ic;ic.ic_state=4;assert(getSSID(&ssid)!=0&&getBSSID(&bssid)!=0);
 ic.ic_bss=&node;node.ni_esslen=4;memcpy(node.ni_essid,"test",4);node.ni_bssid[0]=2;
 assert(!getSSID(&ssid)&&ssid.ssid_len==4&&!memcmp(ssid.ssid_bytes,"test",4));
 assert(!getBSSID(&bssid)&&bssid.bssid.octet[0]==2);
 ic.ic_state=0;assert(getSSID(&ssid)!=0&&getBSSID(&bssid)!=0);
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.cpp';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: native identity getters handle null buffers, missing association and valid identity')
