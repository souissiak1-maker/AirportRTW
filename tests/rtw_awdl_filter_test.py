#!/usr/bin/env python3
"""Execute both HALs' production receive-filter helpers with simulated driver ops."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
for chip in ['88','89']:
    s=(root/f'rtw/hal_rtw{chip}/Rtw{chip}LinuxBridge.cpp').read_text()
    a=s.index('static void applyReceiveFilter(')
    b=s.index('\n}\n',s.index(f'void rtw{chip}LinuxSetAllMulticast(',a))+3
    fn=s[a:b]
    fixture=r'''
#include <AWDL/RTWAwdlRxPolicy.hpp>
#include <cassert>
constexpr unsigned FIF_ALLMULTI=1,FIF_OTHER_BSS=2,FIF_BCN_PRBRESP_PROMISC=4;
static int calls=0,depth=0;static unsigned lastMask,lastFlags;static bool reject=false;
struct ieee80211_hw;
static void configure(ieee80211_hw*,unsigned mask,unsigned *flags,unsigned){
 assert(depth==1);++calls;lastMask=mask;lastFlags=*flags;
 if(reject)*flags&=~FIF_OTHER_BSS;
}
struct Ops {decltype(&configure) configure_filter=configure;};
struct ieee80211_hw {Ops *ops;};
struct WiphyGuard {WiphyGuard(ieee80211_hw*){assert(!depth);++depth;}~WiphyGuard(){--depth;}};
struct CONTEXT {void *hardware;bool started=false,interfaceAdded=false,allMulticast=false,scanning=false,awdlDiscovery=false,awdlDiscoveryApplied=false;};
'''.replace('CONTEXT',f'Rtw{chip}LinuxContext')+fn+r'''
int main(){
 Ops ops;ieee80211_hw hw{&ops};CONTEXT c{&hw};
 PREFIXLinuxSetAwdlDiscovery(&c,true);assert(!calls&&!c.awdlDiscoveryApplied);
 c.started=c.interfaceAdded=true;PREFIXLinuxSetAwdlDiscovery(&c,true);
 assert(c.awdlDiscoveryApplied&&lastFlags==7&&lastMask==7&&!depth);
 // A multicast update must preserve discovery filters.
 PREFIXLinuxSetAllMulticast(&c,true);assert(lastFlags==7&&c.awdlDiscoveryApplied);
 // Scan completion must retain discovery; disabling it restores multicast only.
 applyReceiveFilter(&c,false);assert(lastFlags==7);
 PREFIXLinuxSetAwdlDiscovery(&c,false);assert(lastFlags==1&&!c.awdlDiscoveryApplied);
 c.scanning=true;PREFIXLinuxSetAllMulticast(&c,false);assert(lastFlags==6);
 c.scanning=false;applyReceiveFilter(&c,false);assert(lastFlags==0);
 reject=true;PREFIXLinuxSetAwdlDiscovery(&c,true);assert(!c.awdlDiscoveryApplied);
 int old=calls;hw.ops=nullptr;applyReceiveFilter(&c,false);assert(calls==old&&!c.awdlDiscoveryApplied);
 PREFIXLinuxSetAwdlDiscovery(nullptr,true);PREFIXLinuxSetAllMulticast(nullptr,true);
}
'''.replace('CONTEXT',f'Rtw{chip}LinuxContext').replace('PREFIX',f'rtw{chip}')
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp);(p/'t.cpp').write_text(fixture)
        subprocess.run(['xcrun','clang++','-std=c++14','-fsanitize=address,undefined','-I'+str(root/'include'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
        subprocess.run([str(p/'t')],check=True)
print('PASS: both HAL filter transitions, multicast coexistence, rejected flags and guard ownership')
