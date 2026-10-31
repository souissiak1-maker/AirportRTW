#!/usr/bin/env python3
"""Exercise actual native interface lifecycle/forwarders with host adapters."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
strip=lambda s:re.sub(r'^#include[^\n]*\n','',s,flags=re.M)
abi=(ROOT/'include/Airport/macOS26/IO80211AWDLProtocol.h').read_text().split('class IO80211AWDLProtocol :',1)[1]
methods=re.findall(r'virtual IOReturn\s+(\w+)\(\s*(\w+)\s*\*\)\s*= 0;',abi,re.S)
assert len(methods)==63
base='\n'+''.join(f'struct {t};\n' for t in sorted({t for _,t in methods}))
base+='struct IO80211AWDLProtocol:IO80211VirtualInterface{\n'+''.join(f'virtual IOReturn {name}({typ}*)=0;\n' for name,typ in methods)+'};\n'
control=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlControl.hpp').read_text())
header=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlInterface.hpp').read_text())
source=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlInterface.cpp').read_text())
test=(ROOT/'tests/host/rtw_awdl_interface_scenarios.hpp').read_text()
for name,typ in methods:
    test+=f'''    assert(i->{name}(reinterpret_cast<{typ}*>(&cookie))==42);
    assert(control.last==AirportRTWAwdl::Request::{name[3:]}&&control.lastSet=={str(name.startswith('set')).lower()}&&control.lastPayload==&cookie);
'''
test+='''
    assert(control.requests==63);
    assert(i->getSSID(nullptr)==kIOReturnBadArgument&&control.requests==63);
    control.online=false;assert(i->enable(0)==kIOReturnNotReady);control.online=true;
    control.enableResult=kIOReturnError;assert(i->enable(0)==kIOReturnError&&i->link!=2);
    control.enableResult=0;assert(i->enable(0)==0&&i->link==2);
    uint8_t frame[54]{};auto*dp=AirportRTWAwdlDatapath::last;
    assert(dp->sender(dp->owner,frame,54)&&control.sends==1&&i->receiveEthernet(frame,54));
    uint8_t metadata[72]{};assert(i->receiveAction(frame,54,metadata,72));
    assert(AirportRTWAwdlActionInput::inputs==1);
    assert(i->queueAction(frame,54,metadata,72));
    assert(AirportRTWAwdlActionInput::inputs==1);dp->pumpAction();
    assert(AirportRTWAwdlActionInput::inputs==2);
    frame[10]=2;frame[15]=1;apple80211_channel actionChannel{1,44,0x12};
    assert(i->queueRadioAction(frame,54,actionChannel,-41));
    int32_t actionRssi=0;memcpy(&actionRssi,dp->actionMetadata.data()+44,4);
    assert(actionRssi==-41 && dp->actionMetadata[16]==44);
    dp->pumpAction();assert(AirportRTWAwdlActionInput::inputs==3);
    assert(!i->queueRadioAction(frame,54,actionChannel,0));
    ether_addr address;memcpy(address.octet,mac,6);address.octet[5]=6;
    control.addressResult=kIOReturnError;assert(i->setMacAddress(address)==kIOReturnError);
    ether_addr current;assert(i->getHardwareAddress(&current)==0&&!memcmp(current.octet,mac,6));
    control.addressResult=0;assert(i->setMacAddress(address)==0&&addressUpdates==1);
    assert(i->getHardwareAddress(&current)==0&&!memcmp(current.octet,address.octet,6));
    assert(i->disable(0)==0&&i->link==1&&!i->receiveEthernet(frame,54));
    assert(!dp->sender(dp->owner,frame,54)&&control.sends==1);
    assert(!i->receiveAction(frame,54,metadata,72));
    assert(!i->queueAction(frame,54,metadata,72));
    i->stop(c);i->stop(c);assert(control.shutdowns==1&&!c->current&&!i->isChipInterfaceReady());
    assert(i->enable(0)==kIOReturnNotReady&&i->getSSID(reinterpret_cast<apple80211_ssid_data*>(&cookie))==kIOReturnNotReady);
    assert(i->setMacAddress(address)==0); // unchanged address is a no-op
    address.octet[5]=7;assert(i->setMacAddress(address)==kIOReturnNotReady);
    i->terminate(0);i->release();assert(objects==1&&c->refs==1);c->release();assert(objects==0);
    puts("PASS: native interface capability gate, rollback, all 63 requests, enable/disable and teardown");
}
'''
with tempfile.TemporaryDirectory(prefix='awdl-interface-') as temp:
    path=Path(temp)/'host.cpp';binary=str(Path(temp)/'test')
    path.write_text('#include <AWDL/RTWAwdlData.hpp>\n#include <AWDL/RTWAwdlNativeRxMetadata.hpp>\n'+
        (ROOT/'tests/host/rtw_awdl_interface_shim.hpp').read_text()+base+control+header+source+test)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-Wno-unused-parameter','-Wno-unused-function','-DAIRPORT_WCL',
        '-D__MAC_26_0=260000','-D__IO80211_TARGET=260000','-fsanitize=address,undefined',
        '-I'+str(ROOT/'include'),str(path),'-o',binary],check=True)
    subprocess.run([binary],check=True,timeout=10)
