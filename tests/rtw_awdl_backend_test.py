#!/usr/bin/env python3
"""Exercise production native backend controls with a bounded hardware adapter."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
# Reuse the same native object/queue adapter as the peer composition suite.
ns={'__file__':str(ROOT/'tests/rtw_awdl_native_peers_test.py')}
script=(ROOT/'tests/rtw_awdl_native_peers_test.py').read_text()
exec(compile(script.split("scenario=r'''",1)[0],str(ROOT/'tests/rtw_awdl_native_peers_test.py'),'exec'),ns)
strip=ns['strip']
structs=ns['structs'][:]
for suffix in ['awdl_device_capabilities','awdl_election_params','awdl_master_channel',
               'awdl_secondary_master_channel','awdl_min_rate','awdl_bssid','awdl_oob_request']:
    match=re.search(r'\bstruct apple80211_'+suffix+r'\s*\{.*?\}\s*(?:__attribute__\(\(packed\)\))?;',ns['ioctl'],re.S)
    assert match,suffix
    structs.append(match[0])
source='#define APPLE80211_ADDR_LEN 6\n'+ns['shim']+(ROOT/'tests/host/rtw_awdl_interface_shim.hpp').read_text()+ns['extra']+'\n'.join(structs)+ns['base']
source+='''
#include <HAL/RTWAwdlRadio.hpp>
#include <HAL/RTWAwdlHardwareSupport.hpp>
#include <AWDL/RTWAwdlNativeAction.hpp>
constexpr int kIOReturnNotFound=8;
constexpr unsigned APPLE80211_C_FLAG_40MHZ=8,APPLE80211_C_FLAG_80MHZ=16,APPLE80211_C_FLAG_160MHZ=32,APPLE80211_C_FLAG_ACTIVE=64;
struct RTWCore:RTWAwdl::Radio,RTWAwdl::PeerHardware {
 unsigned support=7,adds=0,closes=0;bool receiver=false;
 void retain(){}void release(){}
 uint32_t awdlHardwareSupport()const{return support;}
 uint32_t awdlPeerCapacity()const override{return 16;}
 RTWAwdl::PeerResult setAwdlPeer(const uint8_t*,bool)override{return RTWAwdl::PeerResult::Success;}
 bool addAwdlInterface(const uint8_t*){++adds;return true;}
 bool quiesceAwdlInterface(){++closes;return true;}
 bool setAwdlReceiver(OSObject*p,RTWAwdl::ReceiveHandler){receiver=p;return true;}
 bool transmitAwdlAction(const uint8_t*,size_t,uint16_t){return true;}
 bool transmitAwdlData(const uint8_t*,size_t,uint16_t,uint64_t){return true;}
 RTWAwdl::RadioState awdlRadioState()const override{return {2437,true,false,0};}
 bool awdlChannelAllowed(uint16_t f)const override{return f==2437 || f==5220 || f==5745;}
};
'''
for filename in ['Control.hpp','PeerControl.hpp','Interface.hpp','Peers.hpp','WindowDriver.hpp','Runtime.hpp','Backend.hpp']:
    source+=strip((ROOT/'AirportRTW/WCL'/('AirportRTWAwdl'+filename)).read_text())
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlInterface.cpp').read_text())
source+=(ROOT/'tests/host/rtw_awdl_interface_scenarios.hpp').read_text().split('struct Control:',1)[0]
source+=r'''
int main(){
 using namespace AirportRTWAwdl;
 const uint8_t mac[6]={2,1,2,3,4,5};RTWCore hal;
 auto *backend=new NativeBackend(hal);Runtime runtime(*backend);auto *controller=new IO80211Controller;
 // Missing producer quiescence must prevent native publication, before any VIF.
 assert(!(backend->capabilities()&Control::QuiescentShutdown));
 assert(!AirportRTWAwdlInterface::withController(controller,&runtime,mac) && !hal.adds);
 // The adapter supplies the barrier only for these control/lifecycle tests.
 hal.support|=RTWAwdl::QuiescentRemoval;
 auto *interface=AirportRTWAwdlInterface::withController(controller,&runtime,mac);assert(interface && hal.adds==1);
 apple80211_awdl_device_capabilities limits{};
 assert(!interface->getAWDL_DEVICE_CAPABILITIES(&limits) && limits.max_peers==16 && limits.max_channel_sequence==16);
 apple80211_awdl_election_params election{};
 assert(!interface->getAWDL_ELECTION_PARAMS(&election));assert(!memcmp(election.master,mac,6));
 election.self_metric=123;election.election_id=7;
 assert(!interface->setAWDL_ELECTION_PARAMS(&election));
 election={};assert(!interface->getAWDL_ELECTION_PARAMS(&election) && election.self_metric==123 && election.election_id==7);
 apple80211_awdl_master_channel channel{1,14};
 assert(interface->setAWDL_MASTER_CHANNEL(&channel)==kIOReturnBadArgument);
 channel.master_channel=44;assert(!interface->setAWDL_MASTER_CHANNEL(&channel));
 channel={};assert(!interface->getAWDL_MASTER_CHANNEL(&channel) && channel.master_channel==44);
 apple80211_awdl_min_rate rate{1,24};assert(interface->setAWDL_MIN_RATE(&rate)==kIOReturnUnsupported);
 rate.min_rate=12;assert(!interface->setAWDL_MIN_RATE(&rate));
 uint8_t selection[44]{};assert(interface->setAWDL_AWDL_ADVERTISERS(reinterpret_cast<awdl_peer_advert_add*>(selection))==kIOReturnBadArgument);
 // Broadcast MI payload is borrowed for this call only; malformed replacement
 // must not be accepted. Disabling needs neither payload nor an enabled radio.
 apple80211_awdl_oob_request mi{};mi.version=1;auto *raw=reinterpret_cast<uint8_t*>(&mi);memset(raw+4,255,6);
 mi.unk4=0xffffffff;uint8_t tlv[]={25,1,0,42};mi.data=tlv;mi.data_len=sizeof(tlv);
 assert(!interface->setAWDL_OOB_AUTO_REQUEST(&mi));
 tlv[0]=4;assert(interface->setAWDL_OOB_AUTO_REQUEST(&mi)==kIOReturnBadArgument);
 mi.unk4=0;mi.data=nullptr;assert(!interface->setAWDL_OOB_AUTO_REQUEST(&mi));
 interface->terminate(0);interface->release();assert(hal.closes==1 && !hal.receiver);
 delete backend;controller->release();assert(objects==0);
 puts("PASS: native backend capability gate, hardware ownership, limits, election, channel policy and bounded MI controls");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-backend-') as tmp:
    cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(source)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function',
        '-DAIRPORT_WCL','-D__MAC_26_0=260000','-D__IO80211_TARGET=260000','-fsanitize=address,undefined',
        '-I'+str(ROOT/'include'),str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
