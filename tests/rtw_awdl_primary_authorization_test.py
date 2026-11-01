#!/usr/bin/env python3
"""Execute real primary station transitions and AWDL entry points with driver faults."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
def extract(path,start):
    s=(ROOT/path).read_text();a=s.index(start);b=s.index('{',a)+1;depth=1
    while depth:
        depth+=(s[b]=='{')-(s[b]=='}');b+=1
    return s[a:b]+'\n'
bridge=extract('rtw/hal_rtw89/Rtw89LinuxBridge.cpp','bool rtw89LinuxSetStationAuthorized(')
core=''.join(extract('rtw/hal_rtw89/RTWCore89.cpp',s) for s in (
    'RTWAwdl::RadioState RTWCore89::awdlRadioState() const',
    'RTWAwdl::RadioReservation RTWCore89::reserveAwdlRadio(',
    'bool RTWCore89::addAwdlInterface('))
shim=r'''
#include <HAL/RTWAwdlRadio.hpp>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <initializer_list>
enum ieee80211_sta_state {IEEE80211_STA_NOTEXIST,IEEE80211_STA_NONE,IEEE80211_STA_AUTH,
 IEEE80211_STA_ASSOC,IEEE80211_STA_AUTHORIZED};
constexpr unsigned IEEE80211_S_RUN=4,IEEE80211_F_RSNON=1;
struct ieee80211_sta {uint8_t addr[6]={2,1,2,3,4,5};};
struct ieee80211_vif {struct{bool assoc=true;}cfg;};
struct ieee80211_hw;
struct Ops {int(*sta_state)(ieee80211_hw*,ieee80211_vif*,ieee80211_sta*,ieee80211_sta_state,ieee80211_sta_state);};
struct ieee80211_hw {Ops*ops;};
struct Rtw89LinuxContext {void*hardware,*vif,*station;bool started=true;unsigned stationState=IEEE80211_STA_ASSOC;};
static unsigned depth,calls,adds,reserves;
static int error;
static unsigned from,to;
struct WiphyGuard {explicit WiphyGuard(ieee80211_hw*){assert(!depth++);}~WiphyGuard(){assert(depth--==1);}};
static int transition(ieee80211_hw*,ieee80211_vif*,ieee80211_sta*,ieee80211_sta_state a,ieee80211_sta_state b){
 assert(depth);++calls;from=a;to=b;return error;
}
struct ieee80211_node {bool ni_port_valid=true;uint8_t ni_bssid[6]={2,1,2,3,4,5};};
struct ieee80211com {unsigned ic_state=IEEE80211_S_RUN,ic_flags=IEEE80211_F_RSNON;ieee80211_node*ic_bss;};
struct RTWCore89 {
 struct {ieee80211com sc_ic;}sc;
 Rtw89LinuxContext linuxContext;
 RTWAwdl::RadioState awdlRadioState()const;
 RTWAwdl::RadioReservation reserveAwdlRadio(uint16_t,uint32_t);
 bool addAwdlInterface(const uint8_t[6]);
};
static RTWAwdl::RadioState rtw89LinuxAwdlRadioState(const Rtw89LinuxContext*c){
 bool ready=c->stationState==IEEE80211_STA_AUTHORIZED;
 return {2437,ready,false,ready?0U:unsigned(RTW_AWDL_RADIO_PRIMARY_NOT_AUTHORIZED)};
}
static bool rtw89LinuxAwdlAddInterface(Rtw89LinuxContext*,const uint8_t*){++adds;return true;}
static RTWAwdl::RadioReservation rtw89LinuxAwdlReserveRadio(Rtw89LinuxContext*c,uint16_t f,uint32_t ms){
 assert(c->stationState==IEEE80211_STA_AUTHORIZED&&f==2437&&ms==20);++reserves;
 return RTWAwdl::RadioReservation::Granted;
}
struct Fixture {
 Ops ops{transition};ieee80211_hw hw{&ops};ieee80211_vif vif;ieee80211_sta sta;ieee80211_node node;
 RTWCore89 core{{{IEEE80211_S_RUN,IEEE80211_F_RSNON,&node}},{&hw,&vif,&sta,true,IEEE80211_STA_ASSOC}};
 Fixture(){calls=adds=reserves=0;error=0;}
};
'''
cases=r'''
int main(){
 uint8_t mac[6]={2,7,8,9,10,11};
 {Fixture f;assert(f.core.addAwdlInterface(mac));assert(calls==1&&adds==1);
  assert(from==IEEE80211_STA_ASSOC&&to==IEEE80211_STA_AUTHORIZED);
  assert(f.core.linuxContext.stationState==IEEE80211_STA_AUTHORIZED&&f.core.awdlRadioState().ready);
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Granted);
  assert(calls==1&&reserves==1); // idempotent, no repeated driver transition
  f.node.ni_port_valid=false;
  auto state=f.core.awdlRadioState();assert(!state.ready&&!state.frequency);
  assert(state.blockers&RTW_AWDL_RADIO_PRIMARY_NOT_AUTHORIZED);
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Rejected);
  assert(calls==2&&from==IEEE80211_STA_AUTHORIZED&&to==IEEE80211_STA_ASSOC&&reserves==1);
  assert(f.core.linuxContext.stationState==IEEE80211_STA_ASSOC);
  f.node.ni_port_valid=true;
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Granted&&calls==3);}
 {Fixture f;f.node.ni_port_valid=false;
  assert(f.core.addAwdlInterface(mac));assert(adds==1&&!calls); // prepare does not authorize RSN early
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Rejected&&!reserves&&!calls);}
 {Fixture f;f.core.sc.sc_ic.ic_flags=0;f.node.ni_port_valid=false;
  assert(f.core.addAwdlInterface(mac)&&calls==1); // open-network connection
  assert(f.core.awdlRadioState().ready);}
 {Fixture f;error=-7;assert(!f.core.addAwdlInterface(mac));
  assert(calls==1&&!adds&&f.core.linuxContext.stationState==IEEE80211_STA_ASSOC);
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Rejected&&!reserves);}
 {Fixture f;f.core.linuxContext.stationState=IEEE80211_STA_AUTHORIZED;
  f.node.ni_port_valid=false;error=-8;
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Rejected&&!reserves);
  assert(f.core.linuxContext.stationState==IEEE80211_STA_AUTHORIZED&&!f.core.awdlRadioState().ready);}
 for(unsigned state:{IEEE80211_STA_NOTEXIST,IEEE80211_STA_NONE,IEEE80211_STA_AUTH}){
  Fixture f;f.core.linuxContext.stationState=state;
  assert(!f.core.addAwdlInterface(mac)&&!calls&&!adds);}
 {Fixture f;f.node.ni_bssid[5]^=1;assert(!f.core.addAwdlInterface(mac)&&!calls&&!adds);}
 {Fixture f;f.core.sc.sc_ic.ic_bss=nullptr;
  assert(!f.core.awdlRadioState().ready);
  assert(f.core.reserveAwdlRadio(2437,20)==RTWAwdl::RadioReservation::Rejected&&!calls&&!reserves);}
 for(unsigned missing=0;missing<6;++missing){Fixture f;auto&c=f.core.linuxContext;
  if(missing==0)c.hardware=nullptr;if(missing==1)c.vif=nullptr;if(missing==2)c.station=nullptr;
  if(missing==3)c.started=false;if(missing==4)f.vif.cfg.assoc=false;if(missing==5)f.hw.ops=nullptr;
  assert(!rtw89LinuxSetStationAuthorized(&c,f.node.ni_bssid,true)&&!calls);}
 {Fixture f;f.ops.sta_state=nullptr;
  assert(!rtw89LinuxSetStationAuthorized(&f.core.linuxContext,f.node.ni_bssid,true)&&!calls);}
 assert(!rtw89LinuxSetStationAuthorized(nullptr,mac,true));
 puts("PASS: actual AWDL entry points mirror completed port authorization, bind the peer, and reject revocation/driver faults");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-auth-') as tmp:
    source=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    source.write_text(shim+bridge+core+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-fsanitize=address,undefined','-I'+str(ROOT/'include'),
                    str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
