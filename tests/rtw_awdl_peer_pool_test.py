#!/usr/bin/env python3
"""Execute production RTW89 native peer pool, rollback and checked quiesce."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
s=(ROOT/'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text()
pool=s[s.index('struct Rtw89AwdlPeerPool {'):s.index('namespace {')]
code=s[s.index('uint32_t rtw89LinuxAwdlPeerCapacity('):s.index('bool rtw89LinuxAwdlAddInterface(')]
shim=r'''
#include <HAL/RTWAwdlInterfaceState.hpp>
#include <HAL/RTWAwdlPeer.hpp>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <map>
#include <set>
#include <vector>
#include <array>
enum ieee80211_sta_state{IEEE80211_STA_NOTEXIST,IEEE80211_STA_NONE,IEEE80211_STA_AUTH,IEEE80211_STA_ASSOC,IEEE80211_STA_AUTHORIZED};
enum{NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,IEEE80211_STA_RX_BW_20};
struct ieee80211_sta;
struct Link{ieee80211_sta*sta;uint8_t addr[6];unsigned supp_rates[2],rx_nss,bandwidth;};
struct ieee80211_sta{uint8_t addr[6];Link*link[16];Link deflink;bool wme,retained;};
struct ieee80211_vif{void*txq;uint8_t addr[6];};
struct ieee80211_hw;
struct Ops{int(*sta_state)(ieee80211_hw*,ieee80211_vif*,ieee80211_sta*,ieee80211_sta_state,ieee80211_sta_state);};
struct ieee80211_hw{Ops*ops;size_t sta_data_size;};
struct Rtw89DeferredRelease{Rtw89DeferredRelease*next;void(*release)(Rtw89DeferredRelease*);};
static std::map<void*,size_t> allocations;
static std::set<ieee80211_sta*> registry;
static bool allocationFails,registerFails,retainFailedAdd,restoreFails;
static unsigned depth,closed,removed,flushed,upcalls,downcalls,failUp,failDown,restores,capacity=16;
static int drainError;
static unsigned drains;
static int rtw89_macos_awdl_tx_drain(ieee80211_hw*){assert(depth);++drains;return drainError;}
static unsigned rtw89_macos_awdl_peer_capacity(ieee80211_hw*){assert(depth);return capacity;}
static void*IOMallocZero(size_t n){if(allocationFails){allocationFails=false;return nullptr;}void*p=calloc(1,n);assert(p);allocations[p]=n;return p;}
static void IOFree(void*p,size_t n){assert(p&&allocations.at(p)==n);allocations.erase(p);free(p);}
static void rtw88_remove_sta(ieee80211_sta*s){assert(depth);registry.erase(s);}
static bool rtw88_add_sta(ieee80211_vif*,ieee80211_sta*s){assert(depth);if(registerFails)return false;assert(!registry.count(s));registry.insert(s);return true;}
static void rtw89_macos_flush_rx_ba(ieee80211_sta*s){assert(depth&&allocations.count(s)&&!registry.count(s));++flushed;}
static bool rtw89_macos_awdl_peer_retained(ieee80211_vif*,ieee80211_sta*s){assert(depth);return s->retained;}
static int transition(ieee80211_hw*,ieee80211_vif*,ieee80211_sta*s,ieee80211_sta_state old,ieee80211_sta_state next){
 assert(depth&&allocations.count(s));
 if(next>old){
  ++upcalls;assert(s->link[0]==&s->deflink&&s->deflink.sta==s);
  assert(s->wme&&s->deflink.supp_rates[0]==0xff0&&s->deflink.supp_rates[1]==0xff);
  assert(s->deflink.rx_nss==1&&s->deflink.bandwidth==IEEE80211_STA_RX_BW_20);
  if(old>=IEEE80211_STA_NONE)assert(registry.count(s));
  if(unsigned(next)==failUp){if(old==IEEE80211_STA_NOTEXIST)s->retained=retainFailedAdd;return -EIO;}
  if(old==IEEE80211_STA_NOTEXIST)s->retained=true;
 }else{
  ++downcalls;assert(!registry.count(s));if(unsigned(old)==failDown)return -EIO;
  if(next==IEEE80211_STA_NOTEXIST)s->retained=false;
 }
 return 0;
}
struct WiphyGuard{explicit WiphyGuard(ieee80211_hw*){assert(!depth++);}~WiphyGuard(){assert(depth--==1);}};
struct Gate{bool paused=false;bool isPaused()const{return paused;}};
namespace RTWAwdl{static void closeReceiver(int&){assert(!depth);++closed;}
 static void removeLinuxInterface(ieee80211_hw*,InterfaceState&state){assert(depth);++removed;state={};}}
'''
context=r'''
struct Rtw89LinuxContext{
 void*hardware;void*vif;RTWAwdl::InterfaceState awdlInterface;
 Rtw89AwdlPeerPool*awdlPeers;bool awdlRecovery,started,scanning;int*awdlReceive;Gate awdlTxGate;
};
static int rtw89LinuxAwdlRestore(Rtw89LinuxContext*c){assert(!depth);++restores;if(restoreFails)return -EIO;c->awdlTxGate.paused=false;return 0;}
struct Fixture{
 Ops ops{transition};ieee80211_hw hw{&ops,64};ieee80211_vif primary{},secondary{};
 int receiver=0;Rtw89LinuxContext c{&hw,&primary,{&secondary,0,0,true,true},nullptr,false,true,false,&receiver,{}};
 Fixture(){assert(!depth&&allocations.empty()&&registry.empty());
  closed=removed=flushed=upcalls=downcalls=failUp=failDown=restores=0;capacity=16;
  allocationFails=registerFails=retainFailedAdd=restoreFails=false;
  primary.addr[0]=secondary.addr[0]=2;primary.addr[5]=1;secondary.addr[5]=2;
  c.awdlPeers=static_cast<Rtw89AwdlPeerPool*>(IOMallocZero(sizeof(Rtw89AwdlPeerPool)));
  c.awdlPeers->deferred.release=releaseAwdlPeerPool;
 }
 ~Fixture();
};
'''
cases=r'''
Fixture::~Fixture(){
 failDown=failUp=0;restoreFails=false;c.started=true;
 assert(rtw89LinuxAwdlQuiesce(&c));
 releaseAwdlPeerPool(&c.awdlPeers->deferred);assert(allocations.empty()&&registry.empty());
}
int main(){
 using Result=RTWAwdl::PeerResult;const uint8_t remote[6]={2,1,2,3,4,5};
 {Fixture f;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::Success);
  auto&entry=f.c.awdlPeers->entries[0];assert(entry.state==4&&entry.registered&&!entry.retiring);
  assert(upcalls==4&&registry.size()==1);
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::Success&&upcalls==4);
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,false)==Result::Success);
  assert(!entry.station&&downcalls==4&&flushed==1&&registry.empty());
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,false)==Result::Success&&downcalls==4);}
 for(unsigned stage=1;stage<=4;++stage){Fixture f;failUp=stage;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::HardwareError);
  assert(!f.c.awdlPeers->entries[0].station&&registry.empty()&&!f.c.awdlRecovery);
  assert(downcalls==stage-1);}
 {Fixture f;failUp=1;retainFailedAdd=true;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::HardwareError&&downcalls==1);
  assert(!f.c.awdlPeers->entries[0].station);}
 {Fixture f;failUp=1;retainFailedAdd=true;failDown=1;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::RecoveryRequired);
  auto&entry=f.c.awdlPeers->entries[0];assert(entry.station&&entry.state==1&&entry.retiring);
  assert(f.c.awdlRecovery&&registry.empty());
  unsigned attempts=upcalls;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::RecoveryRequired&&upcalls==attempts);
  assert(!rtw89LinuxAwdlQuiesce(&f.c)&&!removed&&f.c.awdlInterface.vif);
  failDown=0;assert(rtw89LinuxAwdlQuiesce(&f.c)&&removed==1&&!f.c.awdlRecovery);
  assert(!entry.station&&!f.c.awdlInterface.vif);}
 for(unsigned stage=1;stage<=4;++stage){Fixture f;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::Success);failDown=stage;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,false)==Result::RecoveryRequired);
  auto&entry=f.c.awdlPeers->entries[0];assert(entry.station&&entry.state==stage&&!entry.registered);
  unsigned calls=downcalls;failDown=0;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,false)==Result::Success&&downcalls==calls+stage);}
 {Fixture f;registerFails=true;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::NoResources&&downcalls==1);
  assert(!f.c.awdlPeers->entries[0].station);}
 {Fixture f;allocationFails=true;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::NoMemory);
  f.hw.sta_data_size=SIZE_MAX;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::NoMemory);}
 {Fixture f;uint8_t addr[6]={2,3,4,5,6,0};
  for(unsigned i=0;i<16;++i){addr[5]=uint8_t(i+1);assert(rtw89LinuxAwdlSetPeer(&f.c,addr,true)==Result::Success);}
  addr[5]=17;assert(rtw89LinuxAwdlSetPeer(&f.c,addr,true)==Result::NoResources);
  assert(rtw89LinuxAwdlQuiesce(&f.c)&&registry.empty()&&removed==1);}
 {Fixture f;assert(rtw89LinuxAwdlSetPeer(&f.c,f.primary.addr,true)==Result::Invalid);
  assert(rtw89LinuxAwdlSetPeer(&f.c,f.secondary.addr,true)==Result::Invalid);
  uint8_t bad[6]{};assert(rtw89LinuxAwdlSetPeer(&f.c,bad,true)==Result::Invalid);
  bad[0]=3;assert(rtw89LinuxAwdlSetPeer(&f.c,bad,true)==Result::Invalid);
  f.c.scanning=true;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::NotReady);
  f.c.scanning=false;f.c.awdlRecovery=true;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::RecoveryRequired);}
 {Fixture f;f.c.awdlTxGate.paused=true;restoreFails=true;
  assert(!rtw89LinuxAwdlQuiesce(&f.c)&&!removed&&f.c.awdlRecovery&&restores==1);
  restoreFails=false;assert(rtw89LinuxAwdlQuiesce(&f.c)&&removed==1&&restores==2);}
 {Fixture f;f.c.started=false;
  assert(!rtw89LinuxAwdlQuiesce(&f.c)&&!removed&&f.c.awdlRecovery);}
 {Fixture f;f.c.hardware=nullptr;
  assert(!rtw89LinuxAwdlQuiesce(&f.c)&&!removed&&f.c.awdlRecovery);
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::NotReady);
  f.c.hardware=&f.hw;}
 {Fixture f;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::Success);
  f.c.awdlInterface.vif=nullptr;
  assert(!rtw89LinuxAwdlQuiesce(&f.c)&&!removed&&f.c.awdlRecovery);
  assert(f.c.awdlPeers->entries[0].station);
  f.c.awdlInterface.vif=&f.secondary;}
 {Fixture f;capacity=1;assert(rtw89LinuxAwdlPeerCapacity(&f.c)==1);
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::Success);
  uint8_t another[6]={2,1,2,3,4,6};assert(rtw89LinuxAwdlSetPeer(&f.c,another,true)==Result::NoResources);
  f.c.awdlRecovery=true;assert(rtw89LinuxAwdlPeerCapacity(&f.c)==0);}
 assert(rtw89LinuxAwdlPeerCapacity(nullptr)==0);
 assert(rtw89LinuxAwdlSetPeer(nullptr,remote,true)==Result::Invalid);
 {Fixture f;assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==Result::Success);
  f.c.awdlTxGate.paused=true;drainError=-EIO;
  auto *station=f.c.awdlPeers->entries[0].station;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,false)==Result::RecoveryRequired);
  assert(f.c.awdlPeers->entries[0].station==station&&registry.count(static_cast<ieee80211_sta*>(station)));
  assert(!downcalls&&!flushed&&f.c.awdlPeers->entries[0].retiring);
  drainError=0;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,false)==Result::Success);
  assert(!f.c.awdlPeers->entries[0].station&&downcalls==4&&drains>=2);}
 puts("PASS: production RTW89 peer allocation, registration, rollback, bounded capacity and checked quiesce");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-peer-pool-')as tmp:
 cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(shim+pool+context+code+cases)
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                 '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(cpp),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True,timeout=20)
