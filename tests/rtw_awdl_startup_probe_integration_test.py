#!/usr/bin/env python3
"""Run the production controller hooks and HAL adapter with deterministic IOKit adapters."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
header=(ROOT/'AirportRTW/WCL/AirportRTWAwdlProbe.hpp').read_text()
adapter=header[header.index('class AirportRTWAwdlProbe final'):header.rindex('#endif\n#endif')]
source=(ROOT/'AirportRTW/WCL/AirportRTWV2.cpp').read_text()
hooks=source[source.index('void AirportRTW::startAwdlProbe()'):source.rindex('#endif')]
shim=r'''
#include <AWDL/RTWAwdlStartupProbe.hpp>
#include <HAL/RTWAwdlReceive.hpp>
#include <HAL/RTWAwdlRadio.hpp>
#include <cassert>
#include <cstring>
#include <string>
#include <unordered_map>
#include <cstdio>
#include <mutex>
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=-1,IEEE80211_S_RUN=4;
static unsigned depth,liveTimers;
class OSObject {public:virtual ~OSObject()=default;unsigned refs=1;void retain(){++refs;}void release(){assert(refs);--refs;}};
static OSObject yes,no;
#define kOSBooleanTrue (&yes)
#define kOSBooleanFalse (&no)
#define OSDynamicCast(type,obj) dynamic_cast<type*>(obj)
#define OSSafeReleaseNULL(p) do {if(p){(p)->release();p=nullptr;}}while(0)
struct IOService:OSObject {
 std::unordered_map<std::string,uint64_t> numbers;
 std::unordered_map<std::string,OSObject*>objects;
 OSObject*getProperty(const char*k){return objects[k];}
 void setProperty(const char*k,uint64_t n,unsigned){assert(depth);numbers[k]=n;}
 void setProperty(const char*k,OSObject*o){objects[k]=o;}
};
constexpr unsigned IEEE80211_F_RSNON=1;
struct ieee80211_node {bool ni_port_valid=true;};
struct ieee80211com {unsigned ic_flags=0;ieee80211_node*ic_bss=nullptr;int ic_state=IEEE80211_S_RUN;uint8_t ic_myaddr[6]={0,1,2,3,4,5};};
struct RTWCore:OSObject {
 ieee80211com ic;
 bool openOK=true,bindOK=true,closeOK=true,ready=true,recovery=false;
 unsigned cap=14,opens=0,unbinds=0,closes=0;
 OSObject *owner=nullptr;RTWAwdl::ReceiveHandler handler=nullptr;
 ieee80211com*get80211Controller(){return &ic;}
 uint32_t awdlPeerCapacity(){assert(depth);return cap;}
 bool addAwdlInterface(const uint8_t*m){assert(depth&&m[0]==2&&m[5]==(5^0x40));++opens;return openOK;}
 bool setAwdlReceiver(OSObject*o,RTWAwdl::ReceiveHandler h){
  assert(depth);if(!o){++unbinds;if(owner)owner->release();owner=nullptr;handler=nullptr;return true;}
  assert(!owner&&h);if(!bindOK)return false;owner=o;handler=h;owner->retain();return true;
 }
 RTWAwdl::RadioState awdlRadioState(){assert(depth);return {2437,ready,recovery,
   unsigned(!ready?RTW_AWDL_RADIO_PRIMARY_NOT_AUTHORIZED:recovery?RTW_AWDL_RADIO_TX_PAUSED:0)};}
 bool quiesceAwdlInterface(){assert(depth&&!owner&&!handler);++closes;ready=true;recovery=false;return closeOK;}
};
struct IOTimerEventSource {
 using Action=void(*)(OSObject*,IOTimerEventSource*);
 OSObject *owner;Action action;bool enabled=false,armed=false;
 static bool fail;
 static IOTimerEventSource *timerEventSource(OSObject*o,Action a){
  if(fail)return nullptr;++liveTimers;return new IOTimerEventSource{o,a};
 }
 void enable(){enabled=true;}void disable(){enabled=false;}void cancelTimeout(){armed=false;}
 void setTimeoutMS(unsigned n){assert(depth&&(n==1000||n==5000));armed=true;}
 void release(){--liveTimers;delete this;}
 void fire(){assert(armed&&enabled);armed=false;action(owner,this);}
};
bool IOTimerEventSource::fail=false;
struct FakeLoop {
 bool failAdd=false;std::recursive_mutex mutex;
 using Action=IOReturn(*)(OSObject*,void*,void*,void*,void*);
 IOReturn runAction(Action a,OSObject*o,void*b,void*c,void*d,void*e){
  std::lock_guard<std::recursive_mutex>lock(mutex);++depth;int r=a(o,b,c,d,e);--depth;return r;
 }
 IOReturn addEventSource(IOTimerEventSource*){return failAdd?-1:0;}
 void removeEventSource(IOTimerEventSource*t){assert(!t->armed);}
};
static FakeLoop loop,*_fWorkloop=&loop;
'''
controller=r'''
struct AirportRTW:IOService {
 OSObject*fHalService;
 AirportRTWAwdlProbe *awdlProbe_=nullptr;
 IOTimerEventSource *awdlProbeTimer_=nullptr;
 void startAwdlProbe();void stopAwdlProbe(bool dispose=false);
 static void awdlProbeTimer(OSObject*,IOTimerEventSource*);
 static IOReturn awdlProbeAction(OSObject*,void*,void*,void*,void*);
 static void awdlProbeReceive(OSObject*,const uint8_t*,size_t,const RTWAwdl::ReceiveMetadata&);
};
'''
cases=r'''
int main(){
 {RTWCore core;AirportRTW me;me.fHalService=&core;me.startAwdlProbe();assert(!me.awdlProbe_&&!core.opens);}
 for(unsigned mode=0;mode<7;++mode){
  RTWCore core;AirportRTW me;me.fHalService=&core;
  me.setProperty("RTWAwdlProbeEnabled",kOSBooleanTrue);
  if(mode==1)core.openOK=false;if(mode==2)core.bindOK=false;
  if(mode==3)core.ready=false;if(mode==4)core.closeOK=false;
  if(mode==5)core.cap=0;if(mode==6)core.recovery=true;
  me.startAwdlProbe();assert(me.awdlProbe_&&me.awdlProbeTimer_->armed);
  me.startAwdlProbe();assert(liveTimers==1); // cannot replace an in-flight owner
  for(unsigned n=0;n<12&&me.awdlProbeTimer_->armed;++n){
   me.awdlProbeTimer_->fire();
   if(core.handler){
    assert(!depth);RTWAwdl::ReceiveMetadata metadata{RTWAwdl::FrameKind::Action,-40,2437,0,false};
    core.handler(core.owner,nullptr,0,metadata);
   }
  }
  assert(!core.owner&&!core.handler&&me.refs==1);
  assert(me.numbers["RTWAwdlProbeStage"]==unsigned(mode==0?RTWAwdl::StartupProbe::Stage::Complete:
    mode==1?RTWAwdl::StartupProbe::Stage::OpenFailed:
    mode==2?RTWAwdl::StartupProbe::Stage::BindFailed:
    mode==4?RTWAwdl::StartupProbe::Stage::CleanupFailed:
    mode==5?RTWAwdl::StartupProbe::Stage::Unavailable:RTWAwdl::StartupProbe::Stage::RadioFailed));
  assert(core.opens==unsigned(mode!=5)&&core.closes==unsigned(mode!=5&&mode!=1));
  if(!mode){assert(me.numbers["RTWAwdlProbeActionRx"]==10);assert(me.numbers["RTWAwdlProbePeerCapacity"]==14);}
  if(mode==3){
   assert(me.getProperty("RTWAwdlProbeRadioReady")==kOSBooleanFalse);
   assert(me.numbers["RTWAwdlProbeRadioBlockers"]==RTW_AWDL_RADIO_PRIMARY_NOT_AUTHORIZED);
   assert(me.numbers["RTWAwdlProbeRadioChecks"]==1&&core.ready);
  }
  if(mode==6){
   assert(me.getProperty("RTWAwdlProbeRadioRecoveryRequired")==kOSBooleanTrue);
   assert(me.numbers["RTWAwdlProbeRadioBlockers"]==RTW_AWDL_RADIO_TX_PAUSED&&!core.recovery);
  }
  if(!mode)assert(me.numbers["RTWAwdlProbeRadioChecks"]==11&&me.numbers["RTWAwdlProbeRadioBlockers"]==0);
  me.stopAwdlProbe(true);assert(!me.awdlProbe_&&!me.awdlProbeTimer_&&!liveTimers);
 }
 {RTWCore core;AirportRTW me;me.fHalService=&core;me.setProperty("RTWAwdlProbeEnabled",kOSBooleanTrue);
  me.startAwdlProbe();me.awdlProbeTimer_->fire();assert(core.owner==&me);
  me.stopAwdlProbe();assert(!core.owner&&!me.awdlProbeTimer_->armed&&core.closes==1);
  me.stopAwdlProbe(true);assert(core.closes==1&&!liveTimers&&me.refs==1);}
 {RTWCore core;AirportRTW me;OSObject other;me.fHalService=&core;
  core.openOK=false;core.owner=&other;
  me.setProperty("RTWAwdlProbeEnabled",kOSBooleanTrue);me.startAwdlProbe();
  me.awdlProbeTimer_->fire();me.stopAwdlProbe(true);
  assert(core.owner==&other&&!core.unbinds&&!core.closes&&!liveTimers);}
 {RTWCore core;AirportRTW me;me.fHalService=&core;core.ic.ic_state=0;
  me.setProperty("RTWAwdlProbeEnabled",kOSBooleanTrue);me.startAwdlProbe();
  for(unsigned n=0;n<40;++n)me.awdlProbeTimer_->fire();
  assert(!core.opens&&me.awdlProbeTimer_->armed);
  // An off/on before connection may resume waiting, without duplicate timers.
  me.stopAwdlProbe();assert(!me.awdlProbeTimer_->armed);me.startAwdlProbe();
  assert(me.awdlProbeTimer_->armed&&liveTimers==1);
  core.ic.ic_state=IEEE80211_S_RUN;core.ic.ic_flags=IEEE80211_F_RSNON;
  ieee80211_node node;node.ni_port_valid=false;core.ic.ic_bss=&node;
  me.awdlProbeTimer_->fire();assert(!core.opens&&me.awdlProbeTimer_->armed);
  assert(me.getProperty("RTWAwdlProbePrimaryReady")==kOSBooleanFalse);
  node.ni_port_valid=true;me.awdlProbeTimer_->fire();assert(core.opens==1);
  assert(me.getProperty("RTWAwdlProbePrimaryReady")==kOSBooleanTrue);
  for(unsigned n=0;n<10;++n)me.awdlProbeTimer_->fire();
  assert(!core.owner&&core.closes==1&&!me.awdlProbeTimer_->armed);
  me.stopAwdlProbe();me.startAwdlProbe();assert(!me.awdlProbeTimer_->armed&&core.opens==1);
  me.stopAwdlProbe(true);assert(!liveTimers);}
 for(bool failTimer:{false,true}){
  RTWCore core;AirportRTW me;me.fHalService=&core;me.setProperty("RTWAwdlProbeEnabled",kOSBooleanTrue);
  loop.failAdd=!failTimer;IOTimerEventSource::fail=failTimer;me.startAwdlProbe();
  assert(!me.awdlProbe_&&!me.awdlProbeTimer_&&!liveTimers&&!core.opens);
  assert(me.getProperty("RTWAwdlProbeSetupFailed")==kOSBooleanTrue);
  loop.failAdd=IOTimerEventSource::fail=false;
 }
 puts("PASS: production AWDL probe controller/HAL binding is opt-in, bounded, gated and drained before disposal");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-probe-') as tmp:
    path=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    path.write_text(shim+adapter+controller+hooks+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-fsanitize=address,undefined',
                    '-I'+str(ROOT/'include'),str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
