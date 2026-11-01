#!/usr/bin/env python3
"""Execute actual peer-aware power-down/detach and transport release ordering."""
import ast
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
def extract(s,start):
 a=s.index(start);b=s.index('{',a);depth=1;end=b+1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]+'\n'
# Reuse the allocator's deterministic driver fixture without importing/running it.
module=ast.parse((ROOT/'tests/rtw_awdl_peer_pool_test.py').read_text())
literals={node.targets[0].id:ast.literal_eval(node.value) for node in module.body
 if isinstance(node,ast.Assign)and isinstance(node.targets[0],ast.Name)
 and isinstance(node.value,ast.Constant)and isinstance(node.value.value,str)}
shim=literals['shim']
shim=shim.replace('++removed;state={};','++removed;if(state.vif)IOFree(state.vif,state.allocationSize);state={};')
shim=shim.replace('int(*sta_state)(ieee80211_hw*,ieee80211_vif*,ieee80211_sta*,ieee80211_sta_state,ieee80211_sta_state);',
'''int(*sta_state)(ieee80211_hw*,ieee80211_vif*,ieee80211_sta*,ieee80211_sta_state,ieee80211_sta_state);
void(*stop)(ieee80211_hw*,bool)=nullptr;
void(*remove_interface)(ieee80211_hw*,ieee80211_vif*)=nullptr;
int(*start)(ieee80211_hw*)=nullptr;
int(*add_interface)(ieee80211_hw*,ieee80211_vif*)=nullptr;''')
shim=shim.replace('static void*IOMallocZero', '''static bool workersStopped,pciRemoved;
static std::set<void*> deferredPointers;
static unsigned stopCalls,primaryRemoves,compatStops;
static void*IOMallocZero''')
shim=shim.replace('assert(p&&allocations.at(p)==n);allocations.erase(p);free(p);',
'''assert(p&&allocations.at(p)==n);
if(deferredPointers.count(p)){assert(workersStopped&&pciRemoved);deferredPointers.erase(p);}
allocations.erase(p);free(p);''')
shim+=r'''
namespace RTWAwdl{using ReceiveRegistration=int;static void destroyReceiver(int&){assert(!depth);}}
#define RTW_LOG(...) ((void)0)
#define bzero(p,n) memset((p),0,(n))
static void*rtw88_pci_io_ops,*rtw88_dma_ops;
static void rtw88_compat_exit(){assert(pciRemoved);workersStopped=true;++compatStops;registry.clear();}
struct FakeSource{void release(){}};
struct FakeLoop{void removeEventSource(FakeSource*){}};
struct Rtw89PciTransport{
 static Rtw89PciTransport*active;
 Rtw89DeferredRelease*deferredReleases=nullptr;
 FakeSource*interruptSource=nullptr;FakeLoop*workLoop=nullptr;
 void disableInterrupts(){}
 void*linuxDevice(){return this;}
 void teardown();
'''
transport=(ROOT/'rtw/hal_rtw89/Rtw89PciTransport.cpp').read_text()
header=(ROOT/'rtw/hal_rtw89/Rtw89PciTransport.hpp').read_text()
shim+=extract(header,'    void deferRelease(')+r'''
};
Rtw89PciTransport*Rtw89PciTransport::active;
static void rtw_pci_remove(void*){assert(!depth);pciRemoved=true;}
'''
a=transport.index('void Rtw89PciTransport::teardown()');b=transport.index('    drainPendingFree();',a)
shim+=transport[a:b]+'}\n'
s=(ROOT/'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text()
pool=s[s.index('struct Rtw89AwdlPeerPool {'):s.index('namespace {')]
context=literals['context'].split('struct Fixture{',1)[0]
context=context.replace('int*awdlReceive;Gate awdlTxGate;', '''int*awdlReceive;Gate awdlTxGate;
 void*station=nullptr;size_t stationAllocationSize=0,vifAllocationSize=0;
 unsigned stationState=0;bool interfaceAdded=true,probed=true,awdlDiscoveryApplied=false;
 void*device=nullptr;uint8_t macAddress[6]{};''')
context+=r'''
static Rtw89LinuxContext*activeContext;
static void rtw88_set_tx_resume_cb(void*){}
static void rtw88_set_hw_callbacks(void*,void*){}
static void rtw88_unregister_vif(){assert(!depth);}
static void rtw88_register_vif(ieee80211_vif*){}
static void rtw89LinuxScanEnd(Rtw89LinuxContext*c){c->scanning=false;}
static void rtw89LinuxDisassociate(Rtw89LinuxContext*c){
 if(c->station){IOFree(c->station,c->stationAllocationSize);c->station=nullptr;c->stationAllocationSize=0;}
}
static void stop(ieee80211_hw*,bool){assert(depth);++stopCalls;}
static void removePrimary(ieee80211_hw*,ieee80211_vif*){assert(depth);++primaryRemoves;}
'''
code=s[s.index('uint32_t rtw89LinuxAwdlPeerCapacity('):s.index('bool rtw89LinuxAwdlAddInterface(')]
code+=extract(s,'bool rtw89LinuxPowerUp(')
code+=extract(s,'void rtw89LinuxPowerDown(')
code+=extract(s,'void rtw89LinuxDetach(')
cases=r'''
struct Fixture{
 Ops ops{transition,stop,removePrimary,nullptr,nullptr};ieee80211_hw hw{&ops,64};Rtw89PciTransport transport;
 Rtw89LinuxContext c{&hw,nullptr,{},nullptr,false,true,false,nullptr,{}};
 Fixture(bool pool=true){
  assert(allocations.empty()&&deferredPointers.empty()&&!depth);registry.clear();
  workersStopped=pciRemoved=false;compatStops=stopCalls=primaryRemoves=0;
  failUp=failDown=upcalls=downcalls=restores=0;
  allocationFails=registerFails=retainFailedAdd=restoreFails=false;
  c.vif=IOMallocZero(sizeof(ieee80211_vif));c.vifAllocationSize=sizeof(ieee80211_vif);
  static_cast<ieee80211_vif*>(c.vif)->addr[0]=2;
  c.station=IOMallocZero(sizeof(ieee80211_sta));c.stationAllocationSize=sizeof(ieee80211_sta);
  if(pool){
   c.awdlPeers=static_cast<Rtw89AwdlPeerPool*>(IOMallocZero(sizeof(Rtw89AwdlPeerPool)));
   c.awdlPeers->deferred.release=releaseAwdlPeerPool;
   c.awdlInterface={IOMallocZero(sizeof(ieee80211_vif)),sizeof(ieee80211_vif),0,true,true};
   auto*v=static_cast<ieee80211_vif*>(c.awdlInterface.vif);v->addr[0]=2;v->addr[5]=2;
  }
  Rtw89PciTransport::active=&transport;activeContext=&c;
 }
 ~Fixture(){transport.teardown();assert(allocations.empty()&&registry.empty()&&deferredPointers.empty());}
};
int main(){
 const uint8_t remote[6]={2,1,2,3,4,5};
 {Fixture f;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==RTWAwdl::PeerResult::Success);
  // A failed firmware delete holds peer and BOTH VIF lifetimes through shutdown.
  failDown=IEEE80211_STA_NONE;rtw89LinuxPowerDown(&f.c);
  assert(f.c.awdlRecovery&&!f.c.started&&stopCalls==1&&!primaryRemoves);
  assert(f.c.station&&f.c.vif&&f.c.awdlInterface.vif&&f.c.awdlPeers->entries[0].station);
  assert(!rtw89LinuxPowerUp(&f.c));
  for(auto &entry:allocations)deferredPointers.insert(entry.first);
  allocationFails=true; // teardown must not allocate a release record
  rtw89LinuxDetach(&f.transport,&f.c);
  assert(allocationFails&&pciRemoved&&!workersStopped&&f.transport.deferredReleases);
  assert(!f.c.awdlPeers&&!f.c.vif&&!f.c.station&&!f.c.awdlInterface.vif);
  assert(!allocations.empty()&&!deferredPointers.empty()&&!activeContext);
  allocationFails=false;
  f.transport.teardown();assert(allocations.empty()&&deferredPointers.empty()&&compatStops==1);}
 {Fixture f;
  assert(rtw89LinuxAwdlSetPeer(&f.c,remote,true)==RTWAwdl::PeerResult::Success);
  // Normal peer removal precedes PCI teardown; primary VIF waits for worker exit.
  void*primary=f.c.vif;deferredPointers.insert(primary);
  rtw89LinuxDetach(&f.transport,&f.c);
  assert(pciRemoved&&!workersStopped&&primaryRemoves==1&&stopCalls==1);
  assert(allocations.count(primary)&&!f.c.awdlPeers&&f.transport.deferredReleases);}
 {Fixture f(false);rtw89LinuxDetach(&f.transport,&f.c);
  assert(pciRemoved&&allocations.empty()&&!f.transport.deferredReleases&&primaryRemoves==1);}
 {Fixture f;f.c.awdlTxGate.paused=true;restoreFails=true;
  rtw89LinuxPowerDown(&f.c);assert(f.c.awdlRecovery&&!f.c.started&&stopCalls==1&&!primaryRemoves);
  for(auto &entry:allocations)deferredPointers.insert(entry.first);
  rtw89LinuxDetach(&f.transport,&f.c);assert(pciRemoved&&!workersStopped&&!allocations.empty());}
 puts("PASS: actual peer shutdown retains failed roles/VIFs until PCI removal and transport worker exit");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-peer-shutdown-')as tmp:
 cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(shim+pool+context+code+cases)
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                 '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(cpp),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True,timeout=20)
