#!/usr/bin/env python3
"""Actual native interface -> runtime -> peer session -> HAL contract composition."""
import ast
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
strip=lambda s:re.sub(r'^#include[^\n]*\n','',s,flags=re.M)
ioctl=(ROOT/'include/Airport/apple80211_ioctl.h').read_text()
module=ast.parse((ROOT/'tests/rtw_awdl_runtime_test.py').read_text())
names=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign)
 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='names')
structs=[]
for suffix in names:
 match=re.search(r'\bstruct apple80211_'+suffix+r'\s*\{.*?\}\s*(?:__attribute__\(\(packed\)\))?;',ioctl,re.S)
 assert match,suffix
 structs.append(match[0])
abi=(ROOT/'include/Airport/macOS26/IO80211AWDLProtocol.h').read_text().split('class IO80211AWDLProtocol :',1)[1]
methods=re.findall(r'virtual IOReturn\s+(\w+)\(\s*(\w+)\s*\*\)\s*= 0;',abi,re.S)
base='\n'+''.join(f'struct {t};\n'for t in sorted({t for _,t in methods}))
base+='struct IO80211AWDLProtocol:IO80211VirtualInterface{\n'+''.join(f'virtual IOReturn {n}({t}*)=0;\n'for n,t in methods)+'};\n'
shim=r'''
#include <sys/types.h>
#include <array>
#include <map>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>
#include <AWDL/RTWAwdlData.hpp>
#include <AWDL/RTWAwdlDataReceive.hpp>
#include <AWDL/RTWAwdlDataReplay.hpp>
#include <AWDL/RTWAwdlNativeRxMetadata.hpp>
#include <AWDL/RTWAwdlNativeEvents.hpp>
#include <AWDL/RTWAwdlWindowScheduler.hpp>
#include <AWDL/RTWAwdlTxTemplate.hpp>
#include <HAL/RTWAwdlPeer.hpp>
#define APPLE80211_VERSION 1
#define APPLE80211_MAX_SSID_LEN 32
#define APPLE80211_MAX_CHANNELS 128
#define APPLE80211_S_RUN 4
#define APPLE80211_S_INIT 0
#define OSDynamicCast(T,p) dynamic_cast<T*>(p)
'''
extra=r'''
constexpr int kIOReturnBusy=4,kIOReturnUnsupported=5,kIOReturnNoMemory=6,kIOReturnNoResources=7;
'''
scenario=r'''
using namespace AirportRTWAwdl;
using Key=std::array<uint8_t,6>;
static Key key(const uint8_t*p){Key k{};memcpy(k.data(),p,6);return k;}
struct Hardware:RTWAwdl::PeerHardware{
 unsigned limit=16,adds=0,removes=0;bool slow=false;std::atomic<unsigned>calls{0};
 RTWAwdl::PeerResult addResult=RTWAwdl::PeerResult::Success,removeResult=RTWAwdl::PeerResult::Success;
 std::map<Key,bool> live;
 std::function<void()>onAdd;
 uint32_t awdlPeerCapacity()const override{return limit;}
 RTWAwdl::PeerResult setAwdlPeer(const uint8_t*p,bool add)override{
  struct Scope{Hardware&h;Scope(Hardware&o):h(o){assert(h.calls.fetch_add(1)==0);
   if(h.slow)std::this_thread::sleep_for(std::chrono::microseconds(100));}~Scope(){assert(h.calls.fetch_sub(1)==1);}}scope(*this);
  if(add){++adds;if(addResult==RTWAwdl::PeerResult::Success||addResult==RTWAwdl::PeerResult::RecoveryRequired)live[key(p)]=true;
   if(onAdd)onAdd();return addResult;}
  ++removes;if(removeResult==RTWAwdl::PeerResult::Success)live.erase(key(p));return removeResult;
 }
};
struct Backend:RuntimeBackend{
 Hardware&hardware;unsigned opens=0,closes=0,activations=0;
 Settings settings{};std::function<void()>onOpen;
 Backend(NativePeers&peers,Hardware&h):RuntimeBackend(&peers),hardware(h){}
 uint32_t capabilities()const override{return Control::requiredCapabilities;}
 bool ready()const override{return true;}
 IOReturn open(IO80211VirtualInterface*,const uint8_t*)override{++opens;if(onOpen)onOpen();return 0;}
 IOReturn activate(bool)override{++activations;return 0;}
 void close()override{
  // Model backend close taking the entire HAL VIF after producer shutdown.
  while(!hardware.live.empty()){
   auto address=hardware.live.begin()->first;
   assert(hardware.setAwdlPeer(address.data(),false)==RTWAwdl::PeerResult::Success);
  }
  ++closes;
 }
 bool channelAllowed(const apple80211_channel&)const override{return false;}
 bool currentChannel(apple80211_channel&)const override{return false;}
 IOReturn configure(const Settings&s)override{settings=s;return 0;}
 bool configuration(Settings&s)const override{s=settings;return true;}
 IOReturn installTemplate(const RTWAwdl::TxTemplate&)override{return kIOReturnUnsupported;}
 IOReturn setAddress(const uint8_t*)override{return 0;}
 bool transmitEthernet(const uint8_t*,size_t)override{return false;}
};
static constexpr uint8_t local[6]={2,1,2,3,4,1},peer[6]={2,1,2,3,4,2},second[6]={2,1,2,3,4,3};
static IOReturn cache(AirportRTWAwdlInterface*i,unsigned op,const uint8_t*p){
 uint8_t request[0x1d0]{};request[0]=1;request[4]=uint8_t(op);memcpy(request+8,p,6);
 return i->setPEER_CACHE_CONTROL(reinterpret_cast<apple80211_peer_cache_control*>(request));
}
static apple80211_awdl_peer_traffic_registration traffic(const uint8_t*p,bool active=true){
 apple80211_awdl_peer_traffic_registration d{};d.version=1;d.name_len=7;memcpy(d.name,"AirDrop",7);
 memcpy(d.addr,p,6);d.active=active;return d;
}
struct Fixture{
 Hardware hardware;NativePeers peers{hardware};Backend backend{peers,hardware};Runtime runtime{backend};
 IO80211Controller*c=new IO80211Controller;AirportRTWAwdlInterface*i=nullptr;
 Fixture(){messages.clear();eventHook=nullptr;i=AirportRTWAwdlInterface::withController(c,&runtime,local);assert(i&&!i->enable(0));}
 ~Fixture(){eventHook=nullptr;hardware.removeResult=RTWAwdl::PeerResult::Success;
  i->terminate(0);i->release();c->release();assert(hardware.live.empty()&&objects==0&&controlLocks==0&&backend.closes==1);}
};
static Hardware*hookHardware;
static Runtime*hookRuntime;
static Backend*hookBackend;
int main(){
 {Fixture f;hookHardware=&f.hardware;
  eventHook=[](OSObject*,unsigned id){if(id==51)assert(hookHardware->live.count(key(peer)));};
  assert(cache(f.i,0,peer)==0&&f.hardware.adds==1&&f.peers.authorized(peer));
  assert(messages.size()==1&&messages.back().id==51&&messages.back().bytes.size()==0x1d0);
  auto bytes=messages.back().bytes;assert(bytes[0]==1&&bytes[4]==1&&!memcmp(bytes.data()+8,peer,6));
  for(unsigned n=14;n<bytes.size();++n)assert(!bytes[n]);
  assert(cache(f.i,6,peer)==0&&f.hardware.adds==1&&messages.size()==2);
  auto tr=traffic(peer);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  eventHook=nullptr;assert(!cache(f.i,2,peer));
  assert(messages.back().bytes[4]==3&&f.hardware.removes==0&&f.peers.authorized(peer));
  tr=traffic(local,false);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  assert(f.hardware.removes==1&&!f.peers.authorized(peer));
  assert(!cache(f.i,2,peer)&&f.hardware.removes==1);}
 {Fixture f;apple80211_peer_cache_maximum_size limit{};
  f.hardware.limit=64;assert(!f.i->getPEER_CACHE_MAXIMUM_SIZE(&limit)&&limit.max_peers==16);
  f.hardware.limit=1;assert(!f.i->getPEER_CACHE_MAXIMUM_SIZE(&limit)&&limit.max_peers==1);

  assert(!cache(f.i,0,peer));auto old=messages.size();
  assert(cache(f.i,0,second)==kIOReturnNoResources&&messages.size()==old&&f.hardware.adds==1);}
 for(auto failure:{RTWAwdl::PeerResult::NoMemory,RTWAwdl::PeerResult::NoResources,RTWAwdl::PeerResult::HardwareError}){
  Fixture f;f.hardware.addResult=failure;
  assert(cache(f.i,0,peer)!=0&&messages.empty()&&!f.peers.authorized(peer)&&f.hardware.live.empty());}
 {Fixture f;f.hardware.addResult=RTWAwdl::PeerResult::RecoveryRequired;
  assert(cache(f.i,0,peer)==kIOReturnError&&messages.empty()&&!f.peers.authorized(peer)&&!f.runtime.ready());
  assert(f.hardware.live.count(key(peer)));f.runtime.shutdown();assert(f.hardware.live.empty()&&f.backend.closes==1);}
 {Fixture f;assert(!cache(f.i,0,peer));f.hardware.removeResult=RTWAwdl::PeerResult::RecoveryRequired;
  auto before=messages.size();assert(cache(f.i,2,peer)==kIOReturnError&&messages.size()==before);
  assert(!f.peers.authorized(peer)&&f.hardware.live.count(key(peer))&&!f.runtime.ready());
  f.hardware.removeResult=RTWAwdl::PeerResult::Success;f.runtime.shutdown();assert(f.hardware.live.empty());}
 {Fixture f;auto tr=traffic(peer);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  assert(f.peers.authorized(peer)&&f.hardware.adds==1);
  tr=traffic(second);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  assert(!f.peers.authorized(peer)&&f.peers.authorized(second)&&f.hardware.removes==1);
  assert(!cache(f.i,0,second));tr=traffic(second,false);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  assert(f.peers.authorized(second)&&f.hardware.removes==1);
  assert(!cache(f.i,2,second)&&f.hardware.removes==2);}
 {Fixture f;auto tr=traffic(peer);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  f.hardware.addResult=RTWAwdl::PeerResult::NoResources;tr=traffic(second);
  assert(f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr)==kIOReturnNoResources);
  assert(f.peers.authorized(peer)&&!f.peers.authorized(second)&&f.hardware.live.size()==1);}
 {Fixture f;auto tr=traffic(peer);assert(!f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr));
  f.hardware.removeResult=RTWAwdl::PeerResult::RecoveryRequired;tr=traffic(second);
  assert(f.i->setAWDL_PEER_TRAFFIC_REGISTRATION(&tr)==kIOReturnError);
  assert(!f.peers.authorized(peer)&&!f.peers.authorized(second)&&!f.runtime.ready()&&messages.empty());
  f.hardware.removeResult=RTWAwdl::PeerResult::Success;}
 {Fixture f;hookRuntime=&f.runtime;
  eventHook=[](OSObject*o,unsigned id){if(id==51)assert(cache(static_cast<AirportRTWAwdlInterface*>(o),2,peer)==kIOReturnBusy);};
  assert(!cache(f.i,0,peer)&&f.hardware.adds==1&&!f.hardware.removes&&f.peers.authorized(peer));}
 {Fixture f;hookHardware=&f.hardware;hookBackend=&f.backend;
  eventHook=[](OSObject*o,unsigned id){if(id==51){
   auto*i=static_cast<AirportRTWAwdlInterface*>(o);i->terminate(0);
   assert(hookBackend->closes==0&&hookHardware->live.count(key(peer)));}};
  assert(!cache(f.i,0,peer));assert(f.backend.closes==1&&f.hardware.live.empty()&&!f.runtime.ready());}
 {Fixture f;f.hardware.onAdd=[&f](){f.runtime.shutdown();assert(!f.backend.closes);};
  assert(cache(f.i,0,peer)==kIOReturnNotReady&&messages.empty());
  assert(f.backend.closes==1&&f.hardware.live.empty());f.hardware.onAdd=nullptr;}
 {Fixture f;f.hardware.onAdd=[&f](){assert(!f.i->disable(0));};
  assert(cache(f.i,0,peer)==kIOReturnNotReady&&messages.empty()&&f.hardware.live.empty());
  f.hardware.onAdd=nullptr;assert(!f.i->enable(0));assert(!cache(f.i,0,peer));}
 {Fixture f;assert(!cache(f.i,0,peer));assert(!f.i->disable(0));
  assert(!f.peers.authorized(peer)&&f.hardware.live.empty());
  ether_addr address{};memcpy(address.octet,second,6);
  assert(!f.i->setMacAddress(address));assert(!f.i->enable(0));
  assert(cache(f.i,0,second)==kIOReturnBadArgument);assert(!cache(f.i,0,peer));}
 {Fixture f;f.hardware.slow=true;std::vector<std::thread>workers;
  for(unsigned n=0;n<16;++n)workers.emplace_back([&f,n](){
   uint8_t address[6]={2,2,3,4,5,uint8_t(n+32)};assert(!cache(f.i,0,address));});
  for(auto &worker:workers)worker.join();
  assert(f.hardware.live.size()==16&&f.hardware.adds==16&&messages.size()==16);}
 {Fixture f;f.hardware.slow=true;std::vector<std::thread>workers;
  for(unsigned n=0;n<16;++n)workers.emplace_back([&f,n](){
   uint8_t address[6]={2,2,3,4,5,uint8_t(n+32)};
   auto result=cache(f.i,0,address);assert(result==0||result==kIOReturnNotReady);});
  std::thread stopping([&f](){std::this_thread::sleep_for(std::chrono::microseconds(200));f.i->terminate(0);});
  for(auto &worker:workers)worker.join();stopping.join();
  assert(!f.runtime.ready()&&f.hardware.live.empty()&&f.backend.closes==1);}
 {Hardware h;NativePeers peers(h);Backend b(peers,h);Runtime runtime(b);auto*c=new IO80211Controller;
  b.onOpen=[&h](){h.limit=0;};assert(!AirportRTWAwdlInterface::withController(c,&runtime,local));
  assert(b.opens==1&&b.closes==1);c->release();assert(objects==0);}
 {Fixture f;auto *dp=AirportRTWAwdlDatapath::last;
  uint8_t eth[54]={},wire[82]={};size_t n=0;
  memcpy(eth,local,6);memcpy(eth+6,peer,6);eth[12]=0x86;eth[13]=0xdd;eth[14]=0x60;eth[20]=59;
  assert(RTWAwdl::DataCodec::encode(eth,sizeof(eth),wire,sizeof(wire),1,7,n));
  RTWAwdl::ReceiveMetadata metadata{RTWAwdl::FrameKind::IPv6,-40,5180,0xdeadbeef,true};
  nativeHostUs=1000000;
  AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  assert(!dp->pumpData()&&!dp->received); // native peer membership is mandatory
  assert(!cache(f.i,0,peer));
  AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  wire[41]^=1;assert(dp->dataBytes[41]!=wire[41]);wire[41]^=1;
  assert(dp->pumpData()&&dp->received==1&&dp->ethernetBytes==std::vector<uint8_t>(eth,eth+54));
  assert(!dp->pumpData()&&dp->received==1); // duplicate on this TID
  wire[24]=1;AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  assert(dp->pumpData()&&dp->received==2); // independent stream
  assert(!cache(f.i,2,peer));assert(!cache(f.i,0,peer));
  AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  assert(dp->pumpData()&&dp->received==3); // remove/re-add resets duplicate history
  wire[36]=8;AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  nativeHostUs+=3000001;assert(!dp->pumpData()&&dp->received==3); // stale staging
  nativeHostUs=(uint64_t(1)<<32)+1000;
  AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  assert(dp->pumpData()&&dp->received==4); // software RX clock wraps at 32 bits
  wire[36]=9;AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);
  dp->dataMetadata[0]^=1;assert(!dp->pumpData()&&dp->received==4);
  assert(!f.i->disable(0));assert(!dp->pumpData()&&dp->received==4);
  nativeHostUs=1000000;
 }
 {Fixture f;auto *dp=AirportRTWAwdlDatapath::last;
  assert(!f.i->disable(0));ether_addr address{};memcpy(address.octet,local,6);address.octet[5]^=0x10;
  assert(!f.i->setMacAddress(address));assert(!f.i->enable(0));assert(!cache(f.i,0,peer));
  uint8_t eth[54]={},wire[82]={};size_t n=0;memcpy(eth,local,6);memcpy(eth+6,peer,6);
  eth[12]=0x86;eth[13]=0xdd;eth[14]=0x60;eth[20]=59;
  RTWAwdl::ReceiveMetadata metadata{RTWAwdl::FrameKind::IPv6,-40,5180,0,false};
  assert(RTWAwdl::DataCodec::encode(eth,sizeof(eth),wire,sizeof(wire),1,7,n));
  AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);assert(!dp->pumpData()&&!dp->received);
  memcpy(eth,address.octet,6);
  assert(RTWAwdl::DataCodec::encode(eth,sizeof(eth),wire,sizeof(wire),1,7,n));
  AirportRTWAwdlInterface::receiveRadio(f.i,wire,n,metadata);assert(dp->pumpData()&&dp->received==1);
 }
 puts("PASS: actual native peer requests install hardware before completion, preserve ownership and defer reentrant shutdown");
}
'''
source=shim+(ROOT/'tests/host/rtw_awdl_interface_shim.hpp').read_text()+extra+'\n'.join(structs)+base
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlControl.hpp').read_text())
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlPeerControl.hpp').read_text())
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlInterface.hpp').read_text())
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlPeers.hpp').read_text())
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlRuntime.hpp').read_text())
source+=strip((ROOT/'AirportRTW/WCL/AirportRTWAwdlInterface.cpp').read_text())
source+=(ROOT/'tests/host/rtw_awdl_interface_scenarios.hpp').read_text().split('struct Control:',1)[0]+scenario
with tempfile.TemporaryDirectory(prefix='rtw-native-peers-')as tmp:
 cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(source)
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
  '-Wno-unused-parameter','-Wno-unused-function','-DAIRPORT_WCL','-D__MAC_26_0=260000',
  '-D__IO80211_TARGET=260000','-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(cpp),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True,timeout=15)
