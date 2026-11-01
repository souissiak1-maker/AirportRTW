#!/usr/bin/env python3
"""Run the actual RTW89 radio/peer admission bridge through the real skb submitter."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
shim=(ROOT/'tests/rtw_awdl_linux_data_tx_test.cpp').read_text().split('static ieee80211_sta *expectedPeer;')[0]
source=(ROOT/'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text()
code=source[source.index('static uint64_t awdlDataNowUs()'):source.index('bool rtw89LinuxAwdlSetReceiver(')]
adapters=r'''
static unsigned depth;
struct WiphyGuard {explicit WiphyGuard(ieee80211_hw*){assert(!depth++);}~WiphyGuard(){assert(depth--==1);}};
constexpr unsigned IEEE80211_STA_AUTHORIZED=4;
struct Gate {bool paused=true,empty=true;bool isPaused()const{return paused;}bool drained()const{return empty;}};
struct Rtw89AwdlPeerPool {struct Entry{void*station=nullptr;bool registered=false,retiring=false;unsigned state=0;uint8_t address[6]={};}entries[16];};
struct Rtw89LinuxContext {
 void*hardware;bool started=true,interfaceAdded=true,scanning=false,awdlRecovery=false;
 struct{bool hardwareAdded=true,registered=true;void*vif;}awdlInterface;
 Gate awdlTxGate;Rtw89AwdlPeerPool*awdlPeers;
};
static bool lease=true,allowed=true;
static ieee80211_channel *activeChannel;
static uint64_t mach_absolute_time(){return now*1000;}
static void absolutetime_to_nanoseconds(uint64_t ticks,uint64_t*ns){*ns=ticks;}
static bool rtw89_macos_awdl_needs_restore(ieee80211_hw*,ieee80211_vif*){assert(depth);return lease;}
static ieee80211_channel*rtw89_macos_awdl_current_channel(ieee80211_hw*,ieee80211_vif*){assert(depth);return activeChannel;}
static ieee80211_channel*awdlFrequencyChannel(ieee80211_hw*,uint16_t){assert(depth);return allowed?activeChannel:nullptr;}
static ieee80211_sta *expectedPeer;
static void tx(ieee80211_hw*,ieee80211_tx_control*c,sk_buff*s){assert(depth&&!submitted&&c->sta==expectedPeer);submitted=s;}
struct Fixture {
 Channel channel{NL80211_BAND_5GHZ,5180,0};
 ieee80211_vif vif{true,NL80211_IFTYPE_ADHOC,{2,1,2,3,4,5},{&channel}};
 ieee80211_sta peer{{2,6,7,8,9,10}};
 Ops ops{tx};ieee80211_hw hw{&ops,{{&channel}}};Rtw89AwdlPeerPool pool;
 Rtw89LinuxContext c{&hw,true,true,false,false,{true,true,&vif},{true,true},&pool};
 uint8_t frame[RTWAwdl::DataCodec::maximumFrame]={};size_t length=0;
 Fixture(){
  lease=allowed=true;activeChannel=&channel;now=1000;advanceOnAllocate=0;failAllocation=false;
  pool.entries[0].station=&peer;pool.entries[0].registered=true;pool.entries[0].state=4;
  memcpy(pool.entries[0].address,peer.addr,6);expectedPeer=&peer;
  uint8_t ethernet[54]={};memcpy(ethernet,peer.addr,6);memcpy(ethernet+6,vif.addr,6);
  ethernet[12]=0x86;ethernet[13]=0xdd;ethernet[14]=0x60;ethernet[20]=59;
  ethernet[38]=0xfe;ethernet[39]=0x80;ethernet[53]=1;
  assert(RTWAwdl::DataCodec::encode(ethernet,sizeof(ethernet),frame,sizeof(frame),1,1,length));
 }
 ~Fixture(){if(submitted){delete submitted;submitted=nullptr;}}
 bool send();
};
'''
cases=r'''
bool Fixture::send(){return rtw89LinuxAwdlTransmitData(&c,frame,length,5180,20000);}
int main(){
 {Fixture f;assert(f.send()&&submitted);assert(submitted->info.flags&IEEE80211_TX_CTL_TX_OFFCHAN);}
 for(unsigned failure=0;failure<17;++failure){Fixture f;
  switch(failure){
   case 0:f.c.started=false;break;case 1:f.c.interfaceAdded=false;break;
   case 2:f.c.scanning=true;break;case 3:f.c.awdlRecovery=true;break;
   case 4:f.c.awdlInterface.hardwareAdded=false;break;case 5:f.c.awdlInterface.registered=false;break;
   case 6:f.c.awdlTxGate.paused=false;break;case 7:f.c.awdlTxGate.empty=false;break;
   case 8:lease=false;break;case 9:activeChannel=nullptr;break;
   case 10:allowed=false;break;case 11:f.pool.entries[0].retiring=true;break;
   case 12:f.pool.entries[0].registered=false;break;case 13:f.pool.entries[0].state=3;break;
   case 14:f.pool.entries[0].address[5]^=1;break;case 15:f.c.awdlPeers=nullptr;break;
   case 16:f.c.awdlInterface.vif=nullptr;break;
  }
  unsigned before=allocations;assert(!f.send()&&!submitted&&allocations==before);
 }
 {Fixture f;now=20000;assert(!f.send()&&!submitted);}
 {Fixture f;f.channel.flags=IEEE80211_CHAN_NO_IR;assert(!f.send()&&!submitted);}
 {Fixture f;f.c.hardware=nullptr;assert(!f.send());}
 assert(!rtw89LinuxAwdlTransmitData(nullptr,nullptr,0,0,0));
 puts("PASS: actual RTW89 data bridge rejects inactive leases, undrained producers, unknown/retiring peers and policy failures");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-data-bridge-') as tmp:
    path=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    path.write_text(shim+adapters+code+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-Wno-unused-function',
                    '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
