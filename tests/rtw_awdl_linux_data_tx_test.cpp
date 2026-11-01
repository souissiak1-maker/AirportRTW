/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
using u32=uint32_t;
enum { NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_6GHZ };
enum { NL80211_IFTYPE_ADHOC,NL80211_IFTYPE_STATION };
enum { IEEE80211_CHAN_DISABLED=1,IEEE80211_CHAN_NO_IR=2,
       IEEE80211_CHAN_RADAR=128,IEEE80211_CHAN_NO_OFDM=64 };
enum { IEEE80211_TX_CTL_FIRST_FRAGMENT=16,IEEE80211_TX_CTL_INJECTED=1024,
       IEEE80211_TX_CTL_NO_ACK=4,IEEE80211_TX_CTL_REQ_TX_STATUS=1,
       IEEE80211_TX_CTL_TX_OFFCHAN=2048,IEEE80211_AC_BE=1,IEEE80211_AC_VO=0,IEEE80211_TX_MAX_RATES=4,GFP_ATOMIC=0 };
struct ieee80211_channel { unsigned band; uint16_t center_freq; unsigned flags; };
using Channel=ieee80211_channel;
struct ieee80211_vif {
    bool no_beacon; unsigned type; uint8_t addr[6];
    struct { Channel *chandef_chan; } bss_conf;
};
struct Rate { int idx; unsigned count,flags; };
struct Info {
    unsigned flags,band;
    struct { ieee80211_vif *vif; void *hw_key,*sta; Rate rates[4]; } control;
};
struct sk_buff { std::vector<uint8_t> bytes; size_t reserved; unsigned queue; Info info; };
struct ieee80211_sta {uint8_t addr[6];};
struct ieee80211_hw;
struct ieee80211_tx_control { void *sta; };
struct Ops { void (*tx)(ieee80211_hw *,ieee80211_tx_control *,sk_buff *); };
struct ieee80211_hw { Ops *ops; struct { struct { Channel *chan; } chandef; } conf; };
static unsigned allocations,frees;
static uint64_t now=1000,advanceOnAllocate=0;
static uint64_t clockUs(){return now;}
static bool failAllocation;
static sk_buff *submitted;
static sk_buff *alloc_skb(u32 n,int) {
    ++allocations;now+=advanceOnAllocate; if(failAllocation) return nullptr;
    auto *p=new sk_buff{}; p->bytes.reserve(n); return p;
}
static void skb_reserve(sk_buff *p,unsigned n) { p->reserved=n; }
static void skb_put_data(sk_buff *p,const uint8_t *b,u32 n) { p->bytes.assign(b,b+n); }
static Info *IEEE80211_SKB_CB(sk_buff *p) { return &p->info; }
static void skb_set_queue_mapping(sk_buff *p,unsigned n) { p->queue=n; }
static void kfree_skb(sk_buff*p){++frees;delete p;}
#include <AWDL/RTWAwdlLinuxDataTx.hpp>
static ieee80211_sta *expectedPeer;
static void tx(ieee80211_hw*,ieee80211_tx_control*c,sk_buff*s){
 assert(!submitted&&c->sta==expectedPeer);submitted=s;
}
int main(){
 using Result=RTWAwdl::DataSubmission;
 Channel channel={NL80211_BAND_2GHZ,2437,0},stale=channel;
 ieee80211_vif vif={true,NL80211_IFTYPE_ADHOC,{2,1,2,3,4,5},{&channel}};
 ieee80211_sta peer{{2,6,7,8,9,10}};expectedPeer=&peer;
 Ops ops{tx};ieee80211_hw hw{&ops,{{&channel}}};
 uint8_t ethernet[54]={},frame[RTWAwdl::DataCodec::maximumFrame]={};size_t length=0;
 memcpy(ethernet,peer.addr,6);memcpy(ethernet+6,vif.addr,6);ethernet[12]=0x86;ethernet[13]=0xdd;
 ethernet[14]=0x60;ethernet[20]=59;ethernet[22]=0xfe;ethernet[23]=0x80;ethernet[37]=1;
 ethernet[38]=0xfe;ethernet[39]=0x80;ethernet[53]=2;
 assert(RTWAwdl::DataCodec::encode(ethernet,sizeof(ethernet),frame,sizeof(frame),1,2,length));
 auto submit=[&]{return RTWAwdl::submitLinuxData(&hw,&vif,expectedPeer,frame,length,channel.center_freq,&channel,20000,clockUs);};
 auto rejected=[&]{unsigned before=allocations;assert(submit()==Result::Rejected&&!submitted&&allocations==before);};
 assert(submit()==Result::Submitted);assert(submitted->reserved==128&&submitted->queue==IEEE80211_AC_BE);
 assert(submitted->info.flags&IEEE80211_TX_CTL_TX_OFFCHAN);
 assert(submitted->info.flags&IEEE80211_TX_CTL_REQ_TX_STATUS);
 assert(!(submitted->info.flags&IEEE80211_TX_CTL_NO_ACK));
 assert(submitted->info.control.vif==&vif&&!submitted->info.control.hw_key);
 assert(submitted->info.control.rates[0].idx==4&&submitted->info.control.rates[0].count==1);
 frame[41]^=1;assert(submitted->bytes[41]!=frame[41]);frame[41]^=1;
 delete submitted;submitted=nullptr;
 for(unsigned flag:{IEEE80211_CHAN_DISABLED,IEEE80211_CHAN_NO_IR,IEEE80211_CHAN_RADAR,IEEE80211_CHAN_NO_OFDM}){
  channel.flags=flag;rejected();
 }
 channel.flags=0;vif.bss_conf.chandef_chan=&stale;rejected();vif.bss_conf.chandef_chan=&channel;
 for(unsigned offset:{1U,10U,16U,24U,25U}){frame[offset]^=1;rejected();frame[offset]^=1;}
 frame[42]^=0x10;rejected();frame[42]^=0x10;
 expectedPeer=nullptr;rejected();expectedPeer=&peer;
 peer.addr[5]^=1;rejected();peer.addr[5]^=1;
 now=19999;rejected();now=1000;
 advanceOnAllocate=20000;assert(submit()==Result::Rejected&&frees==1&&!submitted);
 advanceOnAllocate=0;now=1000;
 failAllocation=true;assert(submit()==Result::NoMemory);failAllocation=false;
 channel.band=NL80211_BAND_5GHZ;channel.center_freq=5180;
 assert(submit()==Result::Submitted&&submitted->info.control.rates[0].idx==0);
 delete submitted;submitted=nullptr;
 const uint8_t multicast[6]={0x33,0x33,0,0,0,0xfb};memcpy(ethernet,multicast,6);
 memset(ethernet+38,0,16);ethernet[38]=0xff;ethernet[39]=2;ethernet[53]=0xfb;
 assert(RTWAwdl::DataCodec::encode(ethernet,sizeof(ethernet),frame,sizeof(frame),2,3,length));
 rejected();expectedPeer=nullptr;
 assert(submit()==Result::Submitted);
 assert(submitted->info.flags&IEEE80211_TX_CTL_NO_ACK);
 assert(!(submitted->info.flags&IEEE80211_TX_CTL_REQ_TX_STATUS));delete submitted;submitted=nullptr;
 frame[9]^=1;rejected();frame[9]^=1;frame[66]=0xfe;rejected();
 puts("PASS: production AWDL data submission validates peers, multicast, policy, deadlines and ownership");
}
