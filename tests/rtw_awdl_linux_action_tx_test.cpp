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
       IEEE80211_AC_VO=0,IEEE80211_TX_MAX_RATES=4,GFP_ATOMIC=0 };
struct Channel { unsigned band; uint16_t center_freq; unsigned flags; };
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
struct ieee80211_hw;
struct ieee80211_tx_control { void *sta; };
struct Ops { void (*tx)(ieee80211_hw *,ieee80211_tx_control *,sk_buff *); };
struct ieee80211_hw { Ops *ops; struct { struct { Channel *chan; } chandef; } conf; };
static unsigned allocations;
static bool failAllocation;
static sk_buff *submitted;
static sk_buff *alloc_skb(u32 n,int) {
    ++allocations; if(failAllocation) return nullptr;
    auto *p=new sk_buff{}; p->bytes.reserve(n); return p;
}
static void skb_reserve(sk_buff *p,unsigned n) { p->reserved=n; }
static void skb_put_data(sk_buff *p,const uint8_t *b,u32 n) { p->bytes.assign(b,b+n); }
static Info *IEEE80211_SKB_CB(sk_buff *p) { return &p->info; }
static void skb_set_queue_mapping(sk_buff *p,unsigned n) { p->queue=n; }
#include <AWDL/RTWAwdlLinuxActionTx.hpp>
static void tx(ieee80211_hw *,ieee80211_tx_control *control,sk_buff *skb) {
    assert(!submitted && !control->sta); submitted=skb;
}
int main() {
    Channel channel={NL80211_BAND_2GHZ,2437,0}, stale=channel;
    ieee80211_vif vif={true,NL80211_IFTYPE_ADHOC,{2,1,2,3,4,5},{&channel}};
    Ops ops={tx}; ieee80211_hw hw={&ops,{{&channel}}};
    uint8_t frame[43]={0xd0};
    memset(frame+4,255,6); memcpy(frame+10,vif.addr,6);
    const uint8_t bssid[]={0,0x25,0,0xff,0x94,0x73}; memcpy(frame+16,bssid,6);
    const uint8_t envelope[]={127,0,0x17,0xf2,8,0x10,0}; memcpy(frame+24,envelope,7);
    frame[40]=99; // valid empty TLV
    using Result=RTWAwdl::ActionSubmission;
    auto submit=[&]{ return RTWAwdl::submitLinuxAction(&hw,&vif,frame,sizeof(frame),channel.center_freq); };
    auto rejected=[&]{ unsigned before=allocations; assert(submit()==Result::Rejected); assert(before==allocations && !submitted); };
    assert(submit()==Result::Submitted);
    assert(submitted->reserved==128 && submitted->queue==IEEE80211_AC_VO);
    assert(submitted->info.control.vif==&vif && !submitted->info.control.sta && !submitted->info.control.hw_key);
    assert(submitted->info.control.rates[0].idx==4 && submitted->info.control.rates[0].count==1);
    for(unsigned i=1;i<4;++i) assert(submitted->info.control.rates[i].idx==-1);
    assert(submitted->info.flags & IEEE80211_TX_CTL_NO_ACK);
    frame[25]=1; assert(submitted->bytes[25]==0); frame[25]=0;
    delete submitted; submitted=nullptr;
    for(unsigned bit : {IEEE80211_CHAN_DISABLED,IEEE80211_CHAN_NO_IR,
                       IEEE80211_CHAN_RADAR,IEEE80211_CHAN_NO_OFDM}) {
        channel.flags=bit; rejected();
    }
    channel.flags=0;
    vif.bss_conf.chandef_chan=&stale; rejected(); vif.bss_conf.chandef_chan=&channel;
    channel.center_freq=2484; rejected(); channel.center_freq=2437;
    channel.band=NL80211_BAND_6GHZ; rejected(); channel.band=NL80211_BAND_2GHZ;
    vif.no_beacon=false; rejected(); vif.no_beacon=true;
    vif.type=NL80211_IFTYPE_STATION; rejected(); vif.type=NL80211_IFTYPE_ADHOC;
    for(unsigned offset : {10U,16U}) {
        frame[offset]^=2; rejected(); frame[offset]^=2;
    }
    frame[30]=4; rejected(); frame[30]=0;
    frame[1]=0x40; rejected(); frame[1]=0;
    frame[40]=1; frame[41]=255; rejected(); frame[41]=0;
    for(size_t n=0;n<40;++n)
        assert(RTWAwdl::submitLinuxAction(&hw,&vif,frame,n,2437)==Result::Rejected);
    assert(RTWAwdl::submitLinuxAction(&hw,&vif,frame,sizeof(frame),2412)==Result::Rejected);
    memset(frame+4,0,6); rejected(); frame[4]=1; rejected(); frame[4]=2;
    failAllocation=true; assert(submit()==Result::NoMemory); failAllocation=false;
    channel.band=NL80211_BAND_5GHZ; channel.center_freq=5180; frame[30]=3;
    assert(submit()==Result::Submitted);
    assert(submitted->info.control.rates[0].idx==0);
    assert(submitted->info.flags & IEEE80211_TX_CTL_REQ_TX_STATUS);
    assert(!(submitted->info.flags & IEEE80211_TX_CTL_NO_ACK));
    delete submitted; submitted=nullptr;
    assert(RTWAwdl::submitLinuxAction(nullptr,&vif,frame,sizeof(frame),5180)==Result::Rejected);
}
