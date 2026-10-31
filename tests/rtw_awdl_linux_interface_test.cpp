/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <HAL/RTWAwdlInterfaceState.hpp>
static unsigned allocationAttempts, failAllocation, live, adds, removes, registrations, bssidChanges;
static bool failAdd, failRegistration, hardwareLive, registryLive;
static std::map<void *,size_t> allocations;
static void *IOMallocZero(size_t n) {
    if (++allocationAttempts == failAllocation) return nullptr;
    void *p=calloc(1,n); if(p) { ++live; allocations[p]=n; } return p;
}
static void IOFree(void *p,size_t n) { assert(p && n && allocations.at(p)==n); allocations.erase(p); --live; free(p); }
enum { NL80211_IFTYPE_ADHOC=1, BSS_CHANGED_BSSID=2 };
struct ieee80211_vif;
struct ieee80211_txq { ieee80211_vif *vif; unsigned tid,ac; };
struct Conf { uint8_t addr[6], bssid_buf[6]; const uint8_t *bssid; void *chandef_chan; unsigned chandef_width; };
struct ieee80211_vif {
    int type; bool no_beacon; uint8_t addr[6];
    Conf bss_conf; Conf *link_conf[1]; ieee80211_txq *txq;
};
struct ieee80211_hw;
struct Ops {
    int (*add_interface)(ieee80211_hw *,ieee80211_vif *);
    void (*remove_interface)(ieee80211_hw *,ieee80211_vif *);
    void (*link_info_changed)(ieee80211_hw *,ieee80211_vif *,Conf *,uint64_t);
    void (*bss_info_changed)(ieee80211_hw *,ieee80211_vif *,Conf *,uint64_t);
};
struct ieee80211_hw { Ops *ops; size_t vif_data_size,txq_data_size;
    struct { struct { void *chan; unsigned width; } chandef; } conf; };
static bool rtw88_add_vif(ieee80211_vif *) {
    ++registrations; assert(hardwareLive); if(failRegistration) return false;
    registryLive=true; return true;
}
static void rtw88_remove_vif(ieee80211_vif *) { assert(registryLive); registryLive=false; }
#include <AWDL/RTWAwdlLinuxInterface.hpp>
static int add(ieee80211_hw *,ieee80211_vif *vif) {
    ++adds; assert(vif->type==NL80211_IFTYPE_ADHOC && vif->no_beacon);
    assert(vif->link_conf[0]==&vif->bss_conf);
    assert(vif->bss_conf.bssid==vif->bss_conf.bssid_buf);
    const uint8_t bssid[]={0,0x25,0,0xff,0x94,0x73};
    assert(!memcmp(vif->bss_conf.bssid,bssid,6));
    if(vif->txq) assert(vif->txq->vif==vif && vif->txq->tid==16);
    if(failAdd) return -1; hardwareLive=true; return 0;
}
static void remove(ieee80211_hw *,ieee80211_vif *) {
    ++removes; assert(hardwareLive && !registryLive); hardwareLive=false;
}
static void bssid(ieee80211_hw *,ieee80211_vif *,Conf *,uint64_t flags) {
    assert(hardwareLive && registryLive && flags==BSS_CHANGED_BSSID); ++bssidChanges;
}
int main() {
    Ops ops={add,remove,bssid,nullptr}; ieee80211_hw hw={&ops,128,64,{}};
    uint8_t primary[]={2,1,2,3,4,5}, mac[]={2,1,2,3,4,6};
    RTWAwdl::InterfaceState state={};
    assert(!RTWAwdl::addLinuxInterface(nullptr,state,mac,primary,true));
    assert(!RTWAwdl::addLinuxInterface(&hw,state,primary,primary,true));
    uint8_t zero[6]={}, multicast[6]={1};
    assert(!RTWAwdl::addLinuxInterface(&hw,state,zero,primary,true));
    assert(!RTWAwdl::addLinuxInterface(&hw,state,multicast,primary,true));
    for(bool txq : {false,true}) {
        for(unsigned fault=0;fault<5;++fault) {
            allocationAttempts=0; failAllocation=fault<2?fault+1:0;
            if(!txq && fault==1) continue;
            failAdd=fault==2; failRegistration=fault==3;
            bool ok=RTWAwdl::addLinuxInterface(&hw,state,mac,primary,txq);
            assert(ok==(fault==4));
            if(ok) {
                assert(state.registered && state.hardwareAdded && hardwareLive && registryLive);
                assert(!RTWAwdl::addLinuxInterface(&hw,state,mac,primary,txq));
            } else assert(!state.vif);
            RTWAwdl::removeLinuxInterface(&hw,state);
            RTWAwdl::removeLinuxInterface(&hw,state);
            assert(!live && !hardwareLive && !registryLive && !state.vif);
        }
    }
    assert(bssidChanges==2 && removes==4);
    ops.link_info_changed=nullptr; ops.bss_info_changed=bssid;
    failAdd=failRegistration=false; failAllocation=0;
    assert(RTWAwdl::addLinuxInterface(&hw,state,mac,primary,false));
    assert(bssidChanges==3); RTWAwdl::removeLinuxInterface(&hw,state);
    assert(!live && allocations.empty());
}
