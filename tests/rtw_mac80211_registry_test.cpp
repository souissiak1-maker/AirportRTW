// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <cassert>
#include <cstring>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
using u8 = unsigned char;
#define ETH_ALEN 6
using IORecursiveLock = std::recursive_mutex;
static void IORecursiveLockLock(IORecursiveLock *p) { p->lock(); }
static void IORecursiveLockUnlock(IORecursiveLock *p) { p->unlock(); }
struct ieee80211_vif { u8 addr[6]; };
struct ieee80211_sta { u8 addr[6]; };
struct ieee80211_hw {};
static ieee80211_hw hw, other;
static ieee80211_hw *g_rtw88_hw = &hw;
#include <AWDL/RTWMac80211Registry.h>
static void countVif(void *p, u8 *, ieee80211_vif *) { ++*static_cast<int *>(p); }
static void countSta(void *p, ieee80211_sta *) { ++*static_cast<int *>(p); }
int main()
{
    IORecursiveLock lock;
    g_station_lock = &lock;
    ieee80211_vif vifs[5] = {};
    for (unsigned i=0;i<5;++i) vifs[i].addr[5]=i+1;
    ieee80211_sta ap = {{2,0,0,0,0,1}}, peer = ap, duplicate = ap;
    rtw88_register_vif(&vifs[0]); rtw88_register_sta(&ap);
    assert(rtw88_add_vif(&vifs[1]));
    assert(rtw88_add_sta(&vifs[1], &peer)); // same remote MAC, different local VIF
    assert(!rtw88_add_sta(&vifs[0], &duplicate));
    assert(!rtw88_add_sta(&vifs[1], &ap)); // cannot move a live pointer
    assert(ieee80211_find_sta(&vifs[0], ap.addr)==&ap);
    assert(ieee80211_find_sta(&vifs[1], ap.addr)==&peer);
    assert(ieee80211_find_sta_by_ifaddr(&hw, ap.addr, vifs[1].addr)==&peer);
    assert(!ieee80211_find_sta_by_ifaddr(&other, ap.addr, nullptr));
    assert(!ieee80211_find_sta(&vifs[2], ap.addr));
    int n=0; ieee80211_iterate_stations_atomic(&hw,countSta,&n); assert(n==2);
    n=0; ieee80211_iterate_active_interfaces(&other,0,countVif,&n); assert(n==0);
    rtw88_unregister_sta(); rtw88_unregister_vif();
    assert(ieee80211_find_sta(&vifs[1],peer.addr)==&peer);
    assert(!ieee80211_find_sta(&vifs[0],ap.addr));
    for (unsigned i=0;i<4;++i) assert(rtw88_add_vif(&vifs[i]));
    assert(!rtw88_add_vif(&vifs[4])); assert(rtw88_add_vif(&vifs[1]));
    ieee80211_sta peers[32]={};
    for(unsigned i=0;i<31;++i) {
        peers[i].addr[5]=i+2; assert(rtw88_add_sta(&vifs[1],&peers[i]));
    }
    peers[31].addr[5]=100; assert(!rtw88_add_sta(&vifs[1],&peers[31]));
    rtw88_remove_sta(&peers[5]); assert(rtw88_add_sta(&vifs[1],&peers[31]));
    // Removal must wait until the iterator no longer borrows any peer.
    std::atomic<bool> entered{false}, release{false}, removed{false};
    struct Gate { std::atomic<bool> *entered,*release; } gate{&entered,&release};
    std::thread reader([&]{ieee80211_iterate_stations_atomic(&hw,
        [](void *p, ieee80211_sta *) {
            auto *g=static_cast<Gate *>(p); g->entered->store(true);
            while(!g->release->load()) std::this_thread::yield();
        },&gate);});
    while(!entered.load()) std::this_thread::yield();
    std::thread writer([&]{rtw88_remove_vif(&vifs[1]);removed.store(true);});
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(!removed.load()); release.store(true); reader.join(); writer.join();
    assert(removed.load()); n=0;
    ieee80211_iterate_stations_atomic(&hw,countSta,&n); assert(n==0);
    rtw_registry_reset(); n=0;
    ieee80211_iterate_active_interfaces_atomic(&hw,0,countVif,&n); assert(n==0);
}
