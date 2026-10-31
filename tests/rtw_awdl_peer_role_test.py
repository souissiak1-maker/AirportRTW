#!/usr/bin/env python3
"""Run actual RTW89 firmware role add/remove functions with bounded host adapters."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]

def extract(s, start):
    a=s.index(start);b=s.index('{',a);depth=1;end=b+1
    while depth:
        depth+=(s[end]=='{')-(s[end]=='}');end+=1
    return s[a:end]+'\n'
core=(ROOT/'rtw/hal_rtw89/driver/core.c').read_text()
header=(ROOT/'rtw/hal_rtw89/driver/core.h').read_text()
policy=extract(header,'static inline bool rtw89_vif_has_peer_context(')
functions=extract(core,'int rtw89_core_sta_link_add(')+extract(core,'int rtw89_core_sta_link_remove(')
shim=r'''
#include <cassert>
#include <initializer_list>
#include <cstring>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define INIT_LIST_HEAD(p) (*(p)=0)
#define rtw89_warn(...) ((void)0)
using u8=unsigned char;
enum {NL80211_IFTYPE_AP,NL80211_IFTYPE_STATION,NL80211_IFTYPE_ADHOC};
enum {RTW89_ROLE_CREATE,RTW89_ROLE_REMOVE,BTC_ROLE_MSTS_STA_CONN_START,BTC_ROLE_MSTS_STA_DIS_CONN};
struct ieee80211_vif { int type; bool no_beacon,p2p; };
struct ieee80211_sta { bool tdls; };
struct rtw89_vif_link { ieee80211_vif vif; };
struct rtw89_sta_link {
    ieee80211_sta sta; int prev_rssi,ba_cam_list,avg_rssi,avg_snr,evm_1ss;
    int rssi[2],evm_min[2],evm_max[2]; u8 mac_id,tx_retry;
};
struct rtw89_hal { bool ant_diversity; };
struct Chip { u8 rf_path_num; };
struct rtw89_dev { rtw89_hal hal; Chip *chip; };
static const ieee80211_vif *rtwvif_link_to_vif(rtw89_vif_link *p) { return &p->vif; }
static const ieee80211_sta *rtwsta_link_to_sta(rtw89_sta_link *p) { return &p->sta; }
static void ewma_rssi_init(int *p) { *p=0; }
static void ewma_snr_init(int *p) { *p=0; }
static void ewma_evm_init(int *p) { *p=0; }
static unsigned step,failStep,creates,removes;
static int next() { ++step; return step==failStep?-42:0; }
static int rtw89_reg_6ghz_recalc(rtw89_dev *,rtw89_vif_link *,bool) { return 0; }
static void rtw89_btc_ntfy_role_info(rtw89_dev *,rtw89_vif_link *,rtw89_sta_link *,int) {}
static void rtw89_chip_rfk_channel(rtw89_dev *,rtw89_vif_link *) {}
static void rtw89_mac_get_tx_retry_limit(rtw89_dev *,rtw89_sta_link *,u8 *) {}
static void rtw89_mac_set_tx_retry_limit(rtw89_dev *,rtw89_sta_link *,bool,unsigned) {}
static void rtw89_phy_dig_suspend(rtw89_dev *) {}
static int rtw89_mac_set_macid_pause(rtw89_dev *,u8,bool) { return next(); }
static int rtw89_fw_h2c_role_maintain(rtw89_dev *,rtw89_vif_link *,rtw89_sta_link *,int command) {
    if(command==RTW89_ROLE_CREATE) ++creates; else ++removes; return next();
}
static int rtw89_chip_h2c_default_cmac_tbl(rtw89_dev *,rtw89_vif_link *,rtw89_sta_link *) { return next(); }
static int rtw89_chip_h2c_default_dmac_tbl(rtw89_dev *,rtw89_vif_link *,rtw89_sta_link *) { return next(); }
'''
cases=r'''
int main() {
    Chip chip={2}; rtw89_dev dev={{false},&chip}; rtw89_sta_link peer={};
    for(int type : {NL80211_IFTYPE_AP,NL80211_IFTYPE_STATION,NL80211_IFTYPE_ADHOC})
        for(bool quiet : {false,true}) for(bool tdls : {false,true}) {
            rtw89_vif_link vif={{type,quiet,false}}; peer.sta.tdls=tdls;
            step=failStep=creates=removes=0;
            assert(!rtw89_core_sta_link_add(&dev,&vif,&peer));
            assert(!rtw89_core_sta_link_remove(&dev,&vif,&peer));
            bool remote=type==NL80211_IFTYPE_AP || (quiet && type==NL80211_IFTYPE_ADHOC) || tdls;
            assert(creates==unsigned(remote) && removes==unsigned(remote));
        }
    rtw89_vif_link vif={{NL80211_IFTYPE_ADHOC,true,false}}; peer.sta.tdls=false;
    for(unsigned failure=1;failure<=4;++failure) {
        step=0; failStep=failure;
        assert(rtw89_core_sta_link_add(&dev,&vif,&peer)==-42);
        assert(step==failure);
    }
    step=0;failStep=1;
    assert(rtw89_core_sta_link_remove(&dev,&vif,&peer)==-42);
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-role-') as tmp:
    path=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';path.write_text(shim+policy+functions+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-Wno-unused-parameter','-fsanitize=address,undefined',str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PASS: production RTW89 firmware peer roles and command-error propagation')
