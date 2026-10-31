#!/usr/bin/env python3
"""Execute production add-interface / beacon policy with host register adapters."""
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]

s88 = (ROOT/'rtw/hal_rtw88/driver/mac80211.c').read_text()
a = s88.index('static int rtw_ops_add_interface(')
b = s88.index('static void rtw_ops_remove_interface(', a)
code88 = s88[a:b]
shim88 = r'''
#include <cassert>
#include <cstring>
using u8=unsigned char; using u32=unsigned;
#define EINVAL 22
#define ENOSPC 28
#define FW_FEATURE_BCN_FILTER 1
#define IEEE80211_VIF_BEACON_FILTER 1
#define IEEE80211_VIF_SUPPORTS_CQM_RSSI 2
#define BIT_EN_BCN_FUNCTION 8
#define BIT_DIS_TSF_UDT 16
#define PORT_SET_MAC_ADDR 1
#define PORT_SET_NET_TYPE 2
#define PORT_SET_BCN_CTRL 4
#define RTW_MAX_MAC_ID_NUM 32
#define RTW_PORT_NUM 5
#define INIT_LIST_HEAD(p) ((void)(p))
#define rtw_dbg(...) ((void)0)
#define WARN_ON(p) ((void)(p))
enum rtw_net_type { RTW_NET_AP_MODE, RTW_NET_AD_HOC, RTW_NET_NO_LINK };
enum { NL80211_IFTYPE_AP, NL80211_IFTYPE_MESH_POINT, NL80211_IFTYPE_ADHOC,
       NL80211_IFTYPE_STATION };
struct rtw_dev { int fw,mutex; unsigned long hw_port[1]; };
struct rtw_bfee { int unused; };
struct rtw_vif {
    struct { int tx_unicast,rx_unicast,tx_cnt,rx_cnt; } stats;
    void *scan_req; rtw_bfee bfee; int rsvd_page_list; u8 mac_id,port;
    const int *conf; u8 mac_addr[6]; rtw_net_type net_type; u8 bcn_ctrl;
};
struct ieee80211_vif {
    int driver_flags,type; bool no_beacon; int *txq; u8 addr[6];
    alignas(rtw_vif) u8 drv_priv[sizeof(rtw_vif)];
};
struct ieee80211_hw { rtw_dev *priv; };
static int rtw_vif_port[5];
static int lockDepth, acquired,released,beacons,stations;
static bool exhausted;
static bool rtw_fw_feature_check(int *,int) { return false; }
static void rtw_txq_init(rtw_dev *,int *) {}
static void mutex_lock(int *) { assert(lockDepth++==0); }
static void mutex_unlock(int *) { assert(--lockDepth==0); }
static u8 rtw_acquire_macid(rtw_dev *) { if(exhausted) return 32; ++acquired; return 1; }
static void rtw_release_macid(rtw_dev *,u8 id) { assert(id==1); ++released; }
static u8 find_first_zero_bit(unsigned long *p,unsigned n) {
    for(unsigned i=0;i<n;++i) if(!(*p & (1UL<<i))) return i;
    return n;
}
static void set_bit(unsigned n,unsigned long *p) { *p |= 1UL<<n; }
static void clear_bit(unsigned n,unsigned long *p) { *p &= ~(1UL<<n); }
static void rtw_leave_lps_deep(rtw_dev *) {}
static void rtw_add_rsvd_page_bcn(rtw_dev *,rtw_vif *) { ++beacons; }
static void rtw_add_rsvd_page_sta(rtw_dev *,rtw_vif *) { ++stations; }
static void ether_addr_copy(u8 *a,const u8 *b) { memcpy(a,b,6); }
static void rtw_vif_port_config(rtw_dev *,rtw_vif *,u32) {}
static void rtw_core_port_switch(rtw_dev *,ieee80211_vif *) {}
static void rtw_recalc_lps(rtw_dev *,ieee80211_vif *) {}
'''
cases88 = r'''
int main() {
    for(int kind : {NL80211_IFTYPE_STATION,NL80211_IFTYPE_ADHOC})
        for(bool quiet : {false,true}) {
            rtw_dev dev={}; ieee80211_hw hw={&dev}; ieee80211_vif vif={};
            vif.type=kind; vif.no_beacon=quiet;
            int before=beacons;
            assert(!rtw_ops_add_interface(&hw,&vif));
            auto *rv=reinterpret_cast<rtw_vif *>(vif.drv_priv);
            bool beacon=(kind==NL80211_IFTYPE_ADHOC && !quiet);
            assert(beacons-before==int(beacon));
            assert(bool(rv->bcn_ctrl & BIT_EN_BCN_FUNCTION)==
                   (kind==NL80211_IFTYPE_STATION || !quiet));
            assert(!lockDepth);
        }
    for(int fault=0;fault<3;++fault) {
        rtw_dev dev={}; ieee80211_hw hw={&dev}; ieee80211_vif vif={};
        vif.type=fault==2?99:NL80211_IFTYPE_ADHOC;
        if(fault==1) dev.hw_port[0]=31;
        exhausted=fault==0; int a=acquired,r=released;
        auto ports=dev.hw_port[0];
        assert(rtw_ops_add_interface(&hw,&vif)<0);
        assert(!lockDepth && acquired-a==released-r && dev.hw_port[0]==ports);
    }
}
'''
s89 = (ROOT/'rtw/hal_rtw89/driver/mac.c').read_text()
# First RX function is non-static, retain its actual declaration.
a = s89.index('void rtw89_mac_port_cfg_rx_sync(')
b = s89.index('static void rtw89_mac_enable_ap_bcn_by_chan', a)
code89 = s89[a:b]
shim89 = r'''
#include <cassert>
using u32=unsigned;
enum { RTW89_NET_TYPE_INFRA,RTW89_NET_TYPE_AD_HOC,RTW89_NET_TYPE_AP_MODE,
       RTW89_NET_TYPE_NO_LINK, B_AX_TSF_UDT_EN=16,B_AX_BCNTX_EN=32 };
struct ieee80211_vif { bool no_beacon; };
struct rtw89_vif_link { int net_type; ieee80211_vif vif; };
struct rtw89_port_reg { unsigned port_cfg; };
struct rtw89_mac_gen_def { rtw89_port_reg *port_base; };
struct Chip { rtw89_mac_gen_def *mac_def; };
struct rtw89_dev { Chip *chip; };
static unsigned value;
static ieee80211_vif *rtwvif_link_to_vif(rtw89_vif_link *v) { return &v->vif; }
static void rtw89_write32_port_set(rtw89_dev *,rtw89_vif_link *,unsigned,u32 bits) { value|=bits; }
static void rtw89_write32_port_clr(rtw89_dev *,rtw89_vif_link *,unsigned,u32 bits) { value&=~bits; }
'''
cases89 = r'''
int main() {
    rtw89_port_reg port={}; rtw89_mac_gen_def mac={&port};
    Chip chip={&mac}; rtw89_dev dev={&chip};
    for(int net : {RTW89_NET_TYPE_INFRA,RTW89_NET_TYPE_AD_HOC,
                  RTW89_NET_TYPE_AP_MODE,RTW89_NET_TYPE_NO_LINK})
        for(bool quiet : {false,true}) {
            rtw89_vif_link link={net,{quiet}};
            value=~0U;
            rtw89_mac_port_cfg_rx_sync_by_nettype(&dev,&link);
            assert(bool(value & B_AX_TSF_UDT_EN)==(!quiet &&
                (net==RTW89_NET_TYPE_INFRA || net==RTW89_NET_TYPE_AD_HOC)));
            rtw89_mac_port_cfg_tx_sw_by_nettype(&dev,&link);
            assert(bool(value & B_AX_BCNTX_EN)==(!quiet &&
                (net==RTW89_NET_TYPE_AP_MODE || net==RTW89_NET_TYPE_AD_HOC)));
        }
}
'''
for family, shim, code, cases in [('88',shim88,code88,cases88),('89',shim89,code89,cases89)]:
    with tempfile.TemporaryDirectory(prefix='rtw-awdl-radio-') as tmp:
        path=Path(tmp)/'test.cpp'; binary=Path(tmp)/'test'
        path.write_text('#include <initializer_list>\n'+shim+code+cases)
        subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
            '-Wno-unused-parameter','-fsanitize=address,undefined',str(path),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
    print(f'PASS: RTW{family} production non-beaconing radio policy')
