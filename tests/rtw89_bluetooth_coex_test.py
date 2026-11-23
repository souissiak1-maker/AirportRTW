#!/usr/bin/env python3
"""Execute the production BTC init, scoreboard updates and policy dispatcher."""
from pathlib import Path
import re,subprocess,sys,tempfile
root=Path(__file__).resolve().parents[1];coex=(root/'rtw/hal_rtw89/driver/coex.c').read_text(encoding='utf-8')
def function(signature):
 a=coex.index(signature);return coex[a:coex.index('\n}',a)+3]
init=function('void rtw89_btc_ntfy_init(struct')
run=function('void _run_coex(struct rtw89_dev *rtwdev, enum btc_reason_and_action reason)\n{')
score=function('static void _update_bt_scbd(struct rtw89_dev *rtwdev, bool only_update)\n{')
off=function('static void _action_bt_off(struct')
observe=function('static void airportrtw_btc_observe(struct')
sta_only=function('void rtw89_btc_ntfy_wl_sta(struct')
if 'static void _ntfy_wl_sta(' in coex:
 sta_only=(function('static void _ntfy_wl_sta(')+sta_only+
           function('void rtw89_btc_ntfy_wl_traffic(struct'))
combined=init+run+score+off+observe+sta_only
constants=sorted(set(re.findall(r'\bBTC_\w+\b',combined))|{'BTC_MODE_NORMAL','BTC_MODE_WL','BTC_MODE_BT'})
scorebits={n:v for n,v in re.findall(r'\b(BTC_BSCB_\w+)\s*=\s*BIT\((\d+)\)',coex)}
defines=''
for i,n in enumerate(constants,1):
 if n in scorebits:defines+=f'#define {n} BIT({scorebits[n]})\n'
 elif n=='BTC_SCB_INV_VALUE':defines+='#define BTC_SCB_INV_VALUE UINT32_MAX\n'
 elif n=='BTC_LPS_OFF':defines+='#define BTC_LPS_OFF 0\n'
 elif n=='BTC_WL_RSSI_THMAX':defines+='#define BTC_WL_RSSI_THMAX 4\n'
 elif n=='BTC_NHM_CHK_INTVL':defines+='#define BTC_NHM_CHK_INTVL 20\n'
 else:defines+=f'#define {n} {i}\n'
if 'void rtw89_btc_ntfy_wl_traffic(' in coex:
 defines+='#define HAS_TRAFFIC_ONLY_NOTIFY\n'
actions=sorted(set(re.findall(r'\b(_action_\w+)\(rtwdev\)',run))-{'_action_bt_off','_action_common'})
fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t u32;typedef uint8_t u8;
#define BIT(n) (1U<<(n))
#define rtw89_debug(...) ((void)0)
#define lockdep_assert_wiphy(...) ((void)0)
#define RTW89_TFC_UL 0
#define RTW89_TFC_DL 1
#define RTW89_TFC_IDLE 0
#define FC_EXEC 1
#define CXDRVINFO_INIT 1
#define CXDRVINFO_CTRL 2
#define CXDRVINFO_ROLE 3
#define RTW89_BTC_WL_DEF_TX_PWR 0
'''+defines+r'''
enum btc_reason_and_action{unused_reason};
struct status_bits{bool rf_off,rf_off_pre,init_ok,scan,busy,connecting,_4way;unsigned lps,lps_pre,traffic_dir;};
struct wl_status{struct status_bits map;unsigned val;};
struct rtw89_btc_wl_role_info{u8 link_mode;};
struct rtw89_btc_wl_role_info_v1{u8 link_mode;};
struct rtw89_btc_wl_role_info_v2{u8 link_mode;};
struct rtw89_btc_wl_role_info_v7{u8 link_mode;};
struct rtw89_btc_wl_role_info_v8{u8 link_mode;};
struct rtw89_btc_wl_info{u8 coex_mode,rssi_level;struct wl_status status;
 struct{unsigned state;bool con_rfk;}rfk_info;
 struct rtw89_btc_wl_role_info role_info;
 struct rtw89_btc_wl_role_info_v1 role_info_v1;
 struct rtw89_btc_wl_role_info_v2 role_info_v2;
 struct rtw89_btc_wl_role_info_v7 role_info_v7;
 struct rtw89_btc_wl_role_info_v8 role_info_v8;
};
struct rtw89_btc_bt_info{struct{bool now,last;}enable;bool mbx_avl,whql_test,hi_lna_rx,run_patch_code,scan_rx_low_pri;
 u32 scbd;unsigned btg_type,lna_constrain;
 struct{struct{bool exist;}a2dp_desc;struct{struct{bool connect;}map;}status;}link_info;
 struct{struct{bool run,req;}map;}rfk_info;
};
struct rtw89_btc_cx{struct rtw89_btc_wl_info wl;struct rtw89_btc_bt_info bt;struct{unsigned type;}other;unsigned cnt_bt[512];};
struct rtw89_btc_dm{bool wl_only,bt_only,freerun,freerun_chk;unsigned fddt_train,run_reason,run_action;unsigned cnt_dm[512],cnt_notify[512];struct{struct{bool init,pta_owner;}map;}error;struct{u8 wl_rssi;}trx_info;};
struct rtw89_btc_ver{unsigned fwlrole,fcxctrl;};
struct control{bool igno_bt,always_freerun;};
struct rtw89_btc{struct rtw89_btc_cx cx;struct rtw89_btc_dm dm;const struct rtw89_btc_ver*ver;
 bool manual_ctrl;struct{struct control ctrl,ctrl_v7;}ctrl;struct{u32 cnt_h2c_fail;}fwinfo;};
struct rtw89_dev;
struct chip_ops{void(*btc_set_rfe)(struct rtw89_dev*);void(*btc_init_cfg)(struct rtw89_dev*);};
struct rtw89_chip_info{bool scbd;struct chip_ops*ops;};
struct fixture_hw{void*wiphy;};
struct rtw89_dev{struct rtw89_btc btc;struct rtw89_chip_info*chip;struct fixture_hw*hw;unsigned total_sta_assoc;};
struct rtw89_btc_wl_sta_iter_data {
 struct rtw89_dev *rtwdev;
 u8 busy_all,dir_all,rssi_map_all;
 bool is_sta_change,is_traffic_change;
};
struct ieee80211_sta;
static struct rtw89_btc_wl_sta_iter_data station_sample;
static unsigned station_samples;
static void rtw89_btc_ntfy_wl_sta_iter(void *data,struct ieee80211_sta *sta){}
static void ieee80211_iterate_stations_atomic(struct fixture_hw *hw,
    void (*iter)(void *,struct ieee80211_sta *),void *data){
 struct rtw89_btc_wl_sta_iter_data *out=data;
 ++station_samples;
 out->busy_all=station_sample.busy_all;
 out->dir_all=station_sample.dir_all;
 out->is_sta_change=station_sample.is_sta_change;
 out->is_traffic_change=station_sample.is_traffic_change;
}
static struct{unsigned val;}btc_scanning_map={1};
static u32 scoreboard,observed[7];static unsigned policy,ant,dispatched,common;
static bool pending_wl_busy,applied_wl_busy;
static unsigned role_reports;
static void rtw89_macos_coex_observe(unsigned mode,unsigned flags,unsigned info,unsigned scbd,unsigned failures,unsigned reason,unsigned action){u32 v[]={mode,flags,info,scbd,failures,reason,action};memcpy(observed,v,sizeof(v));}
static u32 _read_scbd(struct rtw89_dev*d){(void)d;return scoreboard;}
static void _update_dm_step(struct rtw89_dev*d,unsigned r){(void)d;(void)r;}
static void _update_btc_state_map(struct rtw89_dev*d){(void)d;}
static bool _check_freerun(struct rtw89_dev*d){(void)d;return false;}
static void _action_wl_off(struct rtw89_dev*d,unsigned mode){(void)d;(void)mode;}
static void _action_common(struct rtw89_dev*d){(void)d;++common;applied_wl_busy=pending_wl_busy;}
static void _set_ant(struct rtw89_dev*d,unsigned x,unsigned y,unsigned a){(void)d;(void)x;(void)y;ant=a;}
static void _set_policy(struct rtw89_dev*d,unsigned p,unsigned a){policy=p;d->btc.dm.run_action=a;}
static void _reset_btc_var(struct rtw89_dev*d,unsigned which){
 if(which==BTC_RESET_ALL){memset(&d->btc.cx,0,sizeof(d->btc.cx));memset(&d->btc.dm,0,sizeof(d->btc.dm));memset(&d->btc.ctrl,0,sizeof(d->btc.ctrl));d->btc.manual_ctrl=false;d->btc.cx.wl.rfk_info.state=BTC_WRFK_STOP;}
 else if(which==BTC_RESET_BTINFO)memset(&d->btc.cx.bt,0,sizeof(d->btc.cx.bt));
}
static bool rtw89_mac_get_ctrl_path(struct rtw89_dev*d){(void)d;return false;}
#define noop(name,args) static void name args {}
static void _write_scbd(struct rtw89_dev*d,u32 v,bool b){
 if(v==BTC_WSCB_WLBUSY)pending_wl_busy=b;
}
noop(_set_init_info,(struct rtw89_dev*d))
noop(_set_wl_tx_power,(struct rtw89_dev*d,unsigned p))
noop(btc_fw_set_monreg,(struct rtw89_dev*d))
noop(rtw89_btc_fw_set_slots,(struct rtw89_dev*d))
static void _fw_set_drv_info(struct rtw89_dev*d,unsigned p){
 if(p==CXDRVINFO_ROLE)++role_reports;
}
static void _run_coex(struct rtw89_dev*,enum btc_reason_and_action);
'''
for i,a in enumerate(actions,1):fixture+=f'static void {a}(struct rtw89_dev*d){{(void)d;dispatched={i};}}\n'
fixture+=f'#define EXPECT_2G {actions.index("_action_wl_2g_sta")+1}\n#define EXPECT_5G {actions.index("_action_wl_5g")+1}\n'+observe+off+score+run+init+sta_only+r'''
static void rfe(struct rtw89_dev*d){(void)d;}
static void init_chip(struct rtw89_dev*d){d->btc.cx.wl.status.map.init_ok=true;}
int main(void){
 struct chip_ops ops={rfe,init_chip};struct rtw89_chip_info chip={true,&ops};
 struct rtw89_btc_ver ver={0,0};struct rtw89_dev d={0};d.chip=&chip;d.btc.ver=&ver;
 // Every start must restore NORMAL, including after an earlier WL/manual state.
 for(unsigned start=0;start<3;start++){
  d.btc.dm.wl_only=true;d.btc.manual_ctrl=true;scoreboard=0;
  rtw89_btc_ntfy_init(&d,BTC_MODE_NORMAL);
  assert(d.btc.cx.wl.coex_mode==BTC_MODE_NORMAL&&!d.btc.dm.wl_only&&!d.btc.manual_ctrl);
  assert(!d.btc.ctrl.ctrl.igno_bt&&(observed[1]&BIT(7)));
  d.btc.cx.wl.role_info.link_mode=BTC_WLINK_2G_STA;
  _run_coex(&d,BTC_RSN_UPDATE_BT_INFO);
  assert(policy==BTC_CXP_OFF_BT&&ant==BTC_ANT_WONLY); // absent BT still gets WLAN-only grants
  // A late BT driver/firmware start is discovered without restarting Wi-Fi.
  scoreboard=BTC_BSCB_ON|BTC_BSCB_ACT|BTC_BSCB_PATCH_CODE|BTC_BSCB_BT_CONNECT;
  dispatched=0;_update_bt_scbd(&d,false);
  assert(d.btc.cx.bt.enable.now&&d.btc.cx.bt.mbx_avl&&d.btc.cx.bt.run_patch_code);
  assert(dispatched==EXPECT_2G&&d.btc.dm.run_reason==BTC_RSN_UPDATE_BT_SCBD&&!d.btc.dm.wl_only);
  d.btc.cx.wl.role_info.link_mode=BTC_WLINK_5G;
  _run_coex(&d,BTC_RSN_UPDATE_BT_INFO);assert(dispatched==EXPECT_5G);
  d.btc.cx.wl.role_info.link_mode=BTC_WLINK_2G_STA;
  assert((observed[1]&7)==7&&!(observed[1]&BIT(4)));
  assert(d.btc.cx.cnt_bt[BTC_BCNT_REENABLE]==1);
  _update_bt_scbd(&d,false);assert(d.btc.cx.cnt_bt[BTC_BCNT_REENABLE]==1);
  // Bluetooth off returns the engine to BT-off policy, not a sticky override.
  scoreboard=0;_update_bt_scbd(&d,false);assert(!d.btc.cx.bt.enable.now&&policy==BTC_CXP_OFF_BT);
  // Invalid reads cannot manufacture Bluetooth readiness.
  scoreboard=BTC_SCB_INV_VALUE;_update_bt_scbd(&d,false);assert(!d.btc.cx.bt.enable.now);
 }
 // The 8852C-era role layout also follows BT availability dynamically.
 ver.fwlrole=2;scoreboard=0;rtw89_btc_ntfy_init(&d,BTC_MODE_NORMAL);
 d.btc.cx.wl.role_info_v2.link_mode=BTC_WLINK_2G_STA;
 scoreboard=BTC_BSCB_ON|BTC_BSCB_ACT|BTC_BSCB_PATCH_CODE;
 _update_bt_scbd(&d,false);assert(dispatched==EXPECT_2G);
 // A scoreboard event with only A2DP changing must refresh the policy.
 dispatched=0;scoreboard|=BTC_BSCB_A2DP_ACT;_update_bt_scbd(&d,false);
 assert(d.btc.cx.bt.link_info.a2dp_desc.exist&&dispatched==EXPECT_2G);
 dispatched=0;_update_bt_scbd(&d,false);assert(dispatched==0);
 scoreboard&=~BTC_BSCB_A2DP_ACT;_update_bt_scbd(&d,false);
 assert(!d.btc.cx.bt.link_info.a2dp_desc.exist&&dispatched==EXPECT_2G);
 // Update-only callers can refresh the cached profile without re-entering coex.
 dispatched=0;scoreboard|=BTC_BSCB_A2DP_ACT;_update_bt_scbd(&d,true);
 assert(d.btc.cx.bt.link_info.a2dp_desc.exist&&dispatched==0);
 // New firmware control/layout version follows the same automatic lifecycle.
 ver.fcxctrl=7;ver.fwlrole=7;scoreboard=BTC_BSCB_ON|BTC_BSCB_PATCH_CODE|BTC_BSCB_ACT;
 rtw89_btc_ntfy_init(&d,BTC_MODE_NORMAL);assert(!d.btc.ctrl.ctrl_v7.igno_bt&&!d.btc.dm.wl_only);
 // The same decision that makes Wi-Fi busy must publish the new scoreboard bit.
 ver.fcxctrl=1;ver.fwlrole=1;
 rtw89_btc_ntfy_init(&d,BTC_MODE_NORMAL);
 d.btc.cx.wl.role_info_v1.link_mode=BTC_WLINK_2G_STA;
 station_sample.busy_all=1;
 station_sample.dir_all=BIT(RTW89_TFC_UL);
 station_sample.is_sta_change=true;
 rtw89_btc_ntfy_wl_sta(&d);
 assert(d.btc.cx.wl.status.map.busy && applied_wl_busy);
 station_sample.busy_all=0;
 rtw89_btc_ntfy_wl_sta(&d);
 assert(!d.btc.cx.wl.status.map.busy && !applied_wl_busy);

#ifdef HAS_TRAFFIC_ONLY_NOTIFY
 d.total_sta_assoc=1;
 d.btc.cx.bt.link_info.a2dp_desc.exist=true;
 station_sample.busy_all=1;
 station_sample.is_traffic_change=true;
 unsigned runs=common,reports=role_reports,samples=station_samples;
 d.btc.cx.wl.status.map._4way=true;
 rtw89_btc_ntfy_wl_traffic(&d);
 assert(station_samples==samples);
 d.btc.cx.wl.status.map._4way=false;
 rtw89_btc_ntfy_wl_traffic(&d);
 assert(common==runs+1 && applied_wl_busy && (observed[1]&BIT(8)));
 assert((observed[1]&BIT(9)) && !(observed[1]&BIT(10)));
 rtw89_btc_ntfy_wl_traffic(&d);
 assert(common==runs+1);
 station_sample.dir_all=BIT(RTW89_TFC_DL);
 rtw89_btc_ntfy_wl_traffic(&d);
 assert(common==runs+2 && applied_wl_busy && (observed[1]&BIT(10)));
 station_sample.busy_all=0;
 rtw89_btc_ntfy_wl_traffic(&d);
 assert(common==runs+3 && !applied_wl_busy && !(observed[1]&(BIT(8)|BIT(10))));
 assert(role_reports==reports);
#endif
}
'''
# A source guard catches reintroduction of the frontend override/start latch.
bridge=(root/'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text(encoding='utf-8')
core=(root/'rtw/hal_rtw89/driver/core.c').read_text(encoding='utf-8')
donor=(root/'rtw/hal_rtw89/driver/Senmiko.c').read_text(encoding='utf-8')
assert 'rtw88_force_wifi_only(' not in bridge and 'airportrtw_wifi_only' not in donor
assert 'rtw89_btc_ntfy_init(rtwdev, BTC_MODE_NORMAL);' in core
with tempfile.TemporaryDirectory(prefix='rtw89-btc-')as tmp:
 p=Path(tmp)/'test.c';p.write_text(fixture)
 if sys.platform=='win32':
  exe=Path(tmp)/'test.exe'
  subprocess.run(['cl','/nologo','/std:c11','/WX',str(p),f'/Fe:{exe}'],cwd=tmp,check=True)
 else:
  exe=Path(tmp)/'test'
  subprocess.run(['xcrun','clang','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: BTC startup, A2DP scoreboard edges and Wi-Fi busy/direction dispatch')
