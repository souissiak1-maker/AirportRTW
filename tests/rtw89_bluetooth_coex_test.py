#!/usr/bin/env python3
"""Execute the production BTC init, scoreboard updates and policy dispatcher."""
from pathlib import Path
import re,subprocess,tempfile
root=Path(__file__).resolve().parents[1];coex=(root/'rtw/hal_rtw89/driver/coex.c').read_text()
def function(signature):
 a=coex.index(signature);return coex[a:coex.index('\n}',a)+3]
init=function('void rtw89_btc_ntfy_init(struct')
run=function('void _run_coex(struct rtw89_dev *rtwdev, enum btc_reason_and_action reason)\n{')
score=function('static void _update_bt_scbd(struct rtw89_dev *rtwdev, bool only_update)\n{')
off=function('static void _action_bt_off(struct')
observe=function('static void airportrtw_btc_observe(struct')
combined=init+run+score+off+observe
constants=sorted(set(re.findall(r'\bBTC_\w+\b',combined))|{'BTC_MODE_NORMAL','BTC_MODE_WL','BTC_MODE_BT'})
scorebits={n:v for n,v in re.findall(r'\b(BTC_BSCB_\w+)\s*=\s*BIT\((\d+)\)',coex)}
defines=''
for i,n in enumerate(constants,1):
 if n in scorebits:defines+=f'#define {n} BIT({scorebits[n]})\n'
 elif n=='BTC_SCB_INV_VALUE':defines+='#define BTC_SCB_INV_VALUE UINT32_MAX\n'
 else:defines+=f'#define {n} {i}\n'
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
#define RTW89_TFC_DL 1
#define FC_EXEC 1
#define CXDRVINFO_INIT 1
#define CXDRVINFO_CTRL 2
#define RTW89_BTC_WL_DEF_TX_PWR 0
'''+defines+r'''
enum btc_reason_and_action{unused_reason};
struct status_bits{bool rf_off,rf_off_pre,init_ok,scan;unsigned lps,lps_pre,traffic_dir;};
struct wl_status{struct status_bits map;unsigned val;};
struct rtw89_btc_wl_role_info{u8 link_mode;};
struct rtw89_btc_wl_role_info_v1{u8 link_mode;};
struct rtw89_btc_wl_role_info_v2{u8 link_mode;};
struct rtw89_btc_wl_role_info_v7{u8 link_mode;};
struct rtw89_btc_wl_role_info_v8{u8 link_mode;};
struct rtw89_btc_wl_info{u8 coex_mode;struct wl_status status;
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
struct rtw89_btc_dm{bool wl_only,bt_only,freerun,freerun_chk;unsigned fddt_train,run_reason,run_action;unsigned cnt_dm[512],cnt_notify[512];struct{struct{bool init,pta_owner;}map;}error;};
struct rtw89_btc_ver{unsigned fwlrole,fcxctrl;};
struct control{bool igno_bt,always_freerun;};
struct rtw89_btc{struct rtw89_btc_cx cx;struct rtw89_btc_dm dm;const struct rtw89_btc_ver*ver;
 bool manual_ctrl;struct{struct control ctrl,ctrl_v7;}ctrl;struct{u32 cnt_h2c_fail;}fwinfo;};
struct rtw89_dev;
struct chip_ops{void(*btc_set_rfe)(struct rtw89_dev*);void(*btc_init_cfg)(struct rtw89_dev*);};
struct rtw89_chip_info{bool scbd;struct chip_ops*ops;};
struct rtw89_dev{struct rtw89_btc btc;struct rtw89_chip_info*chip;struct{void*wiphy;}*hw;};
static struct{unsigned val;}btc_scanning_map={1};
static u32 scoreboard,observed[7];static unsigned policy,ant,dispatched,common;
static void rtw89_macos_coex_observe(unsigned mode,unsigned flags,unsigned info,unsigned scbd,unsigned failures,unsigned reason,unsigned action){u32 v[]={mode,flags,info,scbd,failures,reason,action};memcpy(observed,v,sizeof(v));}
static u32 _read_scbd(struct rtw89_dev*d){(void)d;return scoreboard;}
static void _update_dm_step(struct rtw89_dev*d,unsigned r){(void)d;(void)r;}
static void _update_btc_state_map(struct rtw89_dev*d){(void)d;}
static bool _check_freerun(struct rtw89_dev*d){(void)d;return false;}
static void _action_wl_off(struct rtw89_dev*d,unsigned mode){(void)d;(void)mode;}
static void _action_common(struct rtw89_dev*d){(void)d;++common;}
static void _set_ant(struct rtw89_dev*d,unsigned x,unsigned y,unsigned a){(void)d;(void)x;(void)y;ant=a;}
static void _set_policy(struct rtw89_dev*d,unsigned p,unsigned a){policy=p;d->btc.dm.run_action=a;}
static void _reset_btc_var(struct rtw89_dev*d,unsigned which){
 if(which==BTC_RESET_ALL){memset(&d->btc.cx,0,sizeof(d->btc.cx));memset(&d->btc.dm,0,sizeof(d->btc.dm));memset(&d->btc.ctrl,0,sizeof(d->btc.ctrl));d->btc.manual_ctrl=false;d->btc.cx.wl.rfk_info.state=BTC_WRFK_STOP;}
 else if(which==BTC_RESET_BTINFO)memset(&d->btc.cx.bt,0,sizeof(d->btc.cx.bt));
}
static bool rtw89_mac_get_ctrl_path(struct rtw89_dev*d){(void)d;return false;}
#define noop(name,args) static void name args {}
noop(_write_scbd,(struct rtw89_dev*d,u32 v,bool b))
noop(_set_init_info,(struct rtw89_dev*d))
noop(_set_wl_tx_power,(struct rtw89_dev*d,unsigned p))
noop(btc_fw_set_monreg,(struct rtw89_dev*d))
noop(rtw89_btc_fw_set_slots,(struct rtw89_dev*d))
noop(_fw_set_drv_info,(struct rtw89_dev*d,unsigned p))
static void _run_coex(struct rtw89_dev*,enum btc_reason_and_action);
'''
for i,a in enumerate(actions,1):fixture+=f'static void {a}(struct rtw89_dev*d){{(void)d;dispatched={i};}}\n'
fixture+=f'#define EXPECT_2G {actions.index("_action_wl_2g_sta")+1}\n#define EXPECT_5G {actions.index("_action_wl_5g")+1}\n'+observe+off+score+run+init+r'''
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
 // New firmware control/layout version follows the same automatic lifecycle.
 ver.fcxctrl=7;ver.fwlrole=7;scoreboard=BTC_BSCB_ON|BTC_BSCB_PATCH_CODE|BTC_BSCB_ACT;
 rtw89_btc_ntfy_init(&d,BTC_MODE_NORMAL);assert(!d.btc.ctrl.ctrl_v7.igno_bt&&!d.btc.dm.wl_only);
}
'''
# A source guard catches reintroduction of the frontend override/start latch.
bridge=(root/'rtw/hal_rtw89/Rtw89LinuxBridge.cpp').read_text();core=(root/'rtw/hal_rtw89/driver/core.c').read_text();donor=(root/'rtw/hal_rtw89/driver/Senmiko.c').read_text()
assert 'rtw88_force_wifi_only(' not in bridge and 'airportrtw_wifi_only' not in donor
assert 'rtw89_btc_ntfy_init(rtwdev, BTC_MODE_NORMAL);' in core
with tempfile.TemporaryDirectory(prefix='rtw89-btc-')as tmp:
 p=Path(tmp)/'test.c';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: production BTC init/dispatcher, BT absent/off, late firmware, invalid scoreboard and repeated starts')
