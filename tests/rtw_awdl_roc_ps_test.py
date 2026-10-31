#!/usr/bin/env python3
"""Run real RTW89 ROC admission code with deterministic radio/TX adapters."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
core=(ROOT/'rtw/hal_rtw89/driver/core.c').read_text()
code=core[core.index('static int rtw89_roc_station_ps('):core.index('void rtw89_roc_work(')]
shim=r'''
#include <cassert>
#include <vector>
#include <utility>
#include <cstdio>
using u32=unsigned;
#include <cerrno>
#define NL80211_IFTYPE_STATION 1
#define NL80211_IFTYPE_ADHOC 2
#define RTW89_ROC_IDLE 0
#define RTW89_ROC_NORMAL 2
#define RTW89_ROC_TX_TIMEOUT 20
#define RTW89_CHANCTX_PAUSE_REASON_ROC 1
#define NL80211_CHAN_NO_HT 0
#define B_AX_A_UC_CAM_MATCH 1
#define B_AX_A_BC_CAM_MATCH 2
#define IEEE80211_CONF_IDLE 1
#define RTW89_ROC_IDLE_TIMEOUT 10
#define RTW89_DBG_TXRX 0
#define unlikely(x) (x)
#define lockdep_assert_wiphy(x) ((void)(x))
#define rtw89_err(...) ((void)0)
#define rtw89_debug(...) ((void)0)
#define rtw89_for_each_rtwvif(dev,vif) \
    for(unsigned vi=0;vi<(dev)->vifs.size() && (((vif)=(dev)->vifs[vi]),true);++vi)
#define rtw89_vif_for_each_link(vif,link,index) \
    for((index)=0;(index)<(vif)->links.size();++(index)) \
        if(((link)=(vif)->links[index]))
struct rtw89_vif_link { unsigned chanctx_idx=0,link_id=0,mac_idx=0,id=0; };
struct rtw89_roc { int state=RTW89_ROC_NORMAL,chan=6,duration=50,roc_work=0;unsigned link_id=0; };
struct ieee80211_vif { unsigned type=NL80211_IFTYPE_STATION;struct{bool assoc=true;}cfg; };
struct rtw89_vif { ieee80211_vif native;std::vector<rtw89_vif_link*>links;bool offchan=false;rtw89_roc roc; };
struct ieee80211_hw { int *wiphy=nullptr;struct{unsigned flags=0;}conf; };
struct rtw89_mac_gen_def { unsigned rx_fltr=0; };
struct Chip { rtw89_mac_gen_def *mac_def; };
struct rtw89_dev { Chip *chip;ieee80211_hw *hw;std::vector<rtw89_vif*>vifs;struct{unsigned rx_fltr=0;}hal;int txq_wq=0,txq_work=0; };
struct rtw89_chanctx_pause_parm { unsigned rsn;rtw89_vif_link *trigger=nullptr; };
struct cfg80211_chan_def { int value; };
static std::vector<std::pair<unsigned,bool>>sent;
static unsigned expiries=0;
static unsigned failSleep=999,failWake=999,pauses=0,resumes=0,retunes=0,ready=0,queued=0;
static ieee80211_vif *rtwvif_to_vif(rtw89_vif *v){return &v->native;}
static int rtw89_core_send_nullfunc(rtw89_dev*,rtw89_vif_link*l,bool qos,bool ps,int){
    assert(qos);sent.push_back({l->id,ps});return l->id==(ps?failSleep:failWake)?-7:0;
}
static void rtw89_leave_ips_by_hwflags(rtw89_dev*){}
static void rtw89_leave_lps(rtw89_dev*){}
static rtw89_vif_link *rtw89_get_designated_link(rtw89_vif*v){return v->links.empty()?nullptr:v->links[0];}
static void rtw89_chanctx_pause(rtw89_dev*,rtw89_chanctx_pause_parm*){++pauses;}
static void rtw89_chanctx_proceed(rtw89_dev*,void*){++resumes;}
static void cfg80211_chandef_create(cfg80211_chan_def*,int*,int){}
static void rtw89_config_roc_chandef(rtw89_dev*,rtw89_vif_link*,cfg80211_chan_def*){}
static int rtw89_set_channel(rtw89_dev*){++retunes;return 0;}
static unsigned rtw89_mac_reg_by_idx(rtw89_dev*,unsigned,unsigned){return 0;}
static void rtw89_write32_clr(rtw89_dev*,unsigned,unsigned){}
static void ieee80211_ready_on_channel(ieee80211_hw*){++ready;}
static void wiphy_delayed_work_cancel(int*,int*){}
static unsigned msecs_to_jiffies(unsigned n){return n;}
static void wiphy_delayed_work_queue(int*,int*,unsigned){++queued;}
static void ieee80211_remain_on_channel_expired(ieee80211_hw*){assert(resumes && !sent.empty() && !sent.back().second);++expiries;}
static void rtw89_mac_set_rx_fltr(rtw89_dev*,unsigned,unsigned){}
static void rtw89_core_handle_sta_pending_tx(rtw89_dev*,rtw89_vif_link*){}
static void queue_work(int,int*){}
'''
cases=r'''
int main(){
    rtw89_mac_gen_def mac{};Chip chip{&mac};ieee80211_hw hw{};
    rtw89_vif_link primaryLink{0,0,0,1},secondaryLink{0,0,0,2},otherLink{1,0,0,3},extraLink{0,0,0,4};
    rtw89_vif primary,secondary,other,extra,disconnected;
    primary.links={&primaryLink};secondary.links={&secondaryLink};other.links={&otherLink};
    extra.links={&extraLink};disconnected.links={&extraLink};disconnected.native.cfg.assoc=false;
    secondary.native.type=NL80211_IFTYPE_ADHOC;
    primary.roc.state=other.roc.state=extra.roc.state=disconnected.roc.state=RTW89_ROC_IDLE;
    rtw89_dev dev{};dev.chip=&chip;dev.hw=&hw;
    dev.vifs={&primary,&secondary,&other,&extra,&disconnected};
    assert(!rtw89_roc_start(&dev,&secondary));
    assert(sent.size()==2 && sent[0]==std::make_pair(1U,true) && sent[1]==std::make_pair(4U,true));
    assert(retunes==1 && ready==1 && queued==1);
    assert(primary.offchan && secondary.offchan && extra.offchan && !other.offchan);
    sent.clear();rtw89_roc_end(&dev,&secondary);
    assert(sent.size()==2 && sent[0]==std::make_pair(1U,false) && sent[1]==std::make_pair(4U,false));
    assert(!primary.offchan && !secondary.offchan && !extra.offchan && expiries==1);
    // A failed AP notification must not retune or announce a grant. All
    // previously notified stations are woken, even if one wake attempt fails.
    sent.clear();failSleep=4;failWake=1;secondary.roc.state=RTW89_ROC_NORMAL;
    assert(rtw89_roc_start(&dev,&secondary)==-7);
    assert(retunes==1 && ready==1 && queued==1);
    assert(sent.size()==4 && sent[2]==std::make_pair(1U,false) && sent[3]==std::make_pair(4U,false));
    assert(secondary.roc.state==RTW89_ROC_IDLE && !primary.offchan && !secondary.offchan);
    assert(pauses==2 && resumes==2);
    // Linkless requests fail before pausing or notifying any station.
    sent.clear();secondary.links.clear();secondary.roc.state=RTW89_ROC_NORMAL;
    assert(rtw89_roc_start(&dev,&secondary)==-ENOLINK && sent.empty());
    assert(pauses==2 && secondary.roc.state==RTW89_ROC_IDLE);
    // Another live ROC must not be overwritten by this request.
    primary.roc.state=RTW89_ROC_NORMAL;
    secondary.roc.state=RTW89_ROC_NORMAL;secondary.links={&secondaryLink};
    assert(rtw89_roc_start(&dev,&secondary)==-EBUSY && sent.empty() && pauses==2);
    assert(primary.roc.state==RTW89_ROC_NORMAL);
    primary.roc.state=RTW89_ROC_IDLE;
    // A broken associated-station link cannot silently pass PM admission.
    failSleep=failWake=999;primary.links.clear();
    assert(rtw89_roc_start(&dev,&secondary)==-ENOLINK && ready==1 && retunes==1);
    primary.links={&primaryLink};sent.clear();
    // An unassociated radio does not fabricate a station PM handshake.
    primary.native.cfg.assoc=false;extra.native.cfg.assoc=false;
    secondary.links={&secondaryLink};failSleep=failWake=999;
    assert(!rtw89_roc_start(&dev,&secondary) && sent.empty() && ready==2);
    puts("PASS: RTW89 secondary ROC uses real associated stations and rejects failed PS admission");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-roc-ps-') as tmp:
    source=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    source.write_text(shim+code+cases)
    subprocess.run(['xcrun','clang++','-std=c++20','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-fsanitize=address,undefined',str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
