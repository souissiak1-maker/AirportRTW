#!/usr/bin/env python3
"""Execute actual quiet-ADHOC station-add ownership and retained-state query."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
def extract(s,start):
    a=s.index(start);b=s.index('{',a);depth=1;end=b+1
    while depth:
        depth+=(s[end]=='{')-(s[end]=='}');end+=1
    return s[a:end]+'\n'
source=extract((ROOT/'rtw/hal_rtw89/driver/mac80211.c').read_text(),'static int __rtw89_ops_sta_add(')
query=extract((ROOT/'rtw/hal_rtw89/driver/Senmiko.c').read_text(),'bool rtw89_macos_awdl_peer_retained(')
query+=extract((ROOT/'rtw/hal_rtw89/driver/Senmiko.c').read_text(),'unsigned int rtw89_macos_awdl_peer_capacity(')
shim=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <initializer_list>
#include <cstdio>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define INIT_LIST_HEAD(p) (*(p)=0)
using u8=uint8_t;
constexpr unsigned IEEE80211_MLD_MAX_NUM_LINKS=16,RTW89_MAX_MAC_ID_NUM=128,
 RTW89_MAX_SEC_CAM_NUM=128,RTW89_MLO_MODE_MLSR=1,RTW89_CHANCTX_REMOTE_STA_CHANGE=1;
enum{NL80211_IFTYPE_STATION,NL80211_IFTYPE_AP,NL80211_IFTYPE_ADHOC};
struct Chip{unsigned support_macid_num,support_link_num;};
struct rtw89_dev{const Chip*chip=nullptr;bool support_mlo=false;};
struct ieee80211_hw{void*priv;};
static rtw89_dev*to_rtw89(void*p){return static_cast<rtw89_dev*>(p);}
struct rtw89_vif{unsigned mlo_mode;};
struct ieee80211_vif{int type;bool no_beacon;rtw89_vif priv;};
struct rtw89_vif_link{};
struct rtw89_sta_link{rtw89_vif_link*rtwvif_link;bool awdl_role_pending;};
struct rtw89_sta{int dlink_pool,roc_queue,pairwise_sec_cam_map[4];rtw89_sta_link*links[16];};
struct ieee80211_sta{bool tdls;void*txq[16];struct{unsigned link_id;}deflink;rtw89_sta priv;};
static rtw89_vif_link vifLink;
static rtw89_sta_link peerLink;
static unsigned acquired,released,unsets,inits,changes;
static int addError;
static bool pending,failMac,failLink;
static rtw89_vif*vif_to_rtwvif(ieee80211_vif*v){return &v->priv;}
static rtw89_sta*sta_to_rtwsta(ieee80211_sta*s){return &s->priv;}
static u8 rtw89_vif_get_main_macid(rtw89_vif*){return 3;}
static u8 rtw89_acquire_mac_id(rtw89_dev*){++acquired;return failMac?RTW89_MAX_MAC_ID_NUM:5;}
static void rtw89_release_mac_id(rtw89_dev*,u8){++released;}
static void rtw89_init_sta(rtw89_dev*,rtw89_vif*,rtw89_sta*,u8){++inits;}
static void rtw89_core_txq_init(rtw89_dev*,void*){}
static void skb_queue_head_init(int*p){*p=0;}
static void bitmap_zero(int*p,unsigned){*p=0;}
static rtw89_sta_link*rtw89_sta_set_link(rtw89_sta*s,unsigned id){
 if(failLink)return nullptr;peerLink={&vifLink,false};return s->links[id]=&peerLink;
}
static void rtw89_sta_unset_link(rtw89_sta*s,unsigned id){++unsets;s->links[id]=nullptr;}
static int rtw89_core_sta_link_add(rtw89_dev*,rtw89_vif_link*,rtw89_sta_link*s){s->awdl_role_pending=pending;return addError;}
static bool rtw89_vif_has_peer_context(ieee80211_vif*v){return v->type==NL80211_IFTYPE_AP||(v->type==NL80211_IFTYPE_ADHOC&&v->no_beacon);}
static void rtw89_queue_chanctx_change(rtw89_dev*,unsigned){++changes;}
static void reset(){acquired=released=unsets=inits=changes=0;addError=0;pending=failMac=failLink=false;}
'''
cases=r'''
int main(){
 rtw89_dev dev;
 for(int type:{NL80211_IFTYPE_STATION,NL80211_IFTYPE_AP,NL80211_IFTYPE_ADHOC})
 for(bool quiet:{false,true})for(bool tdls:{false,true})for(bool owesRemove:{false,true}){
  reset();ieee80211_vif vif{type,quiet,{}};ieee80211_sta sta{};sta.tdls=tdls;
  addError=-42;pending=owesRemove;
  assert(__rtw89_ops_sta_add(&dev,&vif,&sta)==-42);
  bool retained=type==NL80211_IFTYPE_ADHOC&&quiet&&!tdls&&owesRemove;
  assert(rtw89_macos_awdl_peer_retained(&vif,&sta)==retained);
  assert(unsets==unsigned(!retained));
  bool ownMac=type!=NL80211_IFTYPE_STATION||tdls;
  assert(released==unsigned(ownMac&&!retained));
  assert(acquired==unsigned(ownMac)&&!changes);
  if(retained){
   assert(__rtw89_ops_sta_add(&dev,&vif,&sta)==-EBUSY);
   assert(acquired==1&&inits==1&&!released&&!unsets);
  }
 }
 {reset();ieee80211_vif vif{NL80211_IFTYPE_ADHOC,true,{}};ieee80211_sta sta{};
  pending=true;assert(!__rtw89_ops_sta_add(&dev,&vif,&sta));
  assert(rtw89_macos_awdl_peer_retained(&vif,&sta)&&changes==1&&!released&&!unsets);
  assert(__rtw89_ops_sta_add(&dev,&vif,&sta)==-EBUSY);
  assert(acquired==1&&inits==1&&changes==1&&!released&&!unsets);
  rtw89_sta_unset_link(&sta.priv,0);assert(!rtw89_macos_awdl_peer_retained(&vif,&sta));}
 {reset();ieee80211_vif vif{NL80211_IFTYPE_ADHOC,true,{}};ieee80211_sta sta{};
  failMac=true;assert(__rtw89_ops_sta_add(&dev,&vif,&sta)==-ENOSPC);
  assert(!rtw89_macos_awdl_peer_retained(&vif,&sta)&&!released&&!inits);}
 {reset();ieee80211_vif vif{NL80211_IFTYPE_ADHOC,true,{}};ieee80211_sta sta{};
  failLink=true;assert(__rtw89_ops_sta_add(&dev,&vif,&sta)==-EINVAL);
  assert(!rtw89_macos_awdl_peer_retained(&vif,&sta)&&released==1&&!unsets);}
 assert(!rtw89_macos_awdl_peer_retained(nullptr,nullptr));
 assert(!rtw89_macos_awdl_peer_capacity(nullptr));ieee80211_hw hw{nullptr};
 assert(!rtw89_macos_awdl_peer_capacity(&hw));hw.priv=&dev;
 assert(!rtw89_macos_awdl_peer_capacity(&hw));
 struct CapacityCase{unsigned ids,links;bool mlo;unsigned expected;};
 for(auto row:{CapacityCase{32,2,true,14},CapacityCase{128,2,true,16},
              CapacityCase{16,2,true,6},CapacityCase{3,1,false,1},
              CapacityCase{2,1,false,0},CapacityCase{16,0,true,0},
              CapacityCase{0,2,true,0},CapacityCase{32,0,false,16}}){
  Chip chip{row.ids,row.links};dev.chip=&chip;dev.support_mlo=row.mlo;
  assert(rtw89_macos_awdl_peer_capacity(&hw)==row.expected);
 }

 puts("PASS: failed quiet-ADHOC peer add retains link/MAC-ID only when firmware cleanup is owed");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-peer-add-')as tmp:
    cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    cpp.write_text(shim+source+query+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-Wno-sign-compare','-fsanitize=address,undefined',str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
