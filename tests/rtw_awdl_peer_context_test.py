#!/usr/bin/env python3
"""Execute the production RTW89 address/BSSID ownership selectors."""
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'rtw/hal_rtw89/driver/core.h').read_text()
a=source.index('static inline bool rtw89_vif_has_peer_context(')
b=source.index('static inline\nvoid rtw89_chip_set_channel_prepare(',a)
selectors=source[a:b]
shim=r'''
#include <cassert>
#include <initializer_list>
enum { NL80211_IFTYPE_AP,NL80211_IFTYPE_STATION,NL80211_IFTYPE_ADHOC,
       NL80211_IFTYPE_MONITOR,RTW89_NET_TYPE_AP_MODE=7 };
struct ieee80211_vif { unsigned type; bool no_beacon; };
struct ieee80211_sta { bool tdls; };
struct rtw89_addr_cam_entry {};
struct rtw89_bssid_cam_entry {};
struct rtw89_vif_link { ieee80211_vif vif; unsigned net_type; rtw89_addr_cam_entry addr_cam; rtw89_bssid_cam_entry bssid_cam; };
struct rtw89_sta_link { ieee80211_sta sta; rtw89_addr_cam_entry addr_cam; rtw89_bssid_cam_entry bssid_cam; };
static ieee80211_vif *rtwvif_link_to_vif(rtw89_vif_link *p) { return &p->vif; }
static ieee80211_sta *rtwsta_link_to_sta(rtw89_sta_link *p) { return &p->sta; }
'''
cases=r'''
int main() {
    // Preserve address selection for any existing AP-mode role, including mesh.
    rtw89_vif_link legacy={{NL80211_IFTYPE_MONITOR,false},RTW89_NET_TYPE_AP_MODE,{},{}};
    rtw89_sta_link legacyPeer={{false},{},{}};
    assert(rtw89_get_addr_cam_of(&legacy,&legacyPeer)==&legacyPeer.addr_cam);

    for(unsigned type : {NL80211_IFTYPE_AP,NL80211_IFTYPE_STATION,
                         NL80211_IFTYPE_ADHOC,NL80211_IFTYPE_MONITOR})
        for(bool quiet : {false,true}) for(bool tdls : {false,true}) {
            rtw89_vif_link vif={{type,quiet},type==NL80211_IFTYPE_AP?RTW89_NET_TYPE_AP_MODE:0U,{},{}};
            rtw89_sta_link peer={{tdls},{},{}};
            assert(rtw89_vif_has_peer_context(&vif.vif)==
                (type==NL80211_IFTYPE_AP || (type==NL80211_IFTYPE_ADHOC && quiet)));
            const bool remote=(type==NL80211_IFTYPE_AP ||
                (type==NL80211_IFTYPE_ADHOC && quiet) || tdls);
            assert(rtw89_get_addr_cam_of(&vif,&peer)==(remote?&peer.addr_cam:&vif.addr_cam));
            assert(rtw89_get_bssid_cam_of(&vif,&peer)==(tdls?&peer.bssid_cam:&vif.bssid_cam));
            assert(rtw89_get_addr_cam_of(&vif,nullptr)==&vif.addr_cam);
            assert(rtw89_get_bssid_cam_of(&vif,nullptr)==&vif.bssid_cam);
        }
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-peer-') as tmp:
    path=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    path.write_text(shim+selectors+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined',str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PASS: production RTW89 peer address CAM / shared BSSID CAM ownership')
