#!/usr/bin/env python3
"""Run RTW88 country helpers against the production regulatory state machine."""
from pathlib import Path
import re,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
hardware=(root/'rtw/hal_rtw88/Rtw88Hardware.c').read_text()
start=hardware.index('static bool country_known(');helpers=hardware[start:hardware.index('unsigned rtw88_hw_get_nss(',start)]
reg=(root/'rtw/hal_rtw88/driver/regd.c').read_text()
start=reg.index('static bool rtw_regd_mgmt_worldwide(');state=reg[start:reg.index('u8 rtw_regd_get(',start)]
codes=(root/'rtw/hal_rtw88/Rtw88CountryCodes.h').read_text()
assert re.findall(r'"([A-Z]{2})"',codes)==re.findall(r'COUNTRY_REGD_ENT\("([A-Z]{2})"',reg)
fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define REGULATORY_COUNTRY_IE_IGNORE 4
#define NL80211_REGDOM_SET_BY_CORE 0
#define NL80211_REGDOM_SET_BY_USER 1
#define NL80211_REGDOM_SET_BY_DRIVER 2
#define NL80211_REGDOM_SET_BY_COUNTRY_IE 3
#define NL80211_DFS_UNSET 0
#define RTW_DBG_REGD 0
#define rtw_dbg(...) ((void)0)
#define rtw_dbg_regd_dump(...) ((void)0)
enum {RTW_REGD_STATE_WORLDWIDE,RTW_REGD_STATE_PROGRAMMED,RTW_REGD_STATE_SETTING,RTW_REGD_STATE_NR};
struct rtw_regulatory {char alpha2[2];};
struct regulatory_request {char alpha2[3];int initiator,dfs_region;};
struct wiphy {unsigned regulatory_flags;void (*reg_notifier)(struct wiphy*,struct regulatory_request*);};
struct ieee80211_hw {struct wiphy*wiphy;void*priv;};
struct rtw_regd {int state;const struct rtw_regulatory*regulatory;int dfs_region;};
struct rtw_hal {int current_channel;};
struct rtw_dev {struct ieee80211_hw*hw;struct rtw_regd regd;struct {char country_code[2];} efuse;struct rtw_hal hal;int mutex;};
static struct rtw_regulatory world={{'0','0'}},tn={{'T','N'}},fr={{'F','R'}};
static struct ieee80211_hw *active;
static struct ieee80211_hw*wiphy_to_ieee80211_hw(struct wiphy*w){assert(active->wiphy==w);return active;}
static bool rtw_reg_is_ww(const struct rtw_regulatory*r){return r==&world;}
static bool rtw_reg_match(const struct rtw_regulatory*r,const char*c){return !memcmp(r->alpha2,c,2);}
static const struct rtw_regulatory*rtw_reg_find_by_name(const char*c){if(!memcmp(c,"TN",2))return &tn;if(!memcmp(c,"FR",2))return &fr;return &world;}
static void mutex_lock(int*m){assert(!*m);*m=1;}
static void mutex_unlock(int*m){assert(*m);*m=0;}
static void rtw_phy_adaptivity_set_mode(struct rtw_dev*d){assert(d->mutex);}
static void rtw_phy_set_tx_power_level(struct rtw_dev*d,int c){(void)c;assert(d->mutex);}
'''+codes+state+helpers+r'''
int main(void){
 struct rtw_dev dev={0};struct wiphy w={0,rtw_regd_notifier};
 struct ieee80211_hw hw={&w,&dev};dev.hw=&hw;active=&hw;dev.regd.regulatory=&world;
 assert(!airportrtw88_apply_country(NULL,"TN",1));
 assert(!airportrtw88_apply_country(&hw,"xx",1));
 assert(!airportrtw88_apply_country(&hw,"ZZ",2));
 assert(airportrtw88_apply_country(&hw,"TN",1));assert(dev.regd.regulatory==&tn);
 assert(dev.regd.state==RTW_REGD_STATE_WORLDWIDE);
 assert(airportrtw88_apply_country(&hw,NULL,0));assert(dev.regd.regulatory==&world);
 assert(airportrtw88_apply_country(&hw,"TN",2));assert(dev.regd.state==RTW_REGD_STATE_SETTING);
 assert(w.regulatory_flags&REGULATORY_COUNTRY_IE_IGNORE);
 assert(!airportrtw88_apply_country(&hw,"FR",1));assert(!airportrtw88_apply_country(&hw,NULL,0));
 assert(dev.regd.regulatory==&tn);
 assert(airportrtw88_apply_country(&hw,"FR",2));assert(dev.regd.regulatory==&fr);
 dev.regd.state=RTW_REGD_STATE_PROGRAMMED;dev.regd.regulatory=&world;
 memcpy(dev.efuse.country_code,"TN",2);
 assert(!airportrtw88_apply_country(&hw,"FR",2));
 assert(!airportrtw88_apply_country(&hw,"TN",1));
 airportrtw88_init_country(&hw);assert(dev.regd.regulatory==&tn);
 assert(airportrtw88_apply_country(&hw,"TN",2));
 assert(!airportrtw88_apply_country(&hw,"FR",2));assert(dev.regd.regulatory==&tn);
 assert(airportrtw88_apply_driver_hint(&w,"ZZ")==-EINVAL);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.c';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: RTW88 production country state machine, AP/reset, OS priority and programmed domains')
