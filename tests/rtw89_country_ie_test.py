#!/usr/bin/env python3
"""Test the production AP-country helper without touching hardware."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'rtw/hal_rtw89/driver/Senmiko.c').read_text();start=s.index('bool rtw89_macos_country_ie(');fn=s[start:s.index('\n}\n',start)+3]
fixture=r'''
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#define REGULATORY_COUNTRY_IE_IGNORE 4
#define NL80211_REGDOM_SET_BY_COUNTRY_IE 3
#define NL80211_REGDOM_SET_BY_CORE 0
#define NL80211_DFS_UNSET 0
struct regulatory_request {char alpha2[3];int initiator,dfs_region;};
struct wiphy {unsigned regulatory_flags;void (*reg_notifier)(struct wiphy*,struct regulatory_request*);};
struct domain {char alpha2[2];};
struct rtw89_dev {struct {bool programmed;struct {unsigned nr;struct domain *map;} ctrl;} regulatory;};
struct ieee80211_hw {struct wiphy *wiphy;void *priv;};
static int calls;static struct regulatory_request last;
static void notify(struct wiphy*w,struct regulatory_request*r){assert(w);last=*r;calls++;}
'''+fn+r'''
int main(void){
 struct domain map[]={{{'T','N'}}};struct rtw89_dev dev={0};
 struct wiphy w={0,notify};struct ieee80211_hw hw={&w,&dev};
 dev.regulatory.ctrl.nr=1;dev.regulatory.ctrl.map=map;
 assert(!rtw89_macos_country_ie(NULL,(const unsigned char*)"TN"));
 assert(!rtw89_macos_country_ie(&hw,(const unsigned char*)"XX"));
 assert(!rtw89_macos_country_ie(&hw,(const unsigned char*)"tn"));assert(!calls);
 dev.regulatory.programmed=true;
 assert(!rtw89_macos_country_ie(&hw,(const unsigned char*)"TN"));assert(!calls);
 dev.regulatory.programmed=false;w.regulatory_flags=4;
 assert(!rtw89_macos_country_ie(&hw,(const unsigned char*)"TN"));assert(!calls);
 w.regulatory_flags=0;
 assert(rtw89_macos_country_ie(&hw,(const unsigned char*)"TN"));
 assert(calls==1&&!strcmp(last.alpha2,"TN")&&last.initiator==3);
 assert(rtw89_macos_country_ie(&hw,NULL));
 assert(calls==2&&!strcmp(last.alpha2,"00")&&last.initiator==0);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.c';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: AP country validation, board protection and disconnect reset')
