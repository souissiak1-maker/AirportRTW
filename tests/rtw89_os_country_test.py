#!/usr/bin/env python3
"""Execute the production OS country setter with a mock regulatory notifier."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'rtw/hal_rtw89/driver/Senmiko.c').read_text();start=s.index('bool rtw89_macos_set_country(');fn=s[start:s.index('\n}\n',start)+3]
fixture=r'''
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#define NL80211_REGDOM_SET_BY_USER 2
#define NL80211_DFS_UNSET 0
struct regulatory_request {char alpha2[3];int initiator,dfs_region;};
struct wiphy {void (*reg_notifier)(struct wiphy*,struct regulatory_request*);};
struct domain {char alpha2[2];};
struct rtw89_dev {struct {bool programmed;const struct domain *regd;struct {unsigned nr;struct domain *map;} ctrl;} regulatory;};
struct ieee80211_hw {struct wiphy *wiphy;void *priv;};
static int calls;static bool ignore;static struct rtw89_dev *active;
static void notify(struct wiphy*w,struct regulatory_request*r){
 assert(w);assert(r->initiator==2);assert(!r->alpha2[2]);calls++;
 if(ignore)return;
 for(unsigned i=0;i<active->regulatory.ctrl.nr;i++)
  if(!memcmp(active->regulatory.ctrl.map[i].alpha2,r->alpha2,2))
   active->regulatory.regd=&active->regulatory.ctrl.map[i];
}
'''+fn+r'''
int main(void){
 struct domain map[]={{{'T','N'}},{{'F','R'}}};struct rtw89_dev dev={0};
 struct wiphy w={notify};struct ieee80211_hw hw={&w,&dev};active=&dev;
 dev.regulatory.ctrl.nr=2;dev.regulatory.ctrl.map=map;
 assert(!rtw89_macos_set_country(NULL,"TN"));assert(!rtw89_macos_set_country(&hw,NULL));
 assert(!rtw89_macos_set_country(&hw,"00"));assert(!rtw89_macos_set_country(&hw,"ZZ"));
 assert(!rtw89_macos_set_country(&hw,"tn"));assert(!calls);
 dev.regulatory.programmed=true;dev.regulatory.regd=&map[1];
 assert(!rtw89_macos_set_country(&hw,"TN"));assert(!calls);
 assert(rtw89_macos_set_country(&hw,"FR"));assert(calls==1);
 dev.regulatory.programmed=false;ignore=true;
 assert(!rtw89_macos_set_country(&hw,"TN"));assert(calls==2);
 ignore=false;assert(rtw89_macos_set_country(&hw,"TN"));assert(calls==3);
 assert(!memcmp(dev.regulatory.regd->alpha2,"TN",2));return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.c';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: OS country validation, board restrictions and effective-domain confirmation')
