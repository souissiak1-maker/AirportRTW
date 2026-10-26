#!/usr/bin/env python3
"""Exercise the production state-exit country notification guard."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'rtw/hal_rtw89/RTWCore89.cpp').read_text();start=s.index('class CountryChangeNotification {');fn=s[start:s.index('\n};',start)+3]
s88=(root/'rtw/hal_rtw88/RTWCore88.cpp').read_text();a88=s88.index('class CountryChangeNotification {')
assert s88[a88:s88.index('\n};',a88)+3].replace('RTWCore88','RTWCore89') == fn
fixture=r'''
#include <cassert>
#include <cstring>
#define IEEE80211_EVT_COUNTRY_CODE_UPDATE 42
struct ieee80211com {void (*ic_event_handler)(ieee80211com*,int,void*);};
struct RTWCore89 {char country[3]={'0','0',0};const char*getFirmwareCountryCode(){return country;}};
static int events;
static void event(ieee80211com*,int code,void*data){assert(code==42);assert(!data);events++;}
'''+fn+r'''
static void failedTransition(RTWCore89 *owner,ieee80211com*ic){
 CountryChangeNotification guard(owner,ic);memcpy(owner->country,"00",3);return;
}
int main(){
 RTWCore89 owner;ieee80211com ic={event};
 {CountryChangeNotification guard(&owner,&ic);}assert(events==0);
 {CountryChangeNotification guard(&owner,&ic);memcpy(owner.country,"TN",3);}assert(events==1);
 {CountryChangeNotification guard(&owner,&ic);}assert(events==1);
 failedTransition(&owner,&ic);assert(events==2);
 ic.ic_event_handler=nullptr;
 {CountryChangeNotification guard(&owner,&ic);memcpy(owner.country,"TN",3);}assert(events==2);
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.cpp';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: changed, unchanged, failed-transition and missing-handler notifications')
