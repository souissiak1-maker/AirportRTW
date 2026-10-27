#!/usr/bin/env python3
"""Simulate Apple's native notification overwriting the Locale property."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'AirportRTW/WCL/WCL.cpp').read_text()
a=s.index('    apple80211_country_code_data country = {};',s.index('wclCountryUpdateGated(\n'))
b=s.index('    return kIOReturnSuccess;',a)
body=s[a:b]
fixture=r'''
#include <cassert>
#include <cstring>
#include <string>
#include <cstdint>
'''+ '#include "'+str(root/'include/HAL/RTWLocale.h')+'"\n'+r'''
using IOReturn=int;
constexpr int kIOReturnSuccess=0;
#define APPLE80211_REGKEY_LOCALE "IO80211Locale"
#define APPLE80211_REGKEY_COUNTRY_CODE "IO80211CountryCode"
#define APPLE80211_M_COUNTRY_CODE_CHANGED 11
struct OSObject {};
struct apple80211_country_code_data {int version;unsigned char cc[3];};
struct Info {unsigned locale=RTW_LOCALE_ETSI;unsigned getRegulatoryLocale(){return locale;}};
struct Hal {Info info;Info*getDriverInfo(){return &info;}};
struct Interface:OSObject {
 Hal hal;Hal*fHalService=&hal;std::string locale,country;
 int posts=0;
 void setProperty(const char*k,const char*v){if(!strcmp(k,APPLE80211_REGKEY_LOCALE))locale=v;else country=v;}
 void postMessage(int code,void*,int,bool){assert(code==11);assert(country=="TN");posts++;locale="Unknown";}
};
struct Controller {int result=0;IOReturn getCOUNTRY_CODE(OSObject*,apple80211_country_code_data*d){memcpy(d->cc,"TN",3);return result;}};
struct Update {Interface*interface;Controller*controller;};
static IOReturn refresh(Update*update){
'''+body+r'''
return kIOReturnSuccess;
}
int main(){
 Interface iface;Controller controller;Update update={&iface,&controller};
 assert(refresh(&update)==0);assert(iface.posts==1);assert(iface.locale=="ETSI");assert(iface.country=="TN");
 iface.hal.info.locale=RTW_LOCALE_UNKNOWN;assert(refresh(&update)==0);assert(iface.locale=="Unknown");
 controller.result=7;assert(refresh(&update)==7);assert(iface.posts==2);
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp)/'test.cpp';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: HAL locale survives native refresh; country and unknown/error handling preserved')
