#!/usr/bin/env python3
"""Execute both production Locale readers against real regulatory enum values."""
from pathlib import Path
import subprocess,tempfile,re
root=Path(__file__).resolve().parents[1]
for family in (88,89):
 base=root/f'rtw/hal_rtw{family}'
 source=(base/('Rtw88Hardware.c' if family==88 else 'driver/Senmiko.c')).read_text()
 symbol='airportrtw88_get_locale' if family==88 else 'rtw89_macos_get_locale'
 start=source.index('unsigned int '+symbol+'(');fn=source[start:source.index('\n}\n',start)+3]
 header=(base/('driver/main.h' if family==88 else 'driver/core.h')).read_text()
 name='rtw_regulatory_domains' if family==88 else 'rtw89_regulation_type'
 start=header.index('enum '+name+' {');enum=header[start:header.index('\n};',start)+3]
 fixture='#include <assert.h>\n#include <stddef.h>\n#include <string.h>\n#include "'+str(root/'include/HAL/RTWLocale.h')+'"\n'+enum+'\n'
 fixture+='struct ieee80211_hw {void*priv;};\n'
 if family==88:
  fixture+='struct rtw_regulatory {char alpha2[2];unsigned txpwr_regd_2g,txpwr_regd_5g;};\nstruct rtw_dev {struct {struct rtw_regulatory*regulatory;}regd;};\n'
  setup='struct rtw_regulatory reg={0};struct rtw_dev dev={{&reg}};'
  setreg=lambda value:f'reg.txpwr_regd_2g=reg.txpwr_regd_5g=RTW_REGD_{value};'
  mixed='reg.txpwr_regd_5g=RTW_REGD_FCC;'
 else:
  fixture+='#define RTW89_BAND_2G 0\n#define RTW89_BAND_5G 1\nstruct rtw89_regd {char alpha2[2];unsigned txpwr_regd[3];};\nstruct rtw89_dev {struct {struct rtw89_regd*regd;}regulatory;};\n'
  setup='struct rtw89_regd reg={0};struct rtw89_dev dev={{&reg}};'
  setreg=lambda value:f'reg.txpwr_regd[0]=reg.txpwr_regd[1]=RTW89_{value};'
  mixed='reg.txpwr_regd[1]=RTW89_FCC;'
 fixture+=fn+'\nint main(void){'+setup+'struct ieee80211_hw hw={&dev};\n'
 fixture+=f'assert({symbol}(NULL)==RTW_LOCALE_UNKNOWN);\n'
 for country,reg,expected in [('00','WW','UNKNOWN'),('TN','ETSI','ETSI'),('US','FCC','FCC'),('JP','MKK','JAPAN'),('KR','KCC','KOREA'),('GB','UK','ETSI'),('CA','IC','ROW')]:
  fixture+=f'memcpy(reg.alpha2,"{country}",2);'+setreg(reg)+f'assert({symbol}(&hw)==RTW_LOCALE_{expected});\n'
 fixture+=setreg('ETSI')+mixed+f'assert({symbol}(&hw)==RTW_LOCALE_ROW);\n'
 fixture+='assert(!strcmp(rtw_locale_name(RTW_LOCALE_ETSI),"ETSI"));assert(!strcmp(rtw_locale_name(99),"Unknown"));return 0;}\n'
 with tempfile.TemporaryDirectory() as tmp:
  p=Path(tmp)/'test.c';p.write_text(fixture);exe=Path(tmp)/'test'
  subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
  subprocess.run([str(exe)],check=True)
# Keep the shared enum numerically aligned with Apple's documented ABI headers.
apple=(root/'include/Airport/apple80211_var.h').read_text()
shared=(root/'include/HAL/RTWLocale.h').read_text()
for label in ['UNKNOWN','FCC','ETSI','JAPAN','KOREA','APAC','ROW','INDONESIA']:
 assert re.search(r'APPLE80211_LOCALE_'+label+r'\s*=\s*(\d+)',apple).group(1)==re.search(r'RTW_LOCALE_'+label+r'\s*=\s*(\d+)',shared).group(1)
print('PASS: both HAL locales, effective domains, mixed domains and Apple ABI alignment')
