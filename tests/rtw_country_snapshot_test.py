#!/usr/bin/env python3
"""Exercise the actual country readers with world, programmed and absent domains."""
from pathlib import Path
import subprocess, tempfile
root = Path(__file__).resolve().parents[1]
for family, file in [(88,'compat/rtw88_compat.c'),(89,'driver/Senmiko.c')]:
    source=(root/f'rtw/hal_rtw{family}'/file).read_text()
    start=source.index('bool rtw88_get_country_code(')
    function=source[start:source.index('\n}\n',start)+3]
    fixture='''#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
struct domain { char alpha2[2]; };
struct rtw_dev { struct { struct domain *regulatory; } regd; };
struct rtw89_dev { struct { struct domain *regd; } regulatory; };
#define to_rtw89(p) ((struct rtw89_dev *)(p))
'''+function+'''
int main(void) {
 char out[3]; struct domain country={{'T','N'}};
'''
    if family==88:
        fixture+='struct rtw_dev dev={0}; dev.regd.regulatory=&country;\n'
    else:
        fixture+='struct rtw89_dev dev={0}; dev.regulatory.regd=&country;\n'
    fixture+='''assert(rtw88_get_country_code((struct rtw_dev *)&dev,out));
 assert(!strcmp(out,"TN")); country.alpha2[0]='0';country.alpha2[1]='0';
 assert(rtw88_get_country_code((struct rtw_dev *)&dev,out));assert(!strcmp(out,"00"));
 assert(!rtw88_get_country_code(NULL,out));assert(!strcmp(out,"00"));
 return 0; }
'''
    with tempfile.TemporaryDirectory() as tmp:
        src=Path(tmp)/'test.c';src.write_text(fixture);exe=Path(tmp)/'test'
        subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(src),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
print('Both country snapshot readers passed')
