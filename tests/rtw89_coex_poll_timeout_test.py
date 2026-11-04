#!/usr/bin/env python3
"""Verify the production mailbox poll returns when firmware remains silent."""
from pathlib import Path
import subprocess,tempfile,re
root=Path(__file__).resolve().parents[1]
s=(root/'rtw/hal_rtw89/compat/linux/iopoll.h').read_text()
a=s.index('#define read_poll_timeout(');b=s.index('#define readx_poll_timeout',a);macro=s[a:b]
# Match the H2C caller's real timeout/delay; guard against an unbounded retry.
fw=(root/'rtw/hal_rtw89/driver/fw.c').read_text();a=fw.index('static int rtw89_fw_write_h2c_reg(')
assert re.search(r'read_poll_timeout\(rtw89_read8, val, val == 0, 1000, 5000, false',fw[a:])
fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
static unsigned long clock_us,reads,ready_at;
#define jiffies (clock_us/1000)
static unsigned long usecs_to_jiffies(unsigned v){return(v+999)/1000;}
static bool time_after(unsigned long a,unsigned long b){return(long)(b-a)<0;}
static void udelay(unsigned v){clock_us+=v;}
static unsigned read_control(void){++reads;return ready_at&&clock_us>=ready_at?0:1;}
'''+macro+r'''
int main(void){unsigned val;int ret;
 ret=read_poll_timeout(read_control,val,val==0,1000,5000,false);
 assert(ret==-ETIMEDOUT&&clock_us<=7000&&reads<=9);
 clock_us=reads=0;ready_at=3000;
 ret=read_poll_timeout(read_control,val,val==0,1000,5000,false);
 assert(!ret&&clock_us==3000&&reads==4);
 clock_us=reads=0;ready_at=1;
 ret=read_poll_timeout(read_control,val,val==0,1000,5000,true);
 assert(!ret&&clock_us==1000&&reads==1);
}
'''
with tempfile.TemporaryDirectory(prefix='rtw89-btc-timeout-')as tmp:
 p=Path(tmp)/'test.c';p.write_text(fixture);exe=Path(tmp)/'test'
 subprocess.run(['xcrun','clang','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
print('PASS: real H2C polling macro times out on silent firmware and accepts delayed replies')
