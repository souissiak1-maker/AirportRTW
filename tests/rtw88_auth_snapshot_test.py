#!/usr/bin/env python3
"""Test the production read-only authentication snapshot against fake MMIO."""
from pathlib import Path
import subprocess,tempfile
s=(Path(__file__).resolve().parents[1]/'rtw/hal_rtw88/Rtw88Hardware.c').read_text()
s=s[s.index('void airportrtw88_auth_snapshot('):].split('\n#endif',1)[0]
stubs=r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
typedef uint8_t u8; typedef uint32_t u32;
#define ETH_ALEN 6
#define REG_RCR 64
struct reg {unsigned addr;}; struct conf {struct reg mac_addr,bssid;};
struct rtw_vif {struct conf *conf;u8 mac_addr[6],bssid[6],port;};
struct ieee80211_vif {void *drv_priv;u8 addr[6];};
struct channel {unsigned hw_value;};
struct rtw_dev {int mutex;struct {unsigned current_channel;} hal;};
struct ieee80211_hw {void *priv;struct {struct {struct channel *chan;} chandef;} conf;};
static u8 mmio[128];static int locks;
static void mutex_lock(int *m){(void)m;++locks;}
static void mutex_unlock(int *m){(void)m;--locks;}
static u8 rtw_read8(struct rtw_dev*d,unsigned a){(void)d;return mmio[a];}
static u32 rtw_read32(struct rtw_dev*d,unsigned a){(void)d;assert(a==REG_RCR);return 0x12345678;}
'''
main=r'''
int main(void){
 u32 out[6];u8 src[6]={2,3,4,5,6,7},peer[6]={8,9,10,11,12,13};
 struct conf c={{0},{16}};struct rtw_vif rv={.conf=&c,.port=1};
 struct ieee80211_vif vif={.drv_priv=&rv};struct rtw_dev dev={.hal={11}};
 struct channel ch={11};struct ieee80211_hw hw={.priv=&dev,.conf={.chandef={&ch}}};
 memcpy(rv.mac_addr,src,6);memcpy(rv.bssid,peer,6);memcpy(vif.addr,src,6);
 memcpy(mmio,src,6);memcpy(mmio+16,peer,6);
 airportrtw88_auth_snapshot(&hw,&vif,src,peer,out);
 assert(out[0]==0x12345678 && out[1]==11 && out[2]==11 && out[3]==31 && out[4]==1 && out[5]==1 && locks==0);
 mmio[0]^=1;mmio[16]^=1;rv.mac_addr[0]^=1;vif.addr[0]^=1;
 airportrtw88_auth_snapshot(&hw,&vif,src,peer,out);assert(out[3]==8 && locks==0);
 airportrtw88_auth_snapshot(0,&vif,src,peer,out);for(int i=0;i<6;++i)assert(out[i]==0);
}
'''
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp);(p/'t.c').write_text(stubs+s+main)
 subprocess.run(['xcrun','clang','-fsanitize=address,undefined',str(p/'t.c'),'-o',str(p/'t')],check=True)
 subprocess.run([str(p/'t')],check=True)
print('OK: authentication hardware snapshot, mismatch masks, null input')
