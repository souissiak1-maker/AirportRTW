#!/usr/bin/env python3
"""Run the production RTW88 snapshot reader against firmware-report fixtures."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
source = (root / 'rtw/hal_rtw88/Rtw88Hardware.c').read_text()
start = source.index('static void copy_tx_rate(')
production = source[start:]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
''' + '#include "' + str(root / 'include/HAL/RTWTxRate.h') + '"\n' + r'''
#define RATE_INFO_FLAGS_MCS 1
#define RATE_INFO_FLAGS_VHT_MCS 2
#define RATE_INFO_FLAGS_SHORT_GI 4
#define RATE_INFO_BW_20 0
#define RATE_INFO_BW_40 1
#define RATE_INFO_BW_80 2
#define RATE_INFO_BW_160 3
struct rate_info { uint32_t flags,legacy;uint8_t mcs,nss,bw; };
struct rtw_sta_info { struct { struct rate_info txrate;uint32_t bit_rate; } ra_report; };
struct ieee80211_sta { struct rtw_sta_info drv_priv[1]; };
struct ieee80211_hw { int unused; };
static struct ieee80211_sta *registered;
static unsigned iterations;
static void ieee80211_iterate_stations_atomic(struct ieee80211_hw *hw,
 void (*callback)(void*,struct ieee80211_sta*),void *data) {
 assert(hw);++iterations;if(registered)callback(data,registered);
}
''' + production + r'''
int main(void) {
 struct ieee80211_hw hw={0};struct ieee80211_sta sta={0},replacement={0};
 struct RTWTxRate sample;memset(&sample,0xff,sizeof(sample));
 rtw88_hw_get_tx_rate(&hw,&sample);assert(!sample.valid && !sample.bitrate100Kbps);
 registered=&sta;
 sta.drv_priv->ra_report.bit_rate=10000; // The compat bitrate is only a presence marker.
 struct rate_info *r=&sta.drv_priv->ra_report.txrate;
 r->flags=RATE_INFO_FLAGS_VHT_MCS|RATE_INFO_FLAGS_SHORT_GI;r->mcs=9;r->nss=1;r->bw=RATE_INFO_BW_80;
 rtw88_hw_get_tx_rate(&hw,&sample);
 assert(sample.valid && sample.bitrate100Kbps==4333 && sample.nss==1 && sample.mcs==9 && sample.widthMHz==80);
 r->mcs=7;r->bw=RATE_INFO_BW_40;r->flags=RATE_INFO_FLAGS_VHT_MCS;
 rtw88_hw_get_tx_rate(&hw,&sample);assert(sample.bitrate100Kbps==1350 && !sample.shortGI);
 r->mcs=15;r->nss=0;r->flags=RATE_INFO_FLAGS_MCS|RATE_INFO_FLAGS_SHORT_GI;
 rtw88_hw_get_tx_rate(&hw,&sample);assert(sample.bitrate100Kbps==3000 && sample.nss==2 && sample.mcs==15);
 registered=&replacement;
 rtw88_hw_get_tx_rate(&hw,&sample);assert(!sample.valid && !sample.bitrate100Kbps);
 registered=NULL;rtw88_hw_get_tx_rate(&hw,&sample);assert(!sample.valid);
 memset(&sample,0xff,sizeof(sample));rtw88_hw_get_tx_rate(NULL,&sample);assert(!sample.valid);
 assert(iterations==6);
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-rate-snapshot-') as directory:
    path = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    path.write_text(fixture)
    subprocess.run(['xcrun', 'clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: production RA snapshot, changing reports, reconnect reset, absent station')
