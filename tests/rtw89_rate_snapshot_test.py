#!/usr/bin/env python3
"""Exercise the production RTW89 station/link rate reader, including HE."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
source = (root / 'rtw/hal_rtw89/driver/Senmiko.c').read_text()
start = source.index('static void rtw89_copy_tx_rate(')
production = source[start:source.index('#endif /* RTW89_MACOS */', start)]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
''' + '#include "' + str(root / 'include/HAL/RTWTxRate.h') + '"\n' + r'''
#define RATE_INFO_FLAGS_MCS 1
#define RATE_INFO_FLAGS_VHT_MCS 2
#define RATE_INFO_FLAGS_SHORT_GI 4
#define RATE_INFO_FLAGS_HE_MCS 8
#define RATE_INFO_FLAGS_EHT_MCS 16
#define RATE_INFO_BW_20 0
#define RATE_INFO_BW_40 1
#define RATE_INFO_BW_80 2
#define RATE_INFO_BW_160 3
#define NL80211_RATE_INFO_HE_GI_0_8 0
#define NL80211_RATE_INFO_HE_GI_1_6 1
#define NL80211_RATE_INFO_HE_GI_3_2 2
struct rate_info { uint32_t flags,legacy;uint8_t mcs,nss,bw,he_gi,he_dcm; };
struct rtw89_sta_link { struct { struct rate_info txrate;uint32_t bit_rate; } ra_report; };
struct rtw89_sta { struct rtw89_sta_link *links[1]; };
struct ieee80211_sta { struct rtw89_sta private; };
struct ieee80211_hw { int unused; };
static struct rtw89_sta *sta_to_rtwsta(struct ieee80211_sta *sta) {return &sta->private;}
static struct ieee80211_sta *registered;
static void ieee80211_iterate_stations_atomic(struct ieee80211_hw *hw,
 void (*callback)(void*,struct ieee80211_sta*),void *data) {
 assert(hw);if(registered)callback(data,registered);
}
''' + production + r'''
int main(void) {
 struct ieee80211_hw hw={0};struct ieee80211_sta sta={0};
 struct rtw89_sta_link link={0},replacement={0};struct RTWTxRate sample;
 memset(&sample,0xff,sizeof(sample));
 rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid && !sample.bitrate100Kbps);
 registered=&sta;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid); // No link yet.
 sta.private.links[0]=&link;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid); // No report yet.
 struct rate_info *r=&link.ra_report.txrate;
 r->flags=RATE_INFO_FLAGS_HE_MCS;r->mcs=11;r->nss=2;r->bw=RATE_INFO_BW_80;r->he_gi=0;
 // The old compat helper gives zero for HE: raw report flags prove presence.
 assert(link.ra_report.bit_rate==0);
 rtw89_macos_get_tx_rate(&hw,&sample);
 assert(sample.valid && sample.mode==RTW_RATE_HE && sample.bitrate100Kbps==12010 && sample.guardIntervalNs==800 && !sample.shortGI);
 r->he_gi=1;rtw89_macos_get_tx_rate(&hw,&sample);assert(sample.bitrate100Kbps==11343);
 r->he_gi=2;rtw89_macos_get_tx_rate(&hw,&sample);assert(sample.bitrate100Kbps==10208);
 r->he_gi=3;rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid);
 r->flags=RATE_INFO_FLAGS_VHT_MCS|RATE_INFO_FLAGS_SHORT_GI;r->mcs=9;r->nss=1;r->bw=RATE_INFO_BW_80;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(sample.bitrate100Kbps==4333 && sample.guardIntervalNs==400);
 r->flags=RATE_INFO_FLAGS_MCS;r->mcs=15;r->nss=0;r->bw=RATE_INFO_BW_40;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(sample.bitrate100Kbps==2700 && sample.nss==2);
 r->flags=0;r->legacy=540;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(sample.valid && sample.bitrate100Kbps==540);
 r->flags=RATE_INFO_FLAGS_EHT_MCS;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid);
 r->flags=RATE_INFO_FLAGS_HE_MCS|RATE_INFO_FLAGS_VHT_MCS;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid);
 sta.private.links[0]=&replacement;
 rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid && !sample.bitrate100Kbps);
 registered=NULL;rtw89_macos_get_tx_rate(&hw,&sample);assert(!sample.valid);
 memset(&sample,0xff,sizeof(sample));rtw89_macos_get_tx_rate(NULL,&sample);assert(!sample.valid);
}
'''
with tempfile.TemporaryDirectory(prefix='rtw89-rate-snapshot-') as directory:
    path = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    path.write_text(fixture)
    subprocess.run(['xcrun', 'clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: RTW89 HE/HT/VHT/legacy reports, GI changes, zero compat HE bitrate and reconnect reset')
