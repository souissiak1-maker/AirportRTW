#!/usr/bin/env python3
"""Check the production HE IE writer and its sizing helpers."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
stack = root / 'rtw80211/openbsd/net80211'

def function(filename, name):
    source = (stack / filename).read_text()
    start = source.index(name + '(')
    end = source.index('\n}', start) + 2
    return source[start:end]

fixture = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#define IEEE80211_ELEMID_EXTENSION 255
#define IEEE80211_ELEMID_EXT_HE_CAPABILITY 35
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G 0x08
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G 0x10
#define IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT 0x80
#define IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK 0x78
#define IEEE80211_PPE_THRES_NSS_MASK 7
#define IEEE80211_PPE_THRES_NSS_POS 0
#define IEEE80211_PPE_THRES_INFO_PPET_SIZE 3
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
static unsigned hweight8(uint8_t n) { return __builtin_popcount(n); }
struct ieee80211_he_cap_elem { uint8_t mac_cap_info[6],phy_cap_info[11]; };
struct ieee80211com {
 ieee80211_he_cap_elem ic_he_cap_elem;
 uint8_t ic_he_mcs_nss_supp[12],ic_ppe_thres[25];
};
'''
for name in ('ieee80211_he_mcs_nss_size', 'ieee80211_he_ppe_size'):
    fixture += '\nstatic uint8_t ' + function('ieee80211.h', name)
fixture += '\nuint8_t *' + function('ieee80211_output.c', 'ieee80211_add_hecaps')
fixture += r'''
int main() {
 for(unsigned widths=0; widths<4; ++widths)
 for(unsigned ppe=0; ppe<2; ++ppe) {
  ieee80211com ic{};
  ic.ic_he_cap_elem.phy_cap_info[0]=widths<<3;
  ic.ic_he_cap_elem.phy_cap_info[6]=ppe?0x80:0;
  memset(ic.ic_he_mcs_nss_supp,0x55,12);
  memset(ic.ic_ppe_thres,0x31,25); // 2 streams, 2 RU sizes: 4 bytes
  uint8_t buffer[80];memset(buffer,0xa5,sizeof(buffer));
  uint8_t *end=ieee80211_add_hecaps(buffer,&ic);
  unsigned mcs=4+4*(widths&1)+4*((widths>>1)&1);
  unsigned payload=1+17+mcs+(ppe?4:0);
  assert(end==buffer+2+payload);
  assert(buffer[0]==255 && buffer[1]==payload && buffer[2]==35);
  assert(memcmp(buffer+3,&ic.ic_he_cap_elem,17)==0);
  assert(memcmp(buffer+20,ic.ic_he_mcs_nss_supp,mcs)==0);
  if(ppe) assert(memcmp(buffer+20+mcs,ic.ic_ppe_thres,4)==0);
  assert(*end==0xa5);
  *end++=244;*end++=1;*end++=0x20; // following RSNXE stays discoverable
  assert(buffer[2+buffer[1]]==244);
 }
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-he-writer-') as directory:
    source = Path(directory) / 'test.cpp'
    binary = Path(directory) / 'test'
    source.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: HE IE length, MCS maps, optional PPE, following RSNXE boundary')
