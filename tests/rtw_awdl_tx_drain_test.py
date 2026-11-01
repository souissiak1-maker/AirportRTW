#!/usr/bin/env python3
"""Execute production PCI/MAC drain logic with pending queues and lost hardware."""
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
def function(path, name):
    text = (ROOT / path).read_text()
    start = text.index(name)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'
code = function('rtw/hal_rtw89/driver/pci.c', 'int rtw89_pci_awdl_tx_drain(')
code += function('rtw/hal_rtw89/driver/Senmiko.c', 'int rtw89_macos_awdl_tx_drain(')
shim = r'''
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdint>
using u8=uint8_t;using u32=uint32_t;
#define RTW89_TXCH_NUM 13
#define RTW89_TXCH_CH12 12
#define BIT(n) (1U<<(n))
#define TXBD_HW_IDX_MASK 0xffff
#define FIELD_GET(mask,n) ((n)&(mask))
#define RTW89_FLAG_POWERON 0
#define RTW89_FLAG_RUNNING 1
struct rtw89_dev;
struct rtw89_mac_gen_def {bool(*is_txq_empty)(rtw89_dev*);};
struct Chip {const rtw89_mac_gen_def *mac_def;};
struct rtw89_pci_dma_ring {struct{u32 idx;}addr;u32 wp;};
struct rtw89_pci_tx_ring {rtw89_pci_dma_ring bd_ring;};
struct rtw89_pci {struct{rtw89_pci_tx_ring rings[13];}tx;};
struct rtw89_pci_info {u32 tx_dma_ch_mask;};
struct rtw89_dev {void *priv;const rtw89_pci_info *pci_info;unsigned flags;Chip*chip;};
struct ieee80211_hw {void *priv;};
#define to_rtw89(p) static_cast<rtw89_dev*>(p)
static bool test_bit(unsigned bit,unsigned flags){return flags&BIT(bit);}
static unsigned reads[13],dmaDelay[13],delays,queries,macDelay;
static int missing=-1,losePower=-1;
static bool macNever,refill;
static u32 rtw89_read32(rtw89_dev*d,u32 ch){
 assert(ch<13);++reads[ch];
 if(int(ch)==missing)return ~0U;
 if(int(ch)==losePower)d->flags=0;
 auto*p=static_cast<rtw89_pci*>(d->priv);
 return reads[ch]<=dmaDelay[ch]?0:p->tx.rings[ch].bd_ring.wp;
}
static void udelay(unsigned){++delays;}
static bool macEmpty(rtw89_dev*){++queries;if(refill)dmaDelay[2]=999;return !macNever&&queries>macDelay;}
struct Fixture {
 rtw89_pci pci{};rtw89_pci_info info{};rtw89_mac_gen_def mac{macEmpty};Chip chip{&mac};
 rtw89_dev dev{&pci,&info,3,&chip};ieee80211_hw hw{&dev};
 Fixture(){for(unsigned i=0;i<13;++i){reads[i]=dmaDelay[i]=0;pci.tx.rings[i].bd_ring={{i},7};}
 delays=queries=macDelay=0;missing=losePower=-1;macNever=refill=false;}
};
'''
cases = r'''
int main(){
 {Fixture f;assert(!rtw89_macos_awdl_tx_drain(&f.hw));assert(queries==1);
  for(unsigned i=0;i<12;++i)assert(reads[i]==2);assert(!reads[12]);}
 {Fixture f;f.info.tx_dma_ch_mask=BIT(5);missing=5;dmaDelay[12]=999;
  assert(!rtw89_macos_awdl_tx_drain(&f.hw));assert(!reads[5]&&!reads[12]);}
 {Fixture f;dmaDelay[3]=59;macDelay=4;assert(!rtw89_macos_awdl_tx_drain(&f.hw));
  assert(reads[3]==61&&queries==5&&delays==63);}
 {Fixture f;dmaDelay[3]=60;assert(rtw89_macos_awdl_tx_drain(&f.hw)==-ETIMEDOUT);
  assert(reads[3]==60&&!reads[4]&&!queries);}
 {Fixture f;macNever=true;assert(rtw89_macos_awdl_tx_drain(&f.hw)==-ETIMEDOUT);
  assert(queries==20&&reads[0]==1);}
 {Fixture f;refill=true;assert(rtw89_macos_awdl_tx_drain(&f.hw)==-ETIMEDOUT);
  assert(queries==1&&reads[2]==61);}
 {Fixture f;missing=1;assert(rtw89_macos_awdl_tx_drain(&f.hw)==-ENODEV);assert(!queries);}
 {Fixture f;losePower=1;assert(rtw89_macos_awdl_tx_drain(&f.hw)==-ENODEV);assert(!queries);}
 for(unsigned flags:{0U,1U,2U}){Fixture f;f.dev.flags=flags;
  assert(rtw89_macos_awdl_tx_drain(&f.hw)==-ENODEV);assert(!reads[0]&&!queries);}
 {Fixture f;f.mac.is_txq_empty=nullptr;assert(rtw89_macos_awdl_tx_drain(&f.hw)==-EOPNOTSUPP);assert(!reads[0]);}
 assert(rtw89_macos_awdl_tx_drain(nullptr)==-EINVAL);
 ieee80211_hw empty{};assert(rtw89_macos_awdl_tx_drain(&empty)==-EINVAL);
 puts("PASS: checked AWDL PCI/MAC drain propagates timeouts and hardware loss");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-awdl-drain-') as tmp:
    source=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    source.write_text('#include <initializer_list>\n'+shim+code+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined',str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
