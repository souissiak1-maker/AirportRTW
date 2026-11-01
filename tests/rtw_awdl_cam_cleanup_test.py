#!/usr/bin/env python3
"""Run production CAM deinitializers for unallocated and retried peer cleanup."""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
s=(ROOT/'rtw/hal_rtw89/driver/cam.c').read_text()
a=s.index('void rtw89_cam_deinit_addr_cam(');b=s.index('void rtw89_cam_deinit(struct ',a)
code=s[a:b]
shim=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
struct rtw89_cam_info{uint64_t addr_cam_map[2],bssid_cam_map[2];};
struct rtw89_dev{rtw89_cam_info cam_info;};
struct rtw89_addr_cam_entry{bool valid;unsigned addr_cam_idx;};
struct rtw89_bssid_cam_entry{bool valid;unsigned bssid_cam_idx;};
static void clear_bit(unsigned bit,uint64_t*map){assert(bit<128);map[bit/64]&=~(uint64_t(1)<<(bit%64));}
'''
cases=r'''
int main(){
 rtw89_dev dev{{{1,0},{1,0}}};rtw89_addr_cam_entry address{};rtw89_bssid_cam_entry bssid{};
 // A zeroed failed peer must not clear the infrastructure entry at index zero.
 rtw89_cam_deinit_addr_cam(&dev,&address);rtw89_cam_deinit_bssid_cam(&dev,&bssid);
 assert(dev.cam_info.addr_cam_map[0]==1&&dev.cam_info.bssid_cam_map[0]==1);
 for(unsigned index=0;index<128;++index){
  dev={{{~uint64_t(0),~uint64_t(0)},{~uint64_t(0),~uint64_t(0)}}};
  address={true,index};bssid={true,index};
  rtw89_cam_deinit_addr_cam(&dev,&address);rtw89_cam_deinit_bssid_cam(&dev,&bssid);
  assert(!address.valid&&!bssid.valid);
  assert(!(dev.cam_info.addr_cam_map[index/64]&(uint64_t(1)<<(index%64))));
  assert(!(dev.cam_info.bssid_cam_map[index/64]&(uint64_t(1)<<(index%64))));
  // Another allocation can reuse that slot before a retained cleanup retries.
  dev.cam_info.addr_cam_map[index/64]|=uint64_t(1)<<(index%64);
  dev.cam_info.bssid_cam_map[index/64]|=uint64_t(1)<<(index%64);
  rtw89_cam_deinit_addr_cam(&dev,&address);rtw89_cam_deinit_bssid_cam(&dev,&bssid);
  assert(dev.cam_info.addr_cam_map[index/64]==~uint64_t(0));
  assert(dev.cam_info.bssid_cam_map[index/64]==~uint64_t(0));
 }
 puts("PASS: CAM cleanup preserves unowned infrastructure/reallocated entries");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-cam-cleanup-')as tmp:
 cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(shim+code+cases)
 subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                 '-fsanitize=address,undefined',str(cpp),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True,timeout=15)
