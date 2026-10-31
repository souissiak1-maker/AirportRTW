#!/usr/bin/env python3
"""Test actual native action-ingress ownership without loading kernel code."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
header=(ROOT/'AirportRTW/WCL/AirportRTWAwdlActionInput.hpp').read_text()
source=(ROOT/'AirportRTW/WCL/AirportRTWAwdlActionInput.cpp').read_text()
strip=lambda text:re.sub(r'^#include[^\n]*\n','',text,flags=re.M)
shim=r'''
#include <AWDL/RTWAwdlFrame.hpp>
#include <cassert>
#include <cstring>
#include <vector>
#include <cstdio>
class IO80211VirtualInterface {};
struct Buffer {std::vector<uint8_t> bytes;size_t length;};
static bool allocationFails=false,bytesFail=false;
static unsigned allocations=0,releases=0,inputs=0;
static std::vector<Buffer*> pending;
'''
scenarios=r'''
extern "C" {
void *rtw_awdl_action_allocate(const void *raw) {
    if(allocationFails)return nullptr;auto *options=static_cast<const uint64_t*>(raw);
    for(unsigned i=1;i<6;++i)assert(options[i]==0);
    ++allocations;return new Buffer{std::vector<uint8_t>(options[0]),0};
}
void *rtw_awdl_action_bytes(void *raw){return bytesFail?nullptr:static_cast<Buffer*>(raw)->bytes.data();}
void rtw_awdl_action_set_length(void *raw,size_t n){auto*b=static_cast<Buffer*>(raw);assert(n<=b->bytes.size());b->length=n;}
void rtw_awdl_action_release(void *raw){++releases;delete static_cast<Buffer*>(raw);}
void rtw_awdl_action_input(IO80211VirtualInterface*,void *raw,uint32_t dlt,void *header,size_t n){
    assert(dlt==12&&n==72&&header);auto*b=static_cast<Buffer*>(raw);
    assert(b->length==16&&b->bytes[0]==127&&b->bytes[5]==0x10);
    ++inputs;pending.push_back(b);
}
}
int main(){
    IO80211VirtualInterface iface;
    uint8_t frame[40]{};frame[0]=0xd0;frame[10]=2;
    frame[24]=127;frame[26]=0x17;frame[27]=0xf2;frame[28]=8;frame[29]=0x10;frame[30]=3;
    uint8_t metadata[73]{};metadata[0]=2;
    using AirportRTWAwdlActionInput::deliver;
    assert(!deliver(nullptr,frame,40,metadata,72));
    for(size_t n=0;n<=73;++n)if(n!=72)assert(!deliver(&iface,frame,40,metadata,n));
    for(size_t n=0;n<40;++n)assert(!deliver(&iface,frame,n,metadata,72));
    assert(allocations==0&&inputs==0);
    metadata[1]=1;assert(!deliver(&iface,frame,40,metadata,72));metadata[1]=0;
    frame[1]=0x40;assert(!deliver(&iface,frame,40,metadata,72));frame[1]=0;
    allocationFails=true;assert(!deliver(&iface,frame,40,metadata,72));allocationFails=false;
    bytesFail=true;assert(!deliver(&iface,frame,40,metadata,72));bytesFail=false;
    assert(allocations==1&&releases==1&&inputs==0);
    assert(deliver(&iface,frame,40,metadata,72));assert(allocations==2&&releases==1&&inputs==1);
    // Native asynchronous ownership: the input frame may be immediately reused.
    frame[24]=0;assert(pending[0]->bytes[0]==127);
    for(auto*b:pending)rtw_awdl_action_release(b);
    assert(allocations==releases);
    puts("PASS: native action header bounds, malformed frames and asynchronous buffer ownership");
}
'''
with tempfile.TemporaryDirectory(prefix='awdl-action-input-') as temp:
    path=Path(temp)/'host.cpp';binary=str(Path(temp)/'test')
    path.write_text(shim+strip(header)+strip(source)+scenarios)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
        '-DAIRPORT_WCL','-D__MAC_26_0=260000','-D__IO80211_TARGET=260000',
        '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(path),'-o',binary],check=True)
    subprocess.run([binary],check=True,timeout=10)
