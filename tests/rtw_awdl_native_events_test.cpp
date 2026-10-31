/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlNativeEvents.hpp>
#include <cassert>
#include <cstring>
int main(){
    using E=RTWAwdl::NativeEvents;
    uint8_t parent[6]={2,1,2,3,4,5},root[6]={2,1,2,3,4,6};
    uint8_t channel[12]={1,0,0,0,44,0,0,0,0x12},start[36],end[40];
    assert(E::start(65535,2,parent,root,channel,12,0x12345678,start,sizeof(start)));
    assert(start[0]==255&&start[1]==255&&!start[2]&&!start[3]&&start[4]==2);
    assert(!memcmp(start+8,parent,6)&&!memcmp(start+14,root,6)&&!memcmp(start+24,channel,12));
    assert(start[20]==0x12&&start[21]==0x34&&start[22]==0x56&&start[23]==0x78);
    assert(E::start(0,3,start+8,start+14,start+24,12,0,start,sizeof(start)));
    assert(!memcmp(start+8,parent,6)&&!memcmp(start+14,root,6)&&start[4]==3&&!start[20]);
    for(size_t n=0;n<42;++n){
        if(n!=36)assert(!E::start(1,1,parent,root,channel,12,1,start,n));
        if(n!=40)assert(!E::end(1,end,n));
    }
    assert(!E::start(1,0,parent,root,channel,12,1,start,36));
    assert(!E::start(1,4,parent,root,channel,12,1,start,36));
    parent[0]=1;assert(!E::start(1,1,parent,root,channel,12,1,start,36));parent[0]=2;
    assert(!E::start(1,1,parent,root,channel,11,1,start,36));
    channel[0]=2;assert(!E::start(1,1,parent,root,channel,12,1,start,36));channel[0]=1;
    channel[4]=0;assert(!E::start(1,1,parent,root,channel,12,1,start,36));
    channel[4]=255;assert(!E::start(1,1,parent,root,channel,12,1,start,36));channel[4]=44;
    assert(E::end(0xaabbccdd,end,40));
    for(unsigned i=0;i<40;++i)
        assert(end[i]==(i>=4&&i<8?uint8_t(0xaabbccddU>>(8*(7-i))):0));
}
