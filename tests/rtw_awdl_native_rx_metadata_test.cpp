// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <AWDL/RTWAwdlNativeRxMetadata.hpp>
#include <cassert>
#include <cstring>
#include <initializer_list>
using RTWAwdl::NativeRxMetadata;
int main() {
    uint8_t source[6]={2,1,2,3,4,5};
    uint8_t channel[12]={1,0,0,0,44,0,0,0,0x12};
    uint8_t out[72];memset(out,0xee,sizeof(out));
    assert(NativeRxMetadata::build(source,channel,12,-41,out,72));
    assert(!memcmp(out,source,6) && !memcmp(out+12,channel,12));
    int32_t rssi=0;memcpy(&rssi,out+44,4);assert(rssi==-41);
    for(unsigned i=0;i<72;++i)
        if(i>=6 && !(i>=12 && i<24) && !(i>=44 && i<48)) assert(out[i]==0);
    assert(NativeRxMetadata::build(source,channel,12,-41,out,72,0x12345678,true));
    assert(out[48]==0x12&&out[49]==0x34&&out[50]==0x56&&out[51]==0x78);
    memcpy(&rssi,out+44,4);assert(rssi==-41);
    assert(NativeRxMetadata::build(source,channel,12,-41,out,72,0x12345678,false));
    assert(!out[48]&&!out[49]&&!out[50]&&!out[51]);
    for(int32_t value : {-127,-70,-1}) {
        assert(NativeRxMetadata::build(source,channel,12,value,out,72));
        memcpy(&rssi,out+44,4);assert(rssi==value);
    }
    for(int32_t value : {-128,0,1,2147483647})
        assert(!NativeRxMetadata::build(source,channel,12,value,out,72));
    for(size_t n=0;n<74;++n)if(n!=72)assert(!NativeRxMetadata::build(source,channel,12,-40,out,n));
    assert(!NativeRxMetadata::build(nullptr,channel,12,-40,out,72));
    assert(!NativeRxMetadata::build(source,channel,11,-40,out,72));
    source[0]=1;assert(!NativeRxMetadata::build(source,channel,12,-40,out,72));source[0]=2;
    assert(NativeRxMetadata::build(source,channel,12,-40,out,72));
    assert(NativeRxMetadata::build(out,out+12,12,-45,out,72));
    assert(!memcmp(out,source,6) && !memcmp(out+12,channel,12));
}
