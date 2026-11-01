/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_NATIVE_EVENTS_HPP
#define RTW_AWDL_NATIVE_EVENTS_HPP
#include <stdint.h>
#include <stddef.h>
namespace RTWAwdl {
// Pinned native Tahoe event payloads. The caller supplies a driver-confirmed
// channel and clock values in the same established domain as RX metadata +48.
// Packing a payload does not establish a lease, authorize a channel or emit it.
class NativeEvents {
public:
    static constexpr unsigned startEvent=41,endEvent=43,cacheEvent=51;
    static constexpr size_t startSize=36,endSize=40,cacheSize=0x1d0;
    // Emit only after a real peer transaction has completed. Unknown native
    // key/cipher fields stay zero for the unencrypted AWDL hardware path.
    static bool cache(const uint8_t address[6],bool present,uint8_t *out,size_t capacity) {
        if (!address || !out || capacity!=cacheSize || !unicast(address)) return false;
        uint8_t saved[6];for(unsigned i=0;i<6;++i)saved[i]=address[i];
        for(unsigned i=0;i<cacheSize;++i)out[i]=0;
        putLE(out,1);putLE(out+4,present ? 1 : 3);
        for(unsigned i=0;i<6;++i)out[8+i]=saved[i];
        return true;
    }
    static bool start(uint16_t counter,uint32_t role,const uint8_t parent[6],
                      const uint8_t root[6],const uint8_t *channel,size_t channelLength,
                      uint32_t wireTime,uint8_t *out,size_t capacity) {
        if (!out || capacity!=startSize || !parent || !root || !channel ||
            channelLength!=12 || role<1 || role>3 || !unicast(parent) || !unicast(root))
            return false;
        const uint32_t version=uint32_t(channel[0])|(uint32_t(channel[1])<<8)|
            (uint32_t(channel[2])<<16)|(uint32_t(channel[3])<<24);
        const uint32_t number=uint32_t(channel[4])|(uint32_t(channel[5])<<8)|
            (uint32_t(channel[6])<<16)|(uint32_t(channel[7])<<24);
        if(version!=1 || !number || number>196)return false;
        // Copy inputs before clearing to support replacement in caller storage.
        uint8_t saved[24];
        for(unsigned i=0;i<6;++i){saved[i]=parent[i];saved[6+i]=root[i];}
        for(unsigned i=0;i<12;++i)saved[12+i]=channel[i];
        for(unsigned i=0;i<startSize;++i)out[i]=0;
        putLE(out,counter);putLE(out+4,role);
        for(unsigned i=0;i<12;++i)out[8+i]=saved[i];
        putBE(out+20,wireTime);
        for(unsigned i=0;i<12;++i)out[24+i]=saved[12+i];
        return true;
    }
    static bool end(uint32_t wireTime,uint8_t *out,size_t capacity) {
        if(!out || capacity!=endSize)return false;
        for(unsigned i=0;i<endSize;++i)out[i]=0;
        putBE(out+4,wireTime);
        return true;
    }
private:
    static bool unicast(const uint8_t *mac) {
        uint8_t bits=0;for(unsigned i=0;i<6;++i)bits|=mac[i];
        return bits && !(mac[0]&1);
    }
    static void putLE(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;++i)p[i]=uint8_t(v>>(8*i));}
    static void putBE(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;++i)p[i]=uint8_t(v>>(8*(3-i)));}
};
}
#endif
