/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_DATA_RECEIVE_HPP
#define RTW_AWDL_DATA_RECEIVE_HPP
#include <AWDL/RTWAwdlData.hpp>
namespace RTWAwdl {
// Heap-own this engine with the runtime: views/scratch stay off the kernel
// stack. Called only on the native workloop. Sink must copy before returning.
class DataReceive {
public:
    template<class Peers,class Sink>
    size_t deliver(const uint8_t *frame,size_t length,const uint8_t local[6],
                   uint64_t now,Peers &peers,Sink sink) {
        if(busy_)return 0;busy_=true;resetPending_=false;
        struct Clear {DataReceive &owner;~Clear(){owner.busy_=false;owner.reset();}} clear{*this};
        if (!frame || !local || length<24 || length>DataCodec::maximumAggregateFrame ||
            (local[0]&1) || !peers.authorized(frame+10)) return 0;
        uint8_t localBits=0;for(unsigned i=0;i<6;++i)localBits|=local[i];
        if (!localBits || (!(frame[4]&1) && !equal(frame+4,local))) return 0;
        size_t count=1;
        if (!DataCodec::inspect(frame,length,views_[0])) {
            if (!DataCodec::inspectAggregate(frame,length,views_,DataCodec::maximumSubframes,count)) return 0;
        }
        // Validate all destinations before changing replay state or delivering
        // a prefix. Outer TA and each aggregate source were checked by codec.
        for(size_t i=0;i<count;++i) {
            const auto &v=views_[i];
            if (v.destination[0]&1) {
                if (v.destination[0]!=0x33 || v.destination[1]!=0x33 || v.payload[24]!=0xff)
                    return 0;
                for(unsigned j=0;j<4;++j)if(v.destination[2+j]!=v.payload[36+j])return 0;
            } else if (!equal(v.destination,local)) return 0;
        }
        const unsigned stream=frame[0]==0x88 ? frame[24]&15 : 16;
        size_t delivered=0;
        for(size_t i=0;i<count && !resetPending_;++i) {
            const auto &v=views_[i];
            // A reentrant sink may revoke the peer between subframes.
            if (!peers.acceptData(v.source,stream,v.sequence,now)) continue;
            for(unsigned j=0;j<6;++j){ethernet_[j]=v.destination[j];ethernet_[6+j]=v.source[j];}
            ethernet_[12]=0x86;ethernet_[13]=0xdd;
            for(size_t j=0;j<v.payloadLength;++j)ethernet_[14+j]=v.payload[j];
            if(sink(ethernet_,14+v.payloadLength))++delivered;
        }
        return delivered;
    }
    void reset() {
        if(busy_){resetPending_=true;return;}
        resetPending_=false;
        for(auto &view:views_)view={};
        for(auto &byte:ethernet_)byte=0;
    }
private:
    static bool equal(const uint8_t *a,const uint8_t *b){for(unsigned i=0;i<6;++i)if(a[i]!=b[i])return false;return true;}
    bool busy_{false},resetPending_{false};
    DataCodec::View views_[DataCodec::maximumSubframes] {};
    uint8_t ethernet_[14+DataCodec::mtu] {};
};
}
#endif
