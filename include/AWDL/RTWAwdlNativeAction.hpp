/* SPDX-License-Identifier: GPL-2.0-only
 * Native supplemental-TLV validation and election patching adapted from
 * MtkWireless Wi-Fi protocol.rs, revision 98d9442076939dd3a0360eed27bdcfb5681c3078.
 * Uses AirportRTW's explicit wire clock and generates no device identity TLVs.
 */
#ifndef RTW_AWDL_NATIVE_ACTION_HPP
#define RTW_AWDL_NATIVE_ACTION_HPP
#include <AWDL/RTWAwdlElection.hpp>
#include <AWDL/RTWAwdlTxTemplate.hpp>
namespace RTWAwdl {
class NativeAction {
public:
    static bool valid(const uint8_t *bytes,size_t length) {
        if(!bytes || !length || length>2048)return false;
        TlvCursor cursor(bytes,length);Tlv tlv;bool election=false;
        while(cursor.next(tlv)) {
            if(tlv.type==4 || tlv.type==18)return false; // radio scheduler owns timing
            if(tlv.type==24){if(election || tlv.length!=40)return false;election=true;}
            if(tlv.type==5 && tlv.length!=21)return false;
            if(tlv.type==20 && tlv.length%6)return false;
        }
        return !cursor.failed();
    }
    static size_t build(Election::State &state,const TxTemplate &native,uint8_t *frame,size_t capacity,
                         uint64_t now,uint32_t wire,uint8_t subtype) {
        if(!valid(native.tlvs(),native.tlvSize()))return 0;
        size_t required=40+3+39+state.sequence.count+43;
        TlvCursor measure(native.tlvs(),native.tlvSize());Tlv tlv;
        while(measure.next(tlv))if(tlv.type!=20 && tlv.type!=24)required+=3+tlv.length;
        if(!frame || required>capacity)return 0;
        size_t length=Election::buildSynchronization(state,frame,capacity,now,wire,wire,subtype);
        if(!length)return 0;
        TlvCursor cursor(native.tlvs(),native.tlvSize());
        while(cursor.next(tlv)) {
            if(tlv.type==20 || tlv.type==24)continue; // stale tree dropped; fresh v2 already generated
            frame[length]=tlv.type;Election::put16(frame+length+1,uint16_t(tlv.length));
            memcpy(frame+length+3,tlv.data,tlv.length);
            if(tlv.type==5) {
                auto *p=frame+length+3;p[3]=uint8_t(state.distance);
                memcpy(p+5,state.master,6);Election::put32(p+11,state.masterMetric);Election::put32(p+15,state.metric);
            }
            length+=3+tlv.length;
        }
        return length;
    }
};
}
#endif
