/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_DATA_HPP
#define RTW_AWDL_DATA_HPP
#include <stddef.h>
#include <stdint.h>

namespace RTWAwdl {
// Independent IPv6 AWDL wire codec. Input/output storage must not overlap.
// Framing facts: Apple LLC OUI, PID 0x0800; eight-byte AWDL prefix (LE head
// 0x0403, LE sequence, zero pad, BE EtherType). No OWL implementation imported.
// Caller owns radio FCS, peer admission, deduplication and packet delivery.
class DataCodec {
public:
    static constexpr size_t mtu = 1428;
    static constexpr size_t maximumFrame = 26 + 16 + mtu;
    static constexpr size_t maximumReceiveFrame = maximumFrame + 8;
    static constexpr size_t maximumAggregateFrame = 11454;
    static constexpr size_t maximumSubframes = 32;
    static bool validEthernet(const uint8_t *ethernet, size_t length) {
        return ethernet && length >= 14 && length <= 14 + mtu &&
            ethernet[12] == 0x86 && ethernet[13] == 0xdd &&
            validSource(ethernet + 6) && ipv6(ethernet + 14, length - 14);
    }
    static bool encode(const uint8_t *ethernet, size_t length, uint8_t *out,
                       size_t capacity, uint16_t sequence, uint16_t dataSequence,
                       size_t &written) {
        written = 0;
        if (!out || !validEthernet(ethernet, length) || capacity < length + 28) return false;
        for (size_t i = 0; i < 42; ++i) out[i] = 0;
        out[0] = 0x88; // QoS data, neither ToDS nor FromDS.
        for (size_t i = 0; i < 6; ++i) {
            out[4 + i] = ethernet[i]; out[10 + i] = ethernet[6 + i];
            out[16 + i] = bssidByte(i);
        }
        const uint16_t control = uint16_t((sequence & 4095) << 4);
        out[22] = uint8_t(control); out[23] = uint8_t(control >> 8);
        // QoS TID zero, no A-MSDU. LLC/SNAP starts after 26-byte header.
        const uint8_t prefix[16] {0xaa,0xaa,3,0,0x17,0xf2,8,0,3,4,
                                  uint8_t(dataSequence),uint8_t(dataSequence >> 8),0,0,0x86,0xdd};
        for (size_t i = 0; i < 16; ++i) out[26 + i] = prefix[i];
        for (size_t i = 14; i < length; ++i) out[28 + i] = ethernet[i];
        written = length + 28;
        return true;
    }
    // Single non-A-MSDU MPDU, without FCS. Unsupported protected, fragmented,
    // mesh/HT-control or aggregate frames are left to their owning decoder.
    struct View {
        const uint8_t *destination {nullptr};
        const uint8_t *source {nullptr};
        const uint8_t *payload {nullptr};
        size_t payloadLength {0};
        uint16_t sequence {0};
    };
    // Validated borrowed view; permits RX classification without a kernel-stack
    // scratch Ethernet packet. The caller must not retain pointers after RX.
    static bool inspect(const uint8_t *frame, size_t length, View &out) {
        out = {};
        if (!frame || length < 40 ||
            (frame[0] != 0x88 && frame[0] != 0x08) ||
            (frame[1] & (3 | 4 | 0x40 | 0x80)) || (frame[22] & 15) ||
            !validSource(frame + 10)) return false;
        for (size_t i = 0; i < 6; ++i)
            if (frame[16 + i] != bssidByte(i)) return false;
        const size_t header = frame[0] == 0x88 ? 26 : 24;
        if (length < header + 16 || (header == 26 && (frame[24] & 0x80))) return false;
        if (!inspectBody(frame+header,length-header,header==26,out)) return false;
        out.destination=frame+4; out.source=frame+10;
        return true;
    }
    // Validate every subframe before exposing any member of an A-MSDU.
    // Views borrow the original RX storage. Callers must serialize its lifetime.
    static bool inspectAggregate(const uint8_t *frame, size_t length,
                                 View *views, size_t capacity, size_t &count) {
        count = 0;
        if (!frame || !capacity || length < 26 || length > maximumAggregateFrame ||
            frame[0] != 0x88 || (frame[1] & (3 | 4 | 0x40 | 0x80)) ||
            (frame[22] & 15) || !(frame[24] & 0x80) ||
            !validSource(frame + 10)) return false;
        for (size_t i=0;i<6;++i)
            if (frame[16+i] != bssidByte(i)) return false;
        // Two passes ensure a malformed tail never delivers a valid prefix.
        size_t total=0;
        for (unsigned pass=0;pass<2;++pass) {
            size_t offset=26, index=0;
            while (offset < length) {
                if (length-offset < 14 || index >= capacity) return false;
                const uint8_t *sub=frame+offset;
                for (size_t i=0;i<6;++i)
                    if (sub[6+i] != frame[10+i]) return false;
                const size_t bytes=(size_t(sub[12])<<8)|sub[13];
                if (bytes > length-offset-14) return false;
                View v;
                if (!inspectBody(sub+14,bytes,true,v)) return false;
                v.destination=sub; v.source=sub+6;
                if (pass && views) views[index]=v;
                ++index; offset+=14+bytes;
                if (offset==length) break;
                const size_t padding=(4-((14+bytes)&3))&3;
                if (padding > length-offset || length-offset-padding < 14)
                    return false;
                offset+=padding;
            }
            if (!index) return false;
            total=index;
        }
        count=total;
        return true;
    }
    // Classify a bounded aggregate without allocating views on an RX stack.
    static bool validAggregate(const uint8_t *frame,size_t length) {
        size_t count=0;
        return inspectAggregate(frame,length,nullptr,maximumSubframes,count);
    }
    static bool decode(const uint8_t *frame, size_t length, uint8_t *ethernet,
                       size_t capacity, size_t &written, uint16_t &dataSequence) {
        written = 0; dataSequence = 0;
        View view;
        if (!ethernet || !inspect(frame, length, view) ||
            capacity < 14 + view.payloadLength) return false;
        for (size_t i = 0; i < 6; ++i) {
            ethernet[i] = view.destination[i]; ethernet[6 + i] = view.source[i];
        }
        ethernet[12] = 0x86; ethernet[13] = 0xdd;
        for (size_t i = 0; i < view.payloadLength; ++i) ethernet[14 + i] = view.payload[i];
        dataSequence = view.sequence;
        written = 14 + view.payloadLength;
        return true;
    }

private:
    static bool inspectBody(const uint8_t *body, size_t bodyLength,
                            bool qos, View &out) {
        const uint8_t envelope[6] {0xaa,0xaa,3,0,0,0};
        bool wrapped = qos && bodyLength >= 8;
        for (size_t i = 0; wrapped && i < 6; ++i)
            wrapped = body[i] == envelope[i];
        if (wrapped) {
            if (size_t((uint16_t(body[6]) << 8) | body[7]) != bodyLength - 8)
                return false;
            body += 8; bodyLength -= 8;
        }
        if (bodyLength < 16) return false;
        const uint8_t fixed[10] {0xaa,0xaa,3,0,0x17,0xf2,8,0,3,4};
        for (size_t i = 0; i < 10; ++i) if (body[i] != fixed[i]) return false;
        if (body[12] || body[13] || body[14] != 0x86 || body[15] != 0xdd) return false;
        const size_t payload = bodyLength - 16;
        if (payload > mtu || !ipv6(body + 16, payload)) return false;
        out.payload = body + 16; out.payloadLength = payload;
        out.sequence = uint16_t(body[10] | (uint16_t(body[11]) << 8));
        return true;
    }
    static uint8_t bssidByte(size_t i) {
        const uint8_t address[6] {0,0x25,0,0xff,0x94,0x73};
        return address[i];
    }
    static bool validSource(const uint8_t *address) {
        uint8_t bits = 0;
        for (unsigned i = 0; i < 6; ++i) bits |= address[i];
        return bits && !(address[0] & 1);
    }
    static bool ipv6(const uint8_t *packet, size_t length) {
        return length >= 40 && (packet[0] >> 4) == 6 &&
            size_t((uint16_t(packet[4]) << 8) | packet[5]) == length - 40;
    }
};
} // namespace RTWAwdl
#endif
