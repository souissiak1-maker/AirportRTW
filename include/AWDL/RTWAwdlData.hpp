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
        const uint8_t *body = frame + header;
        const uint8_t fixed[10] {0xaa,0xaa,3,0,0x17,0xf2,8,0,3,4};
        for (size_t i = 0; i < 10; ++i) if (body[i] != fixed[i]) return false;
        if (body[12] || body[13] || body[14] != 0x86 || body[15] != 0xdd) return false;
        const size_t payload = length - header - 16;
        if (payload > mtu || !ipv6(body + 16, payload)) return false;
        out.destination = frame + 4; out.source = frame + 10;
        out.payload = body + 16; out.payloadLength = payload;
        out.sequence = uint16_t(body[10] | (uint16_t(body[11]) << 8));
        return true;
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
