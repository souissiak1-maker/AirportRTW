/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_NATIVE_RX_METADATA_HPP
#define RTW_AWDL_NATIVE_RX_METADATA_HPP
#include <stdint.h>
#include <stddef.h>
namespace RTWAwdl {
// Pinned native Tahoe receive metadata, not a Broadcom firmware event layout.
// Local IO80211AWDLPeerManager compares +44 as signed RSSI against its -70 dBm
// default. Broadcom byte-swaps the firmware event's RSSI into host byte order.
// Do not put a radio timestamp at +44. +48 is an explicit big-endian
// event-domain RX clock; other, unverified fields stay zero.
class NativeRxMetadata {
public:
    static constexpr size_t size = 72;
    static constexpr size_t channelSize = 12;
    static constexpr size_t channelOffset = 12;
    static constexpr size_t rssiOffset = 44;
    static constexpr size_t clockOffset = 48;
    // Channel descriptor is already validated/selected by the native provider;
    // this packer neither infers bandwidth nor authorizes channel use.
    static bool build(const uint8_t source[6], const uint8_t *channel,
                      size_t channelLength, int32_t rssi, uint8_t *out, size_t capacity,
                      uint32_t wireRxTime = 0, bool wireRxTimeValid = false) {
        if (!out || capacity != size) return false;
        if (!source || !channel || channelLength != channelSize || rssi < -127 || rssi >= 0)
            return false;
        uint8_t bits = 0;
        for (unsigned i = 0; i < 6; ++i) bits |= source[i];
        if (!bits || (source[0] & 1)) return false;
        // Copy inputs first so aliasing into an existing header cannot erase them.
        uint8_t address[6], descriptor[channelSize];
        for (unsigned i = 0; i < 6; ++i) address[i] = source[i];
        for (unsigned i = 0; i < channelSize; ++i) descriptor[i] = channel[i];
        for (unsigned i = 0; i < size; ++i) out[i] = 0;
        for (unsigned i = 0; i < 6; ++i) out[i] = address[i];
        for (unsigned i = 0; i < channelSize; ++i) out[channelOffset+i] = descriptor[i];
        uint32_t value = static_cast<uint32_t>(rssi);
        for (unsigned i = 0; i < 4; ++i) out[rssiOffset+i] = uint8_t(value >> (8*i));
        // Explicitly supplied event-domain RX clock, not the RSSI field and
        // not an implicit cast of the radio's unrelated TSF/free-running clock.
        if (wireRxTimeValid)
            for (unsigned i=0;i<4;++i) out[clockOffset+i]=uint8_t(wireRxTime>>(8*(3-i)));
        return true;
    }
};
}
#endif
