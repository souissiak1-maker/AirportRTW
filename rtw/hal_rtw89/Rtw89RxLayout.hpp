/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW89_RX_LAYOUT_HPP
#define RTW89_RX_LAYOUT_HPP
#include <stddef.h>
#include <stdint.h>
#include <string.h>
namespace Rtw89Rx {
// The direct MLME association-response path bypasses ieee80211_inputm.
// Validate its envelope before any fixed fields, IEs or state are consumed.
inline bool associationResponse(const uint8_t *frame, size_t length,
                                const uint8_t station[6], const uint8_t peer[6])
{
    if (!frame || !station || !peer || length < 30) return false;
    if (frame[0] != 0x10 && frame[0] != 0x30) return false;
    // Management has no DS direction. Reject fragmentation and protection;
    // these pre-key association responses cannot use a protected envelope.
    if ((frame[1] & (0x03 | 0x04 | 0x40 | 0x80)) || (frame[22] & 15)) return false;
    return !memcmp(frame + 4, station, 6) &&
           !memcmp(frame + 10, peer, 6) && !memcmp(frame + 16, peer, 6);
}
// For hardware-decrypted CCMP data with IV and MIC still present, excluding FCS.
struct CCMPLayout { size_t headerLength; unsigned keyIndex; bool multicast; };
inline size_t dataHeaderLength(const uint8_t *frame, size_t length)
{
    if (!frame || length < 24 || (frame[0] & 0x0c) != 0x08)
        return 0;
    size_t header = 24;
    if ((frame[1] & 3) == 3) header += 6;
    if (frame[0] & 0x80) {
        header += 2;
        if (frame[1] & 0x80) header += 4;
    }
    return length >= header ? header : 0;
}
// Header metadata only. For SAE's CCMP-128 path; never interpret ciphertext.
struct HandshakeHeader { uint32_t control, length, flags, etherType; };
inline HandshakeHeader handshakeHeader(const uint8_t *frame, size_t length,
                                      bool decrypted, bool ivStripped)
{
    HandshakeHeader result = {0, uint32_t(length),
        uint32_t((decrypted ? 1 : 0) | (ivStripped ? 2 : 0)), 0xffffffffu};
    if (!frame || length < 24) return result;
    result.control = frame[0] | (uint32_t(frame[1]) << 8);
    size_t offset = dataHeaderLength(frame, length);
    if (!offset || (frame[0] & 0x40) || (frame[1] & 4) || (frame[22] & 15))
        return result; // No-data and fragmented frames have no complete LLC here.
    if (frame[1] & 0x40) {
        if (!decrypted) return result;
        if (!ivStripped) offset += 8;
    }
    if (length >= offset + 8 && !memcmp(frame + offset, "\xaa\xaa\x03\x00\x00\x00", 6))
        result.etherType = (uint32_t(frame[offset + 6]) << 8) | frame[offset + 7];
    return result;
}
inline bool ccmpLayout(const uint8_t *frame, size_t length, CCMPLayout &out)
{
    size_t header = dataHeaderLength(frame, length);
    if (!header || !(frame[1] & 0x40)) return false;
    if (length < header + 8 + 8 || !(frame[header + 3] & 0x20))
        return false;
    out = {header, unsigned(frame[header + 3] >> 6), bool(frame[4] & 1)};
    return true;
}
}
#endif
