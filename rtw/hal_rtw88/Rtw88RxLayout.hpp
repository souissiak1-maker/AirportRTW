/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW88_RX_LAYOUT_HPP
#define RTW88_RX_LAYOUT_HPP
#include <stddef.h>
#include <stdint.h>
namespace Rtw88Rx {
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
