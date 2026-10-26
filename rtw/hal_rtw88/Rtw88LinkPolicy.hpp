/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW88_LINK_POLICY_HPP
#define RTW88_LINK_POLICY_HPP
#include <stdint.h>
namespace Rtw88Link {
// HT bytes 0..3 describe MCS 0..31; byte 4 is MCS32, not a fifth stream.
inline uint8_t htStreams(const uint8_t *mask, unsigned length)
{
    if (!mask) return 1;
    uint8_t streams = 1;
    for (unsigned i = 0; i < length && i < 4; ++i)
        if (mask[i]) streams = i + 1;
    return streams;
}
// Only accept a contiguous channel definition containing the primary 20 MHz.
inline bool validChannel(unsigned primary, unsigned center, unsigned width)
{
    unsigned delta = primary > center ? primary - center : center - primary;
    if (width == 20) return delta == 0;
    if (width == 40) return delta == 10;
    if (width == 80) return primary >= 5000 && (delta == 10 || delta == 30);
    return false;
}
inline uint16_t intersectMCS(uint16_t local, uint16_t peer)
{
    uint16_t result = 0;
    for (unsigned ss = 0; ss < 8; ++ss) {
        unsigned a = (local >> (2 * ss)) & 3;
        unsigned b = (peer >> (2 * ss)) & 3;
        result |= ((a == 3 || b == 3) ? 3 : (a < b ? a : b)) << (2 * ss);
    }
    return result;
}
inline uint8_t vhtStreams(uint16_t map)
{
    uint8_t streams = 0;
    for (unsigned i = 0; i < 8; ++i)
        if (((map >> (2 * i)) & 3) != 3) streams = i + 1;
    return streams;
}
}
#endif
