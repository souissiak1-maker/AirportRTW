/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW89_LINK_POLICY_HPP
#define RTW89_LINK_POLICY_HPP
#include <stdint.h>
namespace Rtw89Link {
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
}
#endif
