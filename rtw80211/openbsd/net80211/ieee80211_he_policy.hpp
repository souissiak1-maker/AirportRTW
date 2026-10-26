/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef IEEE80211_HE_POLICY_HPP
#define IEEE80211_HE_POLICY_HPP
#include <stdint.h>
#include <stddef.h>
namespace Net80211HE {
inline uint16_t center80(uint16_t primary)
{
    const uint16_t centers[] = {5210, 5290, 5530, 5610, 5690, 5775, 5855};
    for (auto center : centers) {
        unsigned delta = primary > center ? primary - center : center - primary;
        if (delta == 10 || delta == 30) return center;
    }
    return 0;
}
inline uint16_t intersect(uint16_t a, uint16_t b)
{
    uint16_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        unsigned x = (a >> (i * 2)) & 3, y = (b >> (i * 2)) & 3;
        result |= (x == 3 || y == 3 ? 3 : (x < y ? x : y)) << (i * 2);
    }
    return result;
}
inline bool ratesValid(uint16_t ownRx, uint16_t ownTx, uint16_t peerRx,
                       uint16_t peerTx, uint16_t basic)
{
    if ((intersect(ownRx, peerTx) & 3) == 3 ||
        (intersect(ownTx, peerRx) & 3) == 3) return false;
    // Some APs send zero instead of a basic MCS/NSS set (Linux compatibility).
    if (!basic) return true;
    for (unsigned i = 0; i < 8; ++i) {
        unsigned need = (basic >> (i * 2)) & 3;
        if (need == 3) continue;
        const uint16_t maps[] = {ownRx, ownTx, peerRx, peerTx};
        for (auto map : maps) {
            unsigned cap = (map >> (i * 2)) & 3;
            if (cap == 3 || cap < need) return false;
        }
    }
    return true;
}
inline unsigned streams(uint16_t map)
{
    unsigned count = 0;
    for (unsigned i = 0; i < 8; ++i)
        if (((map >> (2 * i)) & 3) != 3) count = i + 1;
    return count;
}
// Bodies exclude the element ID, length and extension ID.
inline bool validCapabilities(const uint8_t *data, size_t length)
{
    if (!data || length < 21) return false;
    size_t mcs = 4 + ((data[6] & 8) ? 4 : 0) + ((data[6] & 16) ? 4 : 0);
    size_t required = 17 + mcs;
    if (length < required) return false;
    if (data[12] & 0x80) {
        if (length <= required) return false;
        unsigned ru = (data[required] >> 3) & 15, count = 0;
        for (; ru; ru >>= 1) count += ru & 1;
        if (!count) return false;
        unsigned bits = 7 + 6 * count * ((data[required] & 7) + 1);
        required += (bits + 7) / 8;
    }
    return length >= required;
}
inline bool validOperation(const uint8_t *data, size_t length)
{
    if (!data || length < 6) return false;
    uint32_t params = data[0] | (uint32_t(data[1]) << 8) | (uint32_t(data[2]) << 16);
    size_t required = 6 + ((params & 0x4000) ? 3 : 0) +
        ((params & 0x8000) ? 1 : 0) + ((params & 0x20000) ? 5 : 0);
    return length >= required;
}
}
#endif
