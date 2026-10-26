/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef NET80211_PTK_HPP
#define NET80211_PTK_HPP
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace Net80211PTK {
using KDF = void (*)(const uint8_t *, size_t, const uint8_t *, size_t,
                     const uint8_t *, size_t, uint8_t *, size_t);
inline void derive(bool sae, const uint8_t *pmk, const uint8_t *aa,
                   const uint8_t *spa, const uint8_t *anonce,
                   const uint8_t *snonce, uint8_t *ptk, size_t capacity, KDF kdf)
{
    uint8_t context[76];
    bool first = memcmp(aa, spa, 6) < 0;
    memcpy(context, first ? aa : spa, 6);
    memcpy(context + 6, first ? spa : aa, 6);
    first = memcmp(anonce, snonce, 32) < 0;
    memcpy(context + 12, first ? anonce : snonce, 32);
    memcpy(context + 44, first ? snonce : anonce, 32);
    static const uint8_t label[] = "Pairwise key expansion";
    // Legacy SHA-1 PRF includes the NUL separator. SAE's SHA-256 KDF does not.
    // SAE with CCMP-128 derives KCK16 + KEK16 + TK16; its length is part of KDF input.
    memset(ptk, 0, capacity);
    kdf(pmk, 32, label, sae ? sizeof(label) - 1 : sizeof(label),
        context, sizeof(context), ptk, sae ? 48 : capacity);
}
}
#endif
