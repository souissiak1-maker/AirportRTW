/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_HEX_H
#define _RTW88_COMPAT_HEX_H

#include "types.h"

static inline int hex_to_bin(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static inline int hex2bin(u8 *dst, const char *src, size_t count)
{
    while (count--) {
        int hi = hex_to_bin(*src++);
        int lo = hex_to_bin(*src++);
        if (hi < 0 || lo < 0)
            return -1;
        *dst++ = (u8)((hi << 4) | lo);
    }
    return 0;
}

#endif /* _RTW88_COMPAT_HEX_H */
