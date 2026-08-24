/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_UUID_H
#define _RTW88_COMPAT_UUID_H

#include "types.h"

typedef struct {
    u8 b[16];
} guid_t;

/* Linux GUID_INIT: first three fields little-endian */
#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)              \
((guid_t){ { (u8)(a), (u8)((a) >> 8), (u8)((a) >> 16), (u8)((a) >> 24), \
             (u8)(b), (u8)((b) >> 8),                                   \
             (u8)(c), (u8)((c) >> 8),                                   \
             (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } })

#endif /* _RTW88_COMPAT_UUID_H */
