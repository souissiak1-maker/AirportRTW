/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_SORT_H
#define _RTW88_COMPAT_SORT_H

#include "types.h"
#include <string.h>

/* Minimal in-place insertion sort matching the linux/sort.h signature.
 * rtw89 sorts tiny arrays (beacon-drift stats), so O(n^2) is fine. */
typedef int (*cmp_func_t)(const void *a, const void *b);

static inline void sort(void *base, size_t num, size_t size,
                        cmp_func_t cmp_func,
                        void (*swap_func)(void *a, void *b, int size))
{
    char tmp[64];
    char *b = (char *)base;
    size_t i, j;

    if (size > sizeof(tmp))
        return;

    for (i = 1; i < num; i++) {
        memcpy(tmp, b + i * size, size);
        for (j = i; j > 0 && cmp_func(b + (j - 1) * size, tmp) > 0; j--)
            memmove(b + j * size, b + (j - 1) * size, size);
        memcpy(b + j * size, tmp, size);
    }
}

#endif /* _RTW88_COMPAT_SORT_H */
