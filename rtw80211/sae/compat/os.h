/* SPDX-License-Identifier: GPL-2.0 */
/* hostap's os.h, reduced to what the SAE code uses (see ../rtw_sae_hostap.c). */
#ifndef RTW_SAE_HOSTAP_OS_H
#define RTW_SAE_HOSTAP_OS_H

#include <stddef.h>
#include <string.h>

void *rtw_sae_hostap_malloc(size_t size);
void *rtw_sae_hostap_zalloc(size_t size);
void *rtw_sae_hostap_realloc(void *ptr, size_t size);
void rtw_sae_hostap_free(void *ptr);
int rtw_sae_hostap_memcmp_const(const void *a, const void *b, size_t len);

/* sae.h keeps one of these for anti-clogging bookkeeping that the station
 * side never uses */
typedef long os_time_t;
struct os_reltime {
    os_time_t sec;
    os_time_t usec;
};

#define os_malloc(s) rtw_sae_hostap_malloc(s)
#define os_zalloc(s) rtw_sae_hostap_zalloc(s)
#define os_realloc(p, s) rtw_sae_hostap_realloc((p), (s))
#define os_free(p) rtw_sae_hostap_free(p)
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#define os_memmove(d, s, n) memmove((d), (s), (n))
#define os_memset(s, c, n) memset((s), (c), (n))
#define os_memcmp(a, b, n) memcmp((a), (b), (n))
#define os_memcmp_const(a, b, n) rtw_sae_hostap_memcmp_const((a), (b), (n))
#define os_strlen(s) strlen(s)
#define os_strcmp(a, b) strcmp((a), (b))

static inline void *os_memdup(const void *src, size_t len)
{
    void *r = rtw_sae_hostap_malloc(len);

    if (r && len)
        memcpy(r, src, len);
    return r;
}

static inline void *os_calloc(size_t nmemb, size_t size)
{
    if (size && nmemb > (~(size_t)0) / size)
        return NULL;
    return rtw_sae_hostap_zalloc(nmemb * size);
}

static inline void *os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
    if (size && nmemb > (~(size_t)0) / size)
        return NULL;
    return rtw_sae_hostap_realloc(ptr, nmemb * size);
}

#endif
