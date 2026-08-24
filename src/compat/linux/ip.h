/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_IP_H
#define _RTW88_COMPAT_IP_H

#include "types.h"
#include "skbuff.h"

/* Network byte-order helpers (macOS is little-endian on all supported CPUs) */
#ifndef htons
#define htons(x) ((__be16)__builtin_bswap16((u16)(x)))
#define ntohs(x) ((u16)__builtin_bswap16((u16)(x)))
#define htonl(x) ((__be32)__builtin_bswap32((u32)(x)))
#define ntohl(x) ((u32)__builtin_bswap32((u32)(x)))
#endif

#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17

struct iphdr {
    u8      ihl:4,
            version:4;
    u8      tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    u8      ttl;
    u8      protocol;
    __be16  check;
    __be32  saddr;
    __be32  daddr;
} __packed;

/* The kext never sets skb->network_header; callers in rtw89/rtw88 guard all
 * ip_hdr() uses behind skb->protocol checks which stay 0 in this port, so
 * these accessors exist for compilation and treat skb->data as the header. */
static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
    return skb->data;
}

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *)skb_network_header(skb);
}

#endif /* _RTW88_COMPAT_IP_H */
