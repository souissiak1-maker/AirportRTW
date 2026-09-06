/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_UDP_H
#define _RTW88_COMPAT_UDP_H

#include "types.h"
#include "ip.h"

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
} __packed;

/* Transport header derived from the IP header length; see note in ip.h —
 * only reachable when skb->protocol was set, which the kext never does. */
static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
    const struct iphdr *iph = ip_hdr(skb);
    return (struct udphdr *)(skb_network_header(skb) + iph->ihl * 4);
}

#endif /* _RTW88_COMPAT_UDP_H */
