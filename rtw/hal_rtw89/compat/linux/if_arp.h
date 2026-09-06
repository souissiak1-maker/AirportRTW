/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_IF_ARP_H
#define _RTW88_COMPAT_IF_ARP_H

#include "types.h"
#include "skbuff.h"
#include "ip.h"

#define ARPHRD_ETHER 1

#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2

struct arphdr {
    __be16 ar_hrd;   /* hardware address format */
    __be16 ar_pro;   /* protocol address format */
    u8     ar_hln;   /* hardware address length */
    u8     ar_pln;   /* protocol address length */
    __be16 ar_op;    /* opcode */
} __packed;

static inline struct arphdr *arp_hdr(const struct sk_buff *skb)
{
    return (struct arphdr *)skb_network_header(skb);
}

#endif /* _RTW88_COMPAT_IF_ARP_H */
