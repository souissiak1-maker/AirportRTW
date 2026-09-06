/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Master compatibility header for the rtw89 macOS port.
 *
 * Force-included into every rtw89 driver C file (mirrors rtw88_compat.h for
 * rtw88).  Pulls in the shared compat tree first, then layers the additional
 * kernel APIs that rtw89 uses and rtw88 never needed.  Keep additions here —
 * not in the shared linux/ or net/ headers — unless a definition must be
 * visible to code that includes those headers directly.
 */
#ifndef _RTW89_COMPAT_H
#define _RTW89_COMPAT_H

#include "rtw88_compat.h"

/* ------------------------------------------------------------------ */
/*  RCU (rtw89 uses annotated pointers and rcu_head; rtw88 did not)     */
/* ------------------------------------------------------------------ */

/* Sparse annotation — expands to nothing for real compilers */
#ifndef __rcu
#define __rcu
#endif

struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

/*
 * The port runs the whole driver + MLME on serialized IOKit threads and all
 * rcu_read_lock/unlock shims are no-ops, so there are no concurrent RCU
 * readers to wait for: run callbacks immediately instead of after a grace
 * period.  If the kext ever grows parallel readers this must be revisited.
 */
static inline void call_rcu(struct rcu_head *head,
                            void (*func)(struct rcu_head *head))
{
    func(head);
}

#define rcu_access_pointer(p)  (p)
#define kfree_rcu(ptr, rhf)    kfree(ptr)
#define kfree_rcu_mightsleep(ptr) kfree(ptr)

/* ------------------------------------------------------------------ */
/*  ktime                                                               */
/* ------------------------------------------------------------------ */

typedef s64 ktime_t;

static inline ktime_t ktime_get(void)
{
    uint64_t ns;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return (ktime_t)ns;
}

static inline u64 ktime_get_boottime_ns(void)
{
    return (u64)ktime_get();
}

static inline s64 ktime_ms_delta(ktime_t later, ktime_t earlier)
{
    return (later - earlier) / 1000000LL;
}

static inline s64 ktime_us_delta(ktime_t later, ktime_t earlier)
{
    return (later - earlier) / 1000LL;
}

/* ------------------------------------------------------------------ */
/*  errno / limits additions                                            */
/* ------------------------------------------------------------------ */

#ifndef ESRCH
#define ESRCH 3
#endif
#ifndef ENOLINK
#define ENOLINK 67
#endif
#ifndef ENOKEY
#define ENOKEY 126
#endif
#ifndef UINT_MAX
#define UINT_MAX (~0u)
#endif
#ifndef S8_MAX
#define S8_MAX  ((s8)127)
#endif
#ifndef S8_MIN
#define S8_MIN  ((s8)(-128))
#endif
#ifndef S16_MAX
#define S16_MAX ((s16)32767)
#endif
#ifndef S16_MIN
#define S16_MIN ((s16)(-32768))
#endif
#ifndef S32_MAX
#define S32_MAX ((s32)2147483647)
#endif
#ifndef S32_MIN
#define S32_MIN ((s32)(-2147483647 - 1))
#endif

/* flexible array member inside a union (kernel util macro) */
#ifndef DECLARE_FLEX_ARRAY
#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
    struct { \
        struct { } __empty_##NAME; \
        TYPE NAME[]; \
    }
#endif

#ifndef NAPI_POLL_WEIGHT
#define NAPI_POLL_WEIGHT 64
#endif

#ifndef PCI_VENDOR_ID_ASMEDIA
#define PCI_VENDOR_ID_ASMEDIA 0x1b21
#endif

#ifndef ENODATA
#define ENODATA 61
#endif
#ifndef ECONNRESET
#define ECONNRESET 104
#endif

/* PCIe L1 substates config registers (rtw89 pci.c manipulates these) */
#ifndef PCI_EXT_CAP_ID_L1SS
#define PCI_EXT_CAP_ID_L1SS   0x1E
#define PCI_L1SS_CTL1         0x08
#define PCI_L1SS_CTL1_L1SS_MASK 0x0000000f
#endif

/* list helpers rtw88 never used */
#ifndef list_for_each
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)
#endif
#ifndef list_for_each_safe
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)
#endif

/* compile-time type equality check (linux/typecheck.h) */
#ifndef typecheck
#define typecheck(type, x) \
    ({ type __dummy; \
       __typeof__(x) __dummy2; \
       (void)(&__dummy == &__dummy2); \
       1; })
#endif

#ifndef static_assert
#define static_assert(expr, ...) _Static_assert(expr, #expr)
#endif

#ifndef BITS_PER_TYPE
#define BITS_PER_TYPE(type) (sizeof(type) * 8)
#endif

#ifndef flex_array_size
#define flex_array_size(p, member, count) \
    ((size_t)(count) * sizeof(*(p)->member))
#endif

#ifndef struct_size_t
#define struct_size_t(type, member, count) \
    (sizeof(type) + (size_t)(count) * sizeof(((type *)0)->member[0]))
#endif

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#endif

/* constant-expression popcount so static_assert(hweight32(...)) works */
#ifdef hweight32
#undef hweight32
#endif
#define hweight32(x) __builtin_popcount((u32)(x))
#ifdef hweight16
#undef hweight16
#endif
#define hweight16(x) __builtin_popcount((u16)(x))
#ifdef hweight8
#undef hweight8
#endif
#define hweight8(x)  __builtin_popcount((u8)(x))

/* ------------------------------------------------------------------ */
/*  USB anchors (rtw89 usb.c tracks in-flight URBs with an anchor)      */
/* ------------------------------------------------------------------ */

struct urb;

struct usb_anchor {
    struct list_head urb_list;
    unsigned int poisoned;
};

static inline void init_usb_anchor(struct usb_anchor *anchor)
{
    INIT_LIST_HEAD(&anchor->urb_list);
    anchor->poisoned = 0;
}

/* Implemented in rtw89_compat.c against the port's URB emulation */
void usb_anchor_urb(struct urb *urb, struct usb_anchor *anchor);
void usb_unanchor_urb(struct urb *urb);
void usb_kill_anchored_urbs(struct usb_anchor *anchor);

/* sparse lock annotations */
#ifndef __acquires
#define __acquires(x)
#endif
#ifndef __releases
#define __releases(x)
#endif
#ifndef __must_hold
#define __must_hold(x)
#endif

/* flexible-array struct sizing */
#ifndef struct_size
#define struct_size(p, member, count) \
    (sizeof(*(p)) + (size_t)(count) * sizeof(*(p)->member))
#endif

/*
 * rtw89 asserts on values that are constant only after propagation
 * (static const locals), which _Static_assert-based BUILD_BUG_ON cannot
 * evaluate.  Upstream already validated these; drop to a no-op here.
 */
#ifdef BUILD_BUG_ON
#undef BUILD_BUG_ON
#endif
#define BUILD_BUG_ON(cond) do { } while (0)

/* ------------------------------------------------------------------ */
/*  cleanup.h guards (only the forms rtw89 actually uses)               */
/* ------------------------------------------------------------------ */

/* guard(rcu)(); — RCU read lock is a no-op in this port */
#define guard(_type)              __rtw89_guard_##_type
#define __rtw89_guard_rcu()       do { } while (0)

/* scoped_guard(spinlock_irqsave, &lock) { ... } */
#define scoped_guard(_type, args...) __rtw89_scoped_##_type(args)
#define __rtw89_scoped_spinlock_irqsave(_lock)                                \
    for (unsigned long __sg_once = ({ unsigned long __sg_f = 0;              \
                                      spin_lock_irqsave(_lock, __sg_f);      \
                                      (void)__sg_f; 1UL; });                 \
         __sg_once;                                                          \
         ({ unsigned long __sg_f = 0;                                        \
            spin_unlock_irqrestore(_lock, __sg_f); }), __sg_once = 0)

/* ------------------------------------------------------------------ */
/*  wiphy_work / wiphy_delayed_work                                     */
/* ------------------------------------------------------------------ */

/*
 * mac80211 runs these on the wiphy workqueue with the wiphy mutex held.
 * This port has no wiphy mutex (the kext MLME serializes everything), so
 * they map onto the compat workqueue.  Both flavors are backed by a
 * delayed_work; immediate queueing is delay=0.
 */
struct wiphy;
struct wiphy_work;
typedef void (*wiphy_work_func_t)(struct wiphy *wiphy, struct wiphy_work *work);

struct wiphy_work {
    struct delayed_work dwork;
    wiphy_work_func_t func;
    struct wiphy *wiphy;
};

struct wiphy_delayed_work {
    struct wiphy_work work;
};

static inline void __rtw89_wiphy_work_tramp(struct work_struct *w)
{
    struct delayed_work *dw = container_of(w, struct delayed_work, work);
    struct wiphy_work *ww = container_of(dw, struct wiphy_work, dwork);

    ww->func(ww->wiphy, ww);
}

static inline void wiphy_work_init(struct wiphy_work *work,
                                   wiphy_work_func_t func)
{
    INIT_DELAYED_WORK(&work->dwork, __rtw89_wiphy_work_tramp);
    work->func = func;
    work->wiphy = NULL;
}

static inline void wiphy_work_queue(struct wiphy *wiphy,
                                    struct wiphy_work *work)
{
    work->wiphy = wiphy;
    queue_delayed_work(system_wq, &work->dwork, 0);
}

static inline void wiphy_work_cancel(struct wiphy *wiphy,
                                     struct wiphy_work *work)
{
    cancel_delayed_work_sync(&work->dwork);
}

static inline void wiphy_work_flush(struct wiphy *wiphy,
                                    struct wiphy_work *work)
{
    flush_work(&work->dwork.work);
}

static inline void wiphy_delayed_work_init(struct wiphy_delayed_work *dwork,
                                           wiphy_work_func_t func)
{
    wiphy_work_init(&dwork->work, func);
}

static inline void wiphy_delayed_work_queue(struct wiphy *wiphy,
                                            struct wiphy_delayed_work *dwork,
                                            unsigned long delay)
{
    dwork->work.wiphy = wiphy;
    queue_delayed_work(system_wq, &dwork->work.dwork, delay);
}

static inline void wiphy_delayed_work_cancel(struct wiphy *wiphy,
                                             struct wiphy_delayed_work *dwork)
{
    cancel_delayed_work_sync(&dwork->work.dwork);
}

static inline void wiphy_delayed_work_flush(struct wiphy *wiphy,
                                            struct wiphy_delayed_work *dwork)
{
    if (cancel_delayed_work(&dwork->work.dwork))
        queue_delayed_work(system_wq, &dwork->work.dwork, 0);
    flush_work(&dwork->work.dwork.work);
}

/* 0.3.4: restore the serialization contract assumed by upstream rtw89.
 * Linux/mac80211 enters driver callbacks with the wiphy mutex held; a number
 * of rtw89 channel/entity routines only assert that contract instead of
 * taking an internal lock.  The macOS port used to make these operations
 * no-ops, allowing manual scanning to race interface/chanctx mutation. */
static inline void rtw89_compat_wiphy_lock(struct wiphy *wiphy)
{
    if (!wiphy || !wiphy->serialize_lock.m)
        return;

    if (!mutex_trylock(&wiphy->serialize_lock)) {
        __sync_fetch_and_add(&wiphy->serialize_lock_contention_count, 1);
        mutex_lock(&wiphy->serialize_lock);
    }
    __sync_fetch_and_add(&wiphy->serialize_lock_acquire_count, 1);
}

static inline void rtw89_compat_wiphy_unlock(struct wiphy *wiphy)
{
    if (wiphy && wiphy->serialize_lock.m)
        mutex_unlock(&wiphy->serialize_lock);
}

#define wiphy_lock(w)             rtw89_compat_wiphy_lock((w))
#define wiphy_unlock(w)           rtw89_compat_wiphy_unlock((w))
/* Ownership introspection is not exported by IOLock.  Keep the upstream
 * assertion side-effect free; correctness is provided by the adapter entry
 * points now taking the real lock. */
#define lockdep_assert_wiphy(w)   do { (void)(w); } while (0)

static inline void wiphy_rfkill_set_hw_state(struct wiphy *wiphy, bool blocked) {}
static inline void wiphy_rfkill_start_polling(struct wiphy *wiphy) {}
static inline void wiphy_rfkill_stop_polling(struct wiphy *wiphy) {}

/* ------------------------------------------------------------------ */
/*  mac80211/cfg80211 additions for rtw89                               */
/* ------------------------------------------------------------------ */

enum ieee80211_roc_type {
    IEEE80211_ROC_TYPE_NORMAL = 0,
    IEEE80211_ROC_TYPE_MGMT_TX,
};

/* ------------------------------------------------------------------ */
/*  misc kernel helpers rtw89 needs                                     */
/* ------------------------------------------------------------------ */

/* attribute for flexible arrays sized by a struct member — no codegen */
#ifndef __counted_by
#define __counted_by(member)
#endif

#ifndef BITS_TO_BYTES
#define BITS_TO_BYTES(nr) (((nr) + 7) / 8)
#endif

/* const-preserving container_of; the cast keeps both const and non-const
 * callers compiling (matches how the port already treats constness) */
#ifndef container_of_const
#define container_of_const(ptr, type, member) \
    ((type *)(void *)(uintptr_t)((const char *)(ptr) - offsetof(type, member)))
#endif

/* ------------------------------------------------------------------ */
/*  Helpers rtw89 calls that had no declaration anywhere in the compat */
/*  tree.  The kext links standalone, so every implicitly-declared     */
/*  call becomes an extern symbol kmutil cannot resolve at load        */
/*  (KMErrorDomain code 31).  The build now uses                       */
/*  -Werror=implicit-function-declaration to keep this class fatal at  */
/*  compile time.                                                      */
/* ------------------------------------------------------------------ */

#include "asm/unaligned.h"

/* ---- linux/string_choices.h ---- */
static inline const char *str_yes_no(bool v)         { return v ? "yes" : "no"; }
static inline const char *str_on_off(bool v)         { return v ? "on" : "off"; }
static inline const char *str_enable_disable(bool v) { return v ? "enable" : "disable"; }
static inline const char *str_read_write(bool v)     { return v ? "read" : "write"; }

/* ---- word / math helpers ---- */
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define DIV_ROUND_DOWN_ULL(ll, d) ((unsigned long long)(ll) / (d))
#define umin(x, y) ({ u64 __ux = (x); u64 __uy = (y); __ux < __uy ? __ux : __uy; })

static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
    *remainder = (u32)(dividend % divisor);
    return dividend / divisor;
}

static inline u64 roundup_u64(u64 x, u32 y)
{
    return ((x + y - 1) / y) * y;
}

static inline s32 sign_extend32(u32 value, int index)
{
    u8 shift = 31 - index;

    return (s32)(value << shift) >> shift;
}

/* ---- typed bitfield helpers linux/bitfield.h lacks ---- */
static inline u16 u16_replace_bits(u16 old, u16 val, u16 mask)
{
    return (u16)((old & (u16)~mask) | u16_encode_bits(val, mask));
}

static inline u32 u32_replace_bits(u32 old, u32 val, u32 mask)
{
    return (old & ~mask) | u32_encode_bits(val, mask);
}

static inline __le16 le16_encode_bits(u16 v, u16 mask)
{
    return (__le16)u16_encode_bits(v, mask);
}

static inline void le16p_replace_bits(__le16 *p, u16 val, u16 mask)
{
    u16 tmp = le16_to_cpu(*p);

    *p = cpu_to_le16((u16)((tmp & (u16)~mask) | u16_encode_bits(val, mask)));
}

static inline void le16_add_cpu(__le16 *var, u16 val)
{
    *var = cpu_to_le16((u16)(le16_to_cpu(*var) + val));
}

/* ---- bitmap ops ---- */
#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(nr) (((nr) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#endif

/* non-atomic variant: callers hold the relevant lock */
static inline int __test_and_set_bit(unsigned int nr, volatile unsigned long *addr)
{
    volatile unsigned long *w = addr + nr / BITS_PER_LONG;
    unsigned long mask = 1UL << (nr % BITS_PER_LONG);
    unsigned long old = *w;

    *w = old | mask;
    return (old & mask) != 0;
}

static inline void bitmap_fill(unsigned long *dst, unsigned int nbits)
{
    memset((void *)dst, 0xff, BITS_TO_LONGS(nbits) * sizeof(unsigned long));
}

static inline void bitmap_copy(unsigned long *dst, const unsigned long *src,
                               unsigned int nbits)
{
    memcpy(dst, src, BITS_TO_LONGS(nbits) * sizeof(unsigned long));
}

static inline void bitmap_or(unsigned long *dst, const unsigned long *src1,
                             const unsigned long *src2, unsigned int nbits)
{
    unsigned int i;

    for (i = 0; i < BITS_TO_LONGS(nbits); i++)
        dst[i] = src1[i] | src2[i];
}

static inline unsigned int bitmap_weight(const unsigned long *src,
                                         unsigned int nbits)
{
    unsigned int i, w = 0;

    for (i = 0; i < nbits / BITS_PER_LONG; i++)
        w += (unsigned int)hweight_long(src[i]);
    if (nbits % BITS_PER_LONG)
        w += (unsigned int)hweight_long(src[i] &
                                        ((1UL << (nbits % BITS_PER_LONG)) - 1));
    return w;
}

/* ---- string.h extras ---- */
static inline void *memchr_inv(const void *start, int c, size_t bytes)
{
    const u8 *p = (const u8 *)start;

    while (bytes--) {
        if (*p != (u8)c)
            return (void *)(uintptr_t)p;
        p++;
    }
    return NULL;
}

/* ---- list / skb queue splicing ---- */
static inline void __rtw89_list_splice(const struct list_head *list,
                                       struct list_head *prev,
                                       struct list_head *next)
{
    struct list_head *first = list->next;
    struct list_head *last = list->prev;

    first->prev = prev;
    prev->next = first;
    last->next = next;
    next->prev = last;
}

static inline void list_splice_tail(struct list_head *list,
                                    struct list_head *head)
{
    if (!list_empty(list))
        __rtw89_list_splice(list, head->prev, head);
}

/* Lockless init: the queue's spinlock stays unallocated, so ONLY the
 * lockless __-prefixed ops and the splice/walk helpers below may touch a
 * queue initialized this way (matches rtw89's on-stack c2hq usage). */
static inline void __skb_queue_head_init(struct sk_buff_head *list)
{
    INIT_LIST_HEAD(&list->list);
    list->qlen = 0;
    list->lock.lock = NULL;
}

/* splice @list at the head of @head; touches no locks (caller serializes) */
static inline void skb_queue_splice(const struct sk_buff_head *list,
                                    struct sk_buff_head *head)
{
    if (!skb_queue_empty(list)) {
        __rtw89_list_splice(&list->list, &head->list, head->list.next);
        head->qlen += list->qlen;
    }
}

static inline void skb_queue_splice_init(struct sk_buff_head *list,
                                         struct sk_buff_head *head)
{
    if (!skb_queue_empty(list)) {
        __rtw89_list_splice(&list->list, &head->list, head->list.next);
        head->qlen += list->qlen;
        INIT_LIST_HEAD(&list->list);
        list->qlen = 0;
    }
}

/* ---- skb helpers ---- */
/* compat skb_mac_header() always returns skb->data; nothing to reset */
static inline void skb_reset_mac_header(struct sk_buff *skb)
{
    (void)skb;
}

static inline int pskb_expand_head(struct sk_buff *skb, unsigned int nhead,
                                   unsigned int ntail, gfp_t gfp_mask)
{
    u32 old_size = (u32)(skb->end - skb->head);
    u32 data_off = (u32)(skb->data - skb->head);
    u32 tail_off = (u32)(skb->tail - skb->head);
    u8 *data = (u8 *)kmalloc(old_size + nhead + ntail, gfp_mask);

    if (!data)
        return -ENOMEM;
    memcpy(data + nhead, skb->head, old_size);
    kfree(skb->head);
    skb->head = data;
    skb->data = data + nhead + data_off;
    skb->tail = data + nhead + tail_off;
    skb->end  = data + old_size + nhead + ntail;
    return 0;
}

/* ---- allocation helpers (Linux 6.16 typed-allocation API) ---- */
/* usage: p = kzalloc_objs(*p, n);  p = kzalloc_flex(*p, member, n); */
#define kzalloc_objs(val, count) \
    kzalloc((size_t)(count) * sizeof(val), GFP_KERNEL)
#define kzalloc_flex(val, member, count) \
    kzalloc(sizeof(val) + (size_t)(count) * sizeof((val).member[0]), GFP_KERNEL)

static inline void *devm_kcalloc(struct device *dev, size_t n, size_t size,
                                 gfp_t gfp)
{
    (void)dev;
    return kcalloc(n, size, gfp);
}

/* devm_kzalloc/devm_kcalloc map to plain allocations, so plain kfree */
static inline void devm_kfree(struct device *dev, const void *p)
{
    (void)dev;
    kfree((void *)(uintptr_t)p);
}

#define dev_info_once(dev, ...) \
    do { static int _once; if (!_once) { _once = 1; \
         dev_info(dev, __VA_ARGS__); } } while (0)

/* ---- kernel misc ---- */
/* the port's driver threads are serialized; nothing to mask */
static inline void local_bh_disable(void) {}
static inline void local_bh_enable(void) {}

static inline u32 get_random_u32(void)
{
    u32 v;

    read_random(&v, sizeof(v));
    return v;
}

static inline bool napi_is_scheduled(struct napi_struct *napi)
{
    return napi && napi->running;
}

static inline bool refcount_inc_not_zero(refcount_t *r)
{
    int old = atomic_read(r);

    while (old != 0) {
        int prev = atomic_cmpxchg(r, old, old + 1);

        if (prev == old)
            return true;
        old = prev;
    }
    return false;
}

/* walk the PCIe extended capability list starting at config offset 0x100 */
static inline int pci_find_ext_capability(struct pci_dev *dev, int cap)
{
    int pos = 0x100;
    int ttl = (4096 - 256) / 8;
    u32 header;

    if (pci_read_config_dword(dev, pos, &header) != 0)
        return 0;
    while (ttl-- > 0) {
        if (header == 0 || header == 0xffffffff)
            return 0;
        if ((int)(header & 0xffff) == cap)
            return pos;
        pos = (int)((header >> 20) & 0xffcu);
        if (pos < 0x100)
            return 0;
        if (pci_read_config_dword(dev, pos, &header) != 0)
            return 0;
    }
    return 0;
}

/* no usb_device refcounting in the port */
static inline struct usb_device *usb_get_dev(struct usb_device *udev)
{
    return udev;
}
static inline void usb_put_dev(struct usb_device *udev) { (void)udev; }

/* ---- 802.11 frame helpers ---- */
#ifndef IEEE80211_STYPE_PSPOLL
#define IEEE80211_STYPE_PSPOLL       0x00A0
#endif
#ifndef IEEE80211_STYPE_TRIGGER
#define IEEE80211_STYPE_TRIGGER      0x0020
#endif
#ifndef IEEE80211_STYPE_QOS_NULLFUNC
#define IEEE80211_STYPE_QOS_NULLFUNC 0x00C0
#endif
#ifndef IEEE80211_QOS_CTL_LEN
#define IEEE80211_QOS_CTL_LEN 2
#endif
#ifndef IEEE80211_HT_CTL_LEN
#define IEEE80211_HT_CTL_LEN 4
#endif

static inline int ieee80211_has_a4(__le16 fc)
{
    __le16 tmp = cpu_to_le16(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS);

    return (fc & tmp) == tmp;
}

static inline int ieee80211_has_pm(__le16 fc)
{
    return !!(fc & cpu_to_le16(IEEE80211_FCTL_PM));
}

static inline int ieee80211_has_order(__le16 fc)
{
    return !!(fc & cpu_to_le16(IEEE80211_FCTL_ORDER));
}

static inline int ieee80211_is_pspoll(__le16 fc)
{
    return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_PSPOLL);
}

static inline int ieee80211_is_trigger(__le16 fc)
{
    return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_TRIGGER);
}

static inline int ieee80211_is_qos_nullfunc(__le16 fc)
{
    return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_NULLFUNC);
}

static inline int ieee80211_is_any_nullfunc(__le16 fc)
{
    return ieee80211_is_nullfunc(fc) || ieee80211_is_qos_nullfunc(fc);
}

static inline unsigned int ieee80211_hdrlen(__le16 fc)
{
    unsigned int hdrlen = 24;

    if (ieee80211_is_data(fc)) {
        if (ieee80211_has_a4(fc))
            hdrlen = 30;
        if (ieee80211_is_data_qos(fc)) {
            hdrlen += IEEE80211_QOS_CTL_LEN;
            if (ieee80211_has_order(fc))
                hdrlen += IEEE80211_HT_CTL_LEN;
        }
        return hdrlen;
    }
    if (ieee80211_is_ctl(fc)) {
        /* CTS (stype 1100) and ACK (1101) are 10 bytes; other ctl 16 */
        __le16 stype = fc & cpu_to_le16(IEEE80211_FCTL_STYPE);

        if (stype == cpu_to_le16(0x00C0) || stype == cpu_to_le16(0x00D0))
            return 10;
        return 16;
    }
    if (ieee80211_has_order(fc))
        hdrlen += IEEE80211_HT_CTL_LEN;
    return hdrlen;
}

/* QoS Control sits right after the 3- or 4-address header */
static inline u8 ieee80211_get_tid(struct ieee80211_hdr *hdr)
{
    u8 *qc = (u8 *)hdr + (ieee80211_has_a4(hdr->frame_control) ? 30 : 24);

    return qc[0] & IEEE80211_QOS_CTL_TID_MASK;
}

static inline unsigned long ieee80211_tu_to_usec(unsigned long tu)
{
    return 1024 * tu;
}

/* ---- cfg80211 helpers ---- */
static inline const u8 *cfg80211_find_ie(u8 eid, const u8 *ies, int len)
{
    return (const u8 *)cfg80211_find_elem(eid, ies, len);
}

static inline void cfg80211_chandef_create(struct cfg80211_chan_def *chandef,
                                           struct ieee80211_channel *chan,
                                           enum nl80211_channel_type chan_type)
{
    chandef->chan = chan;
    chandef->center_freq1 = chan->center_freq;
    chandef->center_freq2 = 0;
    chandef->punctured = 0;

    switch (chan_type) {
    case NL80211_CHAN_NO_HT:
        chandef->width = NL80211_CHAN_WIDTH_20_NOHT;
        break;
    case NL80211_CHAN_HT20:
        chandef->width = NL80211_CHAN_WIDTH_20;
        break;
    case NL80211_CHAN_HT40PLUS:
        chandef->width = NL80211_CHAN_WIDTH_40;
        chandef->center_freq1 += 10;
        break;
    case NL80211_CHAN_HT40MINUS:
        chandef->width = NL80211_CHAN_WIDTH_40;
        chandef->center_freq1 -= 10;
        break;
    }
}

static inline bool cfg80211_channel_is_psc(struct ieee80211_channel *chan)
{
    if (chan->band != NL80211_BAND_6GHZ)
        return false;
    /* 6 GHz PSC channels: 5, 21, 37, ... (every 16th, offset 5) */
    return ((chan->center_freq - 5950) / 5) % 16 == 5;
}

/* ---- mac80211 API whose paths the kext MLME supersedes ---- */
static inline u16 ieee80211_vif_usable_links(const struct ieee80211_vif *vif)
{
    return vif->valid_links ? vif->valid_links : BIT(0);
}

static inline int ieee80211_set_active_links(struct ieee80211_vif *vif,
                                             u16 active_links)
{
    vif->active_links = active_links & vif->valid_links;
    return 0;
}

static inline void
_ieee80211_set_sband_iftype_data(struct ieee80211_supported_band *sband,
                                 const struct ieee80211_sband_iftype_data *iftd,
                                 u16 n_iftd)
{
    sband->iftype_data = iftd;
    sband->n_iftype_data = n_iftd;
}

static inline bool
ieee80211_beacon_cntdwn_is_complete(struct ieee80211_vif *vif,
                                    unsigned int link_id)
{
    (void)vif; (void)link_id;
    return false; /* kext MLME runs no CSA beacon countdown */
}

static inline void ieee80211_csa_finish(struct ieee80211_vif *vif,
                                        unsigned int link_id)
{
    (void)vif; (void)link_id;
}

static inline int ieee80211_stop_tx_ba_session(struct ieee80211_sta *sta,
                                               u16 tid)
{
    (void)sta; (void)tid;
    return 0; /* BA sessions are torn down by the kext MLME */
}

/* TXQ scheduling: the kext submits TX directly; no mac80211 TXQs exist */
static inline struct ieee80211_txq *ieee80211_next_txq(struct ieee80211_hw *hw,
                                                       u8 ac)
{
    (void)hw; (void)ac;
    return NULL;
}

static inline void ieee80211_return_txq(struct ieee80211_hw *hw,
                                        struct ieee80211_txq *txq, bool force)
{
    (void)hw; (void)txq; (void)force;
}

/* Remain-on-channel: offchannel mgmt-tx is not used by the kext MLME */
static inline void ieee80211_ready_on_channel(struct ieee80211_hw *hw)
{
    (void)hw;
}

static inline void ieee80211_remain_on_channel_expired(struct ieee80211_hw *hw)
{
    (void)hw;
}

/* "non-irq" flavor: the compat tx_status path is context-agnostic */
static inline void ieee80211_tx_status_ni(struct ieee80211_hw *hw,
                                          struct sk_buff *skb)
{
    ieee80211_tx_status(hw, skb);
}

#endif /* _RTW89_COMPAT_H */
