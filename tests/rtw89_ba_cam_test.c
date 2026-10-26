/* Exercise the production CAM allocator with a small Linux-list/bitmap fixture. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define __RTW89_CORE_H__
typedef uint8_t u8;
struct list_head { struct list_head *next, *prev; };
static void init(struct list_head *h) { h->next=h->prev=h; }
#define INIT_LIST_HEAD(h) init(h)
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev=h->prev; n->next=h; h->prev->next=n; h->prev=n; }
static void list_del(struct list_head *n)
{ n->prev->next=n->next; n->next->prev=n->prev; }
#define entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(e,h,m) \
 for(e=entry((h)->next,__typeof__(*e),m); &e->m!=(h); e=entry(e->m.next,__typeof__(*e),m))
#define list_for_each_entry_safe(e,t,h,m) \
 for(e=entry((h)->next,__typeof__(*e),m),t=entry(e->m.next,__typeof__(*e),m); \
     &e->m!=(h); e=t,t=entry(t->m.next,__typeof__(*t),m))
#define for_each_set_bit(i,map,n) for(i=0;i<(n);++i) if((*(map))&(1UL<<(i)))
#define lockdep_assert_wiphy(w) ((void)0)
struct rtw89_ba_cam_entry { struct list_head list; u8 tid; };
struct rtw89_sta_link { struct list_head ba_cam_list; };
struct rtw89_chip_info { u8 bacam_num; };
struct rtw89_cam_info { unsigned long ba_cam_map[1]; struct rtw89_ba_cam_entry ba_cam_entry[2]; };
struct rtw89_dev { const struct rtw89_chip_info *chip; struct rtw89_cam_info cam_info; };
static u8 rtw89_core_acquire_bit_map(unsigned long *m, unsigned long size)
{ for(unsigned i=0;i<size;++i) if(!(*m&(1UL<<i))) { *m|=1UL<<i; return i; } return size; }
static void rtw89_core_release_bit_map(unsigned long *m,u8 i) { *m&=~(1UL<<i); }
#include "../rtw/hal_rtw89/driver/ba_cam.c"

static void stop_all(struct rtw89_dev *d,struct rtw89_sta_link *s)
{
    rtw89_core_purge_sta_ba_entries(d,s);
    assert(s->ba_cam_list.next==&s->ba_cam_list && s->ba_cam_list.prev==&s->ba_cam_list);
}
int main(void)
{
    const struct rtw89_chip_info chip={2}; /* RTL8852A has two static slots. */
    struct rtw89_dev d={.chip=&chip};
    u8 first,second,index;
    for(unsigned cycle=0;cycle<1000;++cycle) {
        struct rtw89_sta_link *a=calloc(1,sizeof(*a)), *b=calloc(1,sizeof(*b));
        assert(a && b); init(&a->ba_cam_list); init(&b->ba_cam_list);
        assert(!rtw89_core_acquire_sta_ba_entry(&d,a,1,&first));
        /* Duplicate ADDBA must update one slot, not leak another list entry. */
        assert(!rtw89_core_acquire_sta_ba_entry(&d,a,1,&index) && index==first);
        assert(d.cam_info.ba_cam_map[0]==(1UL<<first));
        assert(!rtw89_core_release_sta_ba_entry(&d,a,1,&index) && index==first);
        assert(rtw89_core_release_sta_ba_entry(&d,a,1,&index)==-ENOENT);
        assert(!rtw89_core_acquire_sta_ba_entry(&d,a,1,&first));
        assert(!rtw89_core_acquire_sta_ba_entry(&d,b,2,&second) && second!=first);
        assert(rtw89_core_acquire_sta_ba_entry(&d,b,3,&index)==-ENOSPC);
        /* Replacing a non-priority TID detaches it from its original station. */
        assert(!rtw89_core_acquire_sta_ba_entry(&d,b,0,&index));
        stop_all(&d,a); free(a);
        stop_all(&d,b); free(b);
        assert(d.cam_info.ba_cam_map[0]==0);
        /* Reuse every CAM slot after station memory is freed; ASan catches stale links. */
        struct rtw89_sta_link next; init(&next.ba_cam_list);
        assert(!rtw89_core_acquire_sta_ba_entry(&d,&next,1,&index));
        assert(!rtw89_core_acquire_sta_ba_entry(&d,&next,2,&index));
        assert(!rtw89_core_acquire_sta_ba_entry(&d,&next,5,&index));
        stop_all(&d,&next);
    }
    return 0;
}
