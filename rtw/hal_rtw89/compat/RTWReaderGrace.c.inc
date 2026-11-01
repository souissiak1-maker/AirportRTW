/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Small read-side grace-period implementation for this HAL's NAPI and worker
 * threads. No callback/writer lock is taken by readers. Writers unlink first,
 * then wait outside a read section; pointer publication is sequentially atomic.
 */
static unsigned rtw89_readers;
void rtw89_compat_read_lock(void)
{__atomic_fetch_add(&rtw89_readers,1,__ATOMIC_SEQ_CST);}
void rtw89_compat_read_unlock(void)
{__atomic_fetch_sub(&rtw89_readers,1,__ATOMIC_SEQ_CST);}
void rtw89_compat_synchronize_rcu(void)
{while(__atomic_load_n(&rtw89_readers,__ATOMIC_SEQ_CST))IOSleep(1);}
struct rtw89_reclaim {
    struct work_struct work;
    struct rcu_head *head;
    void (*function)(struct rcu_head *);
    void *allocation;
};
static void rtw89_reclaim_run(struct work_struct *work)
{
    struct rtw89_reclaim *pending=container_of(work,struct rtw89_reclaim,work);
    rtw89_compat_synchronize_rcu();
    if(pending->function)pending->function(pending->head);
    else kfree(pending->allocation);
    kfree(pending);
}
static void rtw89_reclaim_queue(struct rcu_head *head,void (*function)(struct rcu_head *),void *allocation)
{
    struct rtw89_reclaim *pending=(struct rtw89_reclaim *)kzalloc(sizeof(*pending),GFP_ATOMIC);
    if(!pending)return; // retain the target on allocation failure, never free a live reader
    pending->head=head;pending->function=function;pending->allocation=allocation;
    INIT_WORK(&pending->work,rtw89_reclaim_run);
    if(!queue_work(system_wq,&pending->work))kfree(pending); // target remains retained
}
void rtw89_compat_defer_free(void *allocation)
{if(allocation)rtw89_reclaim_queue(NULL,NULL,allocation);}
void rtw89_compat_call_rcu(struct rcu_head *head,void (*function)(struct rcu_head *))
{if(head && function)rtw89_reclaim_queue(head,function,NULL);}
