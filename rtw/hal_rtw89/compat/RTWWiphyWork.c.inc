/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * One stable dispatcher/timer per wiphy; no thread-call retains a VIF's work
 * node. Queue producers may run without the wiphy mutex. Cancellation/flush
 * require that mutex, matching cfg80211, so a removed node cannot be running.
 */
struct rtw89_wiphy_queue {
    struct wiphy *wiphy;
    IOSimpleLock *lock;
    struct list_head pending;
    struct work_struct dispatch;
    struct timer_list timer;
    bool stopping;
};
static void rtw89_wiphy_timer(struct timer_list *timer)
{
    struct rtw89_wiphy_queue *queue=container_of(timer,struct rtw89_wiphy_queue,timer);
    queue_work(system_wq,&queue->dispatch);
}
static void rtw89_wiphy_dispatch(struct work_struct *work)
{
    struct rtw89_wiphy_queue *queue=container_of(work,struct rtw89_wiphy_queue,dispatch);
    wiphy_lock(queue->wiphy);
    unsigned budget=64;
    bool again=false;
    while(budget--) {
        struct wiphy_work *due=NULL;
        unsigned long earliest=0;bool have_deadline=false;
        IOInterruptState irq=IOSimpleLockLockDisableInterrupt(queue->lock);
        if(!queue->stopping) {
            struct list_head *entry;
            list_for_each(entry,&queue->pending) {
                struct wiphy_work *node=container_of(entry,struct wiphy_work,entry);
                if(time_after_eq(jiffies,node->deadline)){due=node;break;}
                if(!have_deadline || time_before(node->deadline,earliest)) {
                    earliest=node->deadline;have_deadline=true;
                }
            }
        }
        if(due){list_del_init(&due->entry);due->queued=false;}
        IOSimpleLockUnlockEnableInterrupt(queue->lock,irq);
        if(!due){if(have_deadline)mod_timer(&queue->timer,earliest);again=false;break;}
        /* The callback may free its enclosing object, including this node. */
        wiphy_work_func_t function=due->func;function(queue->wiphy,due);again=true;
    }
    wiphy_unlock(queue->wiphy);
    if(again)queue_work(system_wq,&queue->dispatch);
}
bool rtw89_wiphy_queue_init(struct wiphy *wiphy)
{
    struct rtw89_wiphy_queue *queue=(struct rtw89_wiphy_queue *)kzalloc(sizeof(*queue),GFP_KERNEL);
    if(!queue)return false;
    queue->lock=IOSimpleLockAlloc();
    if(!queue->lock){kfree(queue);return false;}
    queue->wiphy=wiphy;INIT_LIST_HEAD(&queue->pending);
    INIT_WORK(&queue->dispatch,rtw89_wiphy_dispatch);
    timer_setup(&queue->timer,rtw89_wiphy_timer,0);
    if(!queue->timer.call){IOSimpleLockFree(queue->lock);kfree(queue);return false;}
    wiphy->workqueue=queue;return true;
}
void rtw89_wiphy_queue(struct wiphy *wiphy,struct wiphy_work *work,unsigned long delay)
{
    if(!wiphy || !work || !wiphy->workqueue)return;
    struct rtw89_wiphy_queue *queue=wiphy->workqueue;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(queue->lock);
    if(!queue->stopping && !work->queued) {
        work->deadline=jiffies+delay;work->queued=true;
        list_add_tail(&work->entry,&queue->pending);
    }
    IOSimpleLockUnlockEnableInterrupt(queue->lock,irq);
    // The dispatcher is the only timer producer; it recomputes the next expiry.
    queue_work(system_wq,&queue->dispatch);
}
void rtw89_wiphy_cancel(struct wiphy *wiphy,struct wiphy_work *work)
{
    if(!wiphy || !work || !wiphy->workqueue)return;
    struct rtw89_wiphy_queue *queue=wiphy->workqueue;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(queue->lock);
    if(work->queued){list_del_init(&work->entry);work->queued=false;}
    IOSimpleLockUnlockEnableInterrupt(queue->lock,irq);
}
void rtw89_wiphy_flush(struct wiphy *wiphy,struct wiphy_work *work)
{
    if(!wiphy || !work || !wiphy->workqueue)return;
    struct rtw89_wiphy_queue *queue=wiphy->workqueue;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(queue->lock);
    bool execute=work->queued && !queue->stopping;
    if(work->queued){list_del_init(&work->entry);work->queued=false;}
    IOSimpleLockUnlockEnableInterrupt(queue->lock,irq);
    // Caller owns wiphy mutex; invoking inline avoids waiting for that mutex.
    if(execute){wiphy_work_func_t function=work->func;function(wiphy,work);}
}
void rtw89_wiphy_queue_shutdown(struct wiphy *wiphy)
{
    if(!wiphy || !wiphy->workqueue)return;
    struct rtw89_wiphy_queue *queue=wiphy->workqueue;
    wiphy_lock(wiphy);
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(queue->lock);
    queue->stopping=true;
    while(!list_empty(&queue->pending)) {
        struct wiphy_work *node=container_of(queue->pending.next,struct wiphy_work,entry);
        list_del_init(&node->entry);node->queued=false;
    }
    IOSimpleLockUnlockEnableInterrupt(queue->lock,irq);
    wiphy_unlock(wiphy);
    // A dispatcher already waiting for wiphy can now finish without any node.
    del_timer_sync(&queue->timer);cancel_work_sync(&queue->dispatch);
    wiphy->workqueue=NULL;IOSimpleLockFree(queue->lock);kfree(queue);
}
