/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW89_MANAGED_CALL_H
#define RTW89_MANAGED_CALL_H
/* Private opaque handles: never pass these to XNU directly. Every enqueue owns
 * one outstanding reference before XNU can start its trampoline. Cancellation
 * either removes that reference or waits for the trampoline to release it.
 * Metadata outlives embedded Linux timers and is reclaimed at compat shutdown.
 * Callers must stop external producers before freeing their callback owner.
 */
struct rtw_managed_call {
    thread_call_t raw;
    thread_call_func_t function;
    thread_call_param_t owner;
    IOSimpleLock *lock;
    unsigned outstanding, canceling;
    bool retired;
    struct rtw_managed_call *next;
};
static struct rtw_managed_call *rtw_managed_calls;
static void rtw_managed_trampoline(thread_call_param_t p0,thread_call_param_t p1)
{
    struct rtw_managed_call *call=(struct rtw_managed_call *)p0;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(call->lock);
    bool execute=!call->canceling && !call->retired;
    thread_call_func_t function=call->function;
    thread_call_param_t owner=call->owner;
    IOSimpleLockUnlockEnableInterrupt(call->lock,irq);
    if(execute)function(owner,p1);
    irq=IOSimpleLockLockDisableInterrupt(call->lock);
    --call->outstanding;
    IOSimpleLockUnlockEnableInterrupt(call->lock,irq);
}
static thread_call_t rtw_managed_allocate(thread_call_func_t function,thread_call_param_t owner)
{
    struct rtw_managed_call *call=IOMalloc(sizeof(*call));
    if(!call)return NULL;
    bzero(call,sizeof(*call));call->function=function;call->owner=owner;
    call->lock=IOSimpleLockAlloc();
    if(!call->lock){IOFree(call,sizeof(*call));return NULL;}
    call->raw=thread_call_allocate_with_options(rtw_managed_trampoline,(thread_call_param_t)call,
        THREAD_CALL_PRIORITY_HIGH,THREAD_CALL_OPTIONS_ONCE);
    if(!call->raw){IOSimpleLockFree(call->lock);IOFree(call,sizeof(*call));return NULL;}
    do {call->next=__atomic_load_n(&rtw_managed_calls,__ATOMIC_ACQUIRE);}
    while(!__atomic_compare_exchange_n(&rtw_managed_calls,&call->next,call,false,__ATOMIC_RELEASE,__ATOMIC_RELAXED));
    return (thread_call_t)call;
}
static boolean_t rtw_managed_enter(thread_call_t handle,uint64_t deadline,bool delayed)
{
    struct rtw_managed_call *call=(struct rtw_managed_call *)handle;
    if(!call)return false;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(call->lock);
    if(call->retired || call->canceling){IOSimpleLockUnlockEnableInterrupt(call->lock,irq);return false;}
    /* The trampoline cannot inspect the reference count until this lock drops. */
    boolean_t pending=delayed ? thread_call_enter_delayed(call->raw,deadline) : thread_call_enter(call->raw);
    if(!pending)++call->outstanding;
    IOSimpleLockUnlockEnableInterrupt(call->lock,irq);
    return pending;
}
static boolean_t rtw_managed_cancel(thread_call_t handle,bool wait,bool retire)
{
    struct rtw_managed_call *call=(struct rtw_managed_call *)handle;
    if(!call)return false;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(call->lock);
    ++call->canceling;if(retire)call->retired=true;
    boolean_t removed=call->raw && thread_call_cancel(call->raw);
    if(removed)--call->outstanding;
    IOSimpleLockUnlockEnableInterrupt(call->lock,irq);
    /* Do not substitute a fixed delay for this condition. Waiting while holding
     * a lock required by the callback remains prohibited, just as in Linux.
     * Synchronous self-cancellation is also prohibited by the caller contract. */
    for(;;) {
        irq=IOSimpleLockLockDisableInterrupt(call->lock);
        if(!wait || !call->outstanding){--call->canceling;IOSimpleLockUnlockEnableInterrupt(call->lock,irq);break;}
        IOSimpleLockUnlockEnableInterrupt(call->lock,irq);
        IOSleep(1);
    }
    return removed;
}
static boolean_t rtw_managed_free(thread_call_t handle)
{
    struct rtw_managed_call *call=(struct rtw_managed_call *)handle;
    if(!call)return false;
    rtw_managed_cancel(handle,true,true);
    if(!call->raw)return true;
    if(!thread_call_free(call->raw))return false;
    call->raw=NULL;return true;
}
static void rtw_managed_cleanup(void)
{
    /* compat exit: external producers and both workqueue threads have stopped.
     * Cancelled reusable Linux timers may still have allocated call metadata. */
    struct rtw_managed_call *call=__atomic_exchange_n(&rtw_managed_calls,NULL,__ATOMIC_ACQ_REL);
    while(call){struct rtw_managed_call *next=call->next;
        if(rtw_managed_free((thread_call_t)call)){
            IOSimpleLockFree(call->lock);IOFree(call,sizeof(*call));
        } /* Fail closed: retain metadata if XNU refuses to release its call. */
        call=next;
    }
}
#endif
