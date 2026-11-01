/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
typedef pthread_mutex_t IOSimpleLock;typedef unsigned long IOInterruptState;
typedef void *thread_call_param_t;typedef bool boolean_t;
typedef void (*thread_call_func_t)(void*,void*);
struct raw_call {thread_call_func_t function;void *owner;bool pending,running;};
typedef struct raw_call *thread_call_t;
static pthread_mutex_t raw_lock=PTHREAD_MUTEX_INITIALIZER;
static void *IOMalloc(size_t n){return calloc(1,n);}static void IOFree(void *p,size_t n){(void)n;free(p);}
static IOSimpleLock *IOSimpleLockAlloc(void){IOSimpleLock *p=malloc(sizeof(*p));assert(!pthread_mutex_init(p,0));return p;}
static void IOSimpleLockFree(IOSimpleLock*p){pthread_mutex_destroy(p);free(p);}
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock*p){pthread_mutex_lock(p);return 0;}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock*p,IOInterruptState f){(void)f;pthread_mutex_unlock(p);}
static void IOSleep(unsigned n){usleep(n*1000);}
static thread_call_t thread_call_allocate(thread_call_func_t f,void*p){thread_call_t c=calloc(1,sizeof(*c));c->function=f;c->owner=p;return c;}
enum {THREAD_CALL_PRIORITY_HIGH=0,THREAD_CALL_OPTIONS_ONCE=1};
static thread_call_t thread_call_allocate_with_options(thread_call_func_t f,void*p,int priority,unsigned options){assert(priority==0 && options==1);return thread_call_allocate(f,p);}
static boolean_t thread_call_enter(thread_call_t c){pthread_mutex_lock(&raw_lock);bool was=c->pending;c->pending=true;pthread_mutex_unlock(&raw_lock);return was;}
static boolean_t thread_call_enter_delayed(thread_call_t c,uint64_t d){(void)d;return thread_call_enter(c);}
static boolean_t thread_call_cancel(thread_call_t c){pthread_mutex_lock(&raw_lock);bool was=c->pending;c->pending=false;pthread_mutex_unlock(&raw_lock);return was;}
static boolean_t thread_call_free(thread_call_t c){pthread_mutex_lock(&raw_lock);bool ok=!c->pending&&!c->running;pthread_mutex_unlock(&raw_lock);if(ok)free(c);return ok;}
#include "../rtw/hal_rtw89/compat/RTWManagedCall.h"
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static bool dispatch_entered,allow_entry,owner_entered,allow_owner,wait_done;static unsigned calls;
static void callback(void*p,void*q){(void)q;assert(p==(void*)(uintptr_t)42);pthread_mutex_lock(&lock);++calls;owner_entered=true;
 pthread_cond_broadcast(&changed);while(!allow_owner)pthread_cond_wait(&changed,&lock);pthread_mutex_unlock(&lock);}
static void *dispatch(void*p){thread_call_t c=((struct rtw_managed_call*)p)->raw;
 pthread_mutex_lock(&raw_lock);assert(c->pending);c->pending=false;c->running=true;pthread_mutex_unlock(&raw_lock);
 pthread_mutex_lock(&lock);dispatch_entered=true;pthread_cond_broadcast(&changed);while(!allow_entry)pthread_cond_wait(&changed,&lock);pthread_mutex_unlock(&lock);
 c->function(c->owner,0);pthread_mutex_lock(&raw_lock);c->running=false;pthread_mutex_unlock(&raw_lock);return 0;}
static void *cancel(void*p){rtw_managed_cancel(p,true,false);pthread_mutex_lock(&lock);wait_done=true;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);return 0;}
static void wait_for(bool*p){pthread_mutex_lock(&lock);while(!*p)pthread_cond_wait(&changed,&lock);pthread_mutex_unlock(&lock);}
int main(void){
 thread_call_t c=rtw_managed_allocate(callback,(void*)(uintptr_t)42);assert(c);
 assert(!rtw_managed_enter(c,0,false));assert(rtw_managed_enter(c,1,true));assert(((struct rtw_managed_call*)c)->outstanding==1);
 assert(rtw_managed_cancel(c,true,false));assert(!((struct rtw_managed_call*)c)->outstanding);
 // Expired and removed from XNU's pending queue, but not yet in our trampoline.
 assert(!rtw_managed_enter(c,0,false));pthread_t worker,waiter;pthread_create(&worker,0,dispatch,c);wait_for(&dispatch_entered);
 pthread_create(&waiter,0,cancel,c);usleep(10000);pthread_mutex_lock(&lock);assert(!wait_done);allow_entry=true;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);
 pthread_join(worker,0);pthread_join(waiter,0);assert(!calls); // cancelled before owner access
 // A genuinely running callback must finish, even if it takes >500 microseconds.
 dispatch_entered=owner_entered=wait_done=false;allow_owner=false;allow_entry=true;
 assert(!rtw_managed_enter(c,0,false));pthread_create(&worker,0,dispatch,c);wait_for(&owner_entered);
 pthread_create(&waiter,0,cancel,c);usleep(10000);pthread_mutex_lock(&lock);assert(!wait_done);allow_owner=true;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&lock);
 pthread_join(worker,0);pthread_join(waiter,0);assert(calls==1);
 assert(rtw_managed_free(c));assert(!rtw_managed_enter(c,0,false));
 rtw_managed_cleanup();assert(!rtw_managed_calls);
 puts("PASS: coalescing, pre-trampoline cancellation, running callback barrier and retired handle rejection");
}
