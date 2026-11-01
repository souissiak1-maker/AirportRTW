#!/usr/bin/env python3
"""Threaded execution of the production RTW89 dispatcher and cancellation."""
from pathlib import Path
import re,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
base=ROOT/'rtw/hal_rtw89/compat'
strip=lambda s:re.sub(r'^#include[^\n]*\n','',s,flags=re.M)
shim=(ROOT/'tests/host/rtw_workqueue_shim.hpp').read_text().replace('t->function=fn;t->active=0;', 't->function=fn;t->active=0;t->call=t;')
header=(base/'rtw89_compat.h').read_text();start=header.index('struct wiphy;\nstruct wiphy_work;');end=header.index('/* 0.3.4: restore',start)
source=(base/'rtw88_compat.c').read_text();a=source.index('static void wq_thread_fn(');b=source.index('\n/* ------------------------------------------------------------------ */\n/*  Timer',a)
extra=r'''
using IOSimpleLock=std::mutex;using IOInterruptState=unsigned;
static IOSimpleLock *IOSimpleLockAlloc(){return new IOSimpleLock;}
static void IOSimpleLockFree(IOSimpleLock*p){delete p;}
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock*p){p->lock();return 0;}
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock*p,IOInterruptState){p->unlock();}
static bool time_after_eq(unsigned long a,unsigned long b){return long(a-b)>=0;}
static bool time_before(unsigned long a,unsigned long b){return long(a-b)<0;}
#define list_for_each(p,h) for(p=(h)->next;p!=(h);p=p->next)
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
struct rcu_head {rcu_head*next;void(*function)(rcu_head*);};
static void IOSleep(unsigned ms){std::this_thread::sleep_for(std::chrono::milliseconds(ms));}
static void*kzalloc(size_t n,int){return calloc(1,n);}static void kfree(void*p){free(p);}
struct rtw89_wiphy_queue;
struct wiphy{std::mutex mutex;rtw89_wiphy_queue*workqueue=nullptr;std::atomic<thread_t>owner{0};};
static void wiphy_lock(wiphy*p){p->mutex.lock();p->owner=current_thread();}
static void wiphy_unlock(wiphy*p){p->owner=0;p->mutex.unlock();}
'''
scenario=r'''
struct Node {wiphy_work work;unsigned *calls;bool freeSelf=false;};
static std::atomic<unsigned> reclaimed{0};
static void reclaim(rcu_head*head){++reclaimed;delete head;}
static void callback(wiphy*p,wiphy_work*w){assert(p->owner==current_thread());auto*n=container_of(w,Node,work);++*n->calls;if(n->freeSelf)delete n;}
static Node *node(unsigned &count){auto*n=new Node;n->calls=&count;wiphy_work_init(&n->work,callback);return n;}
int main(){
 system_wq=alloc_workqueue("wiphy-test",0,1);wiphy radio;assert(rtw89_wiphy_queue_init(&radio));

 rtw89_compat_read_lock();rtw89_compat_read_lock();
 auto grace=std::async(std::launch::async,[]{rtw89_compat_synchronize_rcu();});
 rtw89_compat_call_rcu(new rcu_head{},reclaim);
 assert(grace.wait_for(std::chrono::milliseconds(10))==std::future_status::timeout && !reclaimed);
 rtw89_compat_read_unlock();
 assert(grace.wait_for(std::chrono::milliseconds(10))==std::future_status::timeout && !reclaimed);
 rtw89_compat_read_unlock();grace.get();flush_workqueue(system_wq);assert(reclaimed==1);
 rtw89_compat_defer_free(calloc(1,64));flush_workqueue(system_wq);
 unsigned canceled=0,executed=0,flushed=0,delayed=0;
 // Dispatcher has already been dequeued by its thread and waits for wiphy.
 // Cancellation must return under wiphy; the caller can immediately free VIF memory.
 wiphy_lock(&radio);auto*bad=node(canceled);wiphy_work_queue(&radio,&bad->work);
 for(;;){IOLockLock(system_wq->lock);bool running=system_wq->current_work;IOLockUnlock(system_wq->lock);if(running)break;std::this_thread::yield();}
 wiphy_work_cancel(&radio,&bad->work);delete bad;wiphy_unlock(&radio);flush_workqueue(system_wq);assert(!canceled);
 auto*good=node(executed);good->freeSelf=true;wiphy_work_queue(&radio,&good->work);flush_workqueue(system_wq);assert(executed==1);
 wiphy_lock(&radio);auto*inlineNode=node(flushed);inlineNode->freeSelf=true;
 rtw89_wiphy_queue(&radio,&inlineNode->work,1000);wiphy_work_flush(&radio,&inlineNode->work);
 wiphy_unlock(&radio);flush_workqueue(system_wq);assert(flushed==1);
 auto*later=node(delayed);rtw89_wiphy_queue(&radio,&later->work,20);flush_workqueue(system_wq);assert(!delayed && radio.workqueue->timer.active);
 jiffies+=20;radio.workqueue->timer.function(&radio.workqueue->timer);flush_workqueue(system_wq);assert(delayed==1);delete later;
 // Shutdown removes delayed nodes and drains the stable dispatcher before freeing its queue.
 unsigned never=0;auto*pending=node(never);rtw89_wiphy_queue(&radio,&pending->work,100);flush_workqueue(system_wq);
 rtw89_wiphy_queue_shutdown(&radio);delete pending;assert(!never&&!radio.workqueue);
 destroy_workqueue(system_wq);for(auto &thread:workers)thread.join();
 puts("PASS: wiphy serialization, cancel under mutex, freed VIF node, inline flush, delay, nested reader grace and shutdown drain");
}
'''
# Include atomic explicitly; all other adapters are shared with real workqueue tests.
text='#include <atomic>\n'+shim+strip((base/'linux/workqueue.h').read_text())+'\nstruct workqueue_struct *system_wq=nullptr,*system_long_wq=nullptr;\n'+source[a:b]+extra+header[start:end]
text+=(base/'RTWReaderGrace.c.inc').read_text()+(base/'RTWWiphyWork.c.inc').read_text()+scenario
with tempfile.TemporaryDirectory(prefix='rtw-wiphy-')as tmp:
    cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test';cpp.write_text(text)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function',
        '-fsanitize=address,undefined',str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
