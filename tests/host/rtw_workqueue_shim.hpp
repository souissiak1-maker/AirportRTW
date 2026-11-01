// Host adapters for testing the production compat workqueue (not the XNU timer).
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <future>
#include <mutex>
#include <thread>
#include <vector>
#include <cstdio>
#include <cstdint>
using thread_t = uintptr_t;
using wait_result_t = int;
using kern_return_t = int;
constexpr int KERN_SUCCESS=0, THREAD_UNINT=0;
struct IOLock { std::mutex mutex; std::condition_variable condition; };
static IOLock *IOLockAlloc() { return new IOLock; }
static void IOLockFree(IOLock *lock) { delete lock; }
static void IOLockLock(IOLock *lock) { lock->mutex.lock(); }
static void IOLockUnlock(IOLock *lock) { lock->mutex.unlock(); }
static void IOLockWakeup(IOLock *lock,void *,bool) { lock->condition.notify_all(); }
static void IOLockSleep(IOLock *lock,void *,int) {
    std::unique_lock<std::mutex> guard(lock->mutex,std::adopt_lock);
    lock->condition.wait(guard); guard.release();
}
static void *IOMalloc(size_t size) { return malloc(size); }
static void IOFree(void *p,size_t) { free(p); }
struct ThreadExit {};
static thread_t current_thread() { return std::hash<std::thread::id>{}(std::this_thread::get_id()) | 1; }
static std::vector<std::thread> workers;
static kern_return_t kernel_thread_start(void(*fn)(void*,wait_result_t),void *arg,thread_t *id) {
    workers.emplace_back([=] {try {fn(arg,0);} catch(const ThreadExit&) {}});
    *id=std::hash<std::thread::id>{}(workers.back().get_id()) | 1; return 0;
}
static void thread_deallocate(thread_t) {}
[[noreturn]] static void thread_terminate(thread_t) { throw ThreadExit{}; }
struct list_head { list_head *next,*prev; };
static void INIT_LIST_HEAD(list_head *p) {p->next=p->prev=p;}
static bool list_empty(list_head *p) {return p->next==p;}
static void list_add_tail(list_head *p,list_head *head) {p->prev=head->prev;p->next=head;head->prev->next=p;head->prev=p;}
static void list_del_init(list_head *p) {p->prev->next=p->next;p->next->prev=p->prev;INIT_LIST_HEAD(p);}
#define from_timer(var,timer,member) container_of(timer,__typeof__(*var),member)
#define container_of(ptr,type,member) ((type*)((char*)(ptr)-offsetof(type,member)))
struct timer_list {unsigned long expires;void(*function)(timer_list*);void *call;int active;};
static void timer_setup(timer_list *t,void(*fn)(timer_list*),unsigned) {t->function=fn;t->active=0;}
static void mod_timer(timer_list *t,unsigned long expires) {t->expires=expires;t->active=1;}
static bool del_timer(timer_list *t) {bool old=t->active;t->active=0;return old;}
static bool del_timer_sync(timer_list *t) {return del_timer(t);}
static unsigned long jiffies=1;
