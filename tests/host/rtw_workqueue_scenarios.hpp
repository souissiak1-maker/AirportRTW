static std::mutex gateMutex;
static std::condition_variable gateCondition;
static bool started=false,released=false;
static unsigned callbacks=0;
static void block(work_struct*) {
    std::unique_lock<std::mutex> lock(gateMutex);started=true;gateCondition.notify_all();
    gateCondition.wait(lock,[]{return released;});
}
static void count(work_struct*) {++callbacks;}
static void selfFree(work_struct *work) {free(work);}
static workqueue_struct *target;
static void checkQueue(work_struct*) {assert(current_thread()==target->thread);++callbacks;}
static void repeat(work_struct *work) {if(++callbacks<3) assert(queue_work(target,work));}
int main() {
    auto *q=alloc_workqueue("host",0,1);assert(q);system_wq=q;
    work_struct blocking {},pending {};INIT_WORK(&blocking,block);INIT_WORK(&pending,count);
    assert(queue_work(q,&blocking));
    {std::unique_lock<std::mutex> lock(gateMutex);assert(gateCondition.wait_for(lock,std::chrono::seconds(2),[]{return started;}));}
    // Cancel/requeue repeatedly behind a running callback. A stale queue link
    // would execute canceled callbacks or corrupt the intrusive list.
    for(unsigned i=0;i<100;++i) {assert(queue_work(q,&pending));assert(cancel_work_sync(&pending));assert(!cancel_work_sync(&pending));}
    auto flush=std::async(std::launch::async,[=]{flush_workqueue(q);});
    assert(flush.wait_for(std::chrono::milliseconds(20))==std::future_status::timeout);
    auto cancel=std::async(std::launch::async,[&]{cancel_work_sync(&blocking);});
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!__sync_fetch_and_add(&blocking.canceling,0) && std::chrono::steady_clock::now()<deadline) std::this_thread::yield();
    assert(__sync_fetch_and_add(&blocking.canceling,0));
    assert(!queue_work(q,&blocking));
    assert(cancel.wait_for(std::chrono::milliseconds(20))==std::future_status::timeout);
    {std::lock_guard<std::mutex> lock(gateMutex);released=true;gateCondition.notify_all();}
    assert(cancel.wait_for(std::chrono::seconds(2))==std::future_status::ready);cancel.get();
    assert(flush.wait_for(std::chrono::seconds(2))==std::future_status::ready);flush.get();assert(callbacks==0);
    target=alloc_workqueue("target",0,1);assert(target);
    delayed_work delayed {};INIT_DELAYED_WORK(&delayed,checkQueue);
    assert(queue_delayed_work(target,&delayed,1));assert(delayed.target_queue==target);
    // Fire a controlled host timer; test timer-to-workqueue routing only.
    delayed.timer.active=0;delayed.timer.function(&delayed.timer);
    flush_workqueue(target);assert(callbacks==1);
    work_struct requeue {};INIT_WORK(&requeue,repeat);callbacks=0;
    assert(queue_work(target,&requeue));flush_workqueue(target);assert(callbacks==3);
    auto *owned=static_cast<work_struct*>(malloc(sizeof(work_struct)));assert(owned);
    INIT_WORK(owned,selfFree);assert(queue_work(target,owned));flush_workqueue(target);
    destroy_workqueue(target);destroy_workqueue(q);
    for(auto &worker:workers) worker.join();
    puts("PASS: queued cancellation, running drain, requeue gate, target routing and self-free");
}
