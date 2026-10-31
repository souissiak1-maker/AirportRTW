extern "C" {
void*rtw_awdl_pool(const char*,OSObject*o,uint32_t,const void*){return failNow()?nullptr:new FakePool(o);}
void*rtw_awdl_txsub(void*,uint32_t,uint32_t,OSObject*o,uint32_t(*action)(OSObject*,void*,void*const*,uint32_t,void*),void*,uint32_t){return failNow()?nullptr:new FakeQueue(o,action);}
void*rtw_awdl_txcomp(void*,uint32_t,uint32_t,OSObject*o,uint32_t(*)(OSObject*,void*,void**,uint32_t,void*),void*,uint32_t){return failNow()?nullptr:new FakeQueue(o);}
void*rtw_awdl_rxcomp(void*,uint32_t,uint32_t,OSObject*o,uint32_t(*)(OSObject*,void*,void**,uint32_t,void*),void*,uint32_t){return failNow()?nullptr:new FakeQueue(o);}
IOReturn rtw_awdl_allocate(void*raw,void**out,uint32_t){*out=nullptr;if(allocationFails)return kIOReturnNoMemory;auto*p=new FakePacket;p->pool=static_cast<FakePool*>(raw);++p->pool->packets;++packets;*out=p;return 0;}
void rtw_awdl_release(void*raw,void*value){auto*p=static_cast<FakePacket*>(value);assert(p->pool==raw);assert(packets&&p->pool->packets);--packets;--p->pool->packets;delete p;}
IOReturn rtw_awdl_prepare(void*,void*source,uint64_t,uint32_t){assert(!source);return prepareFails?kIOReturnError:0;}
IOReturn rtw_awdl_set_length(void*raw,uint16_t offset,uint32_t length){if(lengthFails)return kIOReturnError;auto*p=static_cast<FakePacket*>(raw);p->offset=offset;p->length=length;return 0;}
void rtw_awdl_set_header(void*raw,uint8_t n){static_cast<FakePacket*>(raw)->header=n;}
uint64_t rtw_awdl_base(const void*p){return uintptr_t(static_cast<const FakePacket*>(p)->bytes);}
uint32_t rtw_awdl_length(const void*p){return static_cast<const FakePacket*>(p)->length;}
uint16_t rtw_awdl_offset(const void*p){return static_cast<const FakePacket*>(p)->offset;}
uint32_t rtw_awdl_buffer_size(const void*){return 2048;}
uint32_t rtw_awdl_buffer_count(const void*){return 1;}
IOReturn rtw_awdl_tx_complete(void*,void*const*values,uint32_t count,uint32_t){
    assert(count>0&&count<=64);if(txCompletionFails)return kIOReturnError;
    for(unsigned i=0;i<count;++i){auto*p=static_cast<FakePacket*>(values[i]);++txCompleted;rtw_awdl_release(p->pool,p);}return 0;
}
IOReturn rtw_awdl_rx_complete(void*,void*const*values,uint32_t count,uint32_t){
    assert(count>0&&count<=32);if(enqueueFails)return kIOReturnError;
    for(unsigned i=0;i<count;++i){auto*p=static_cast<FakePacket*>(values[i]);assert(p->header==14&&p->offset==0);lastReceived.assign(p->bytes,p->bytes+p->length);++delivered;rtw_awdl_release(p->pool,p);}return 0;
}
void rtw_awdl_request_dequeue(void*,void*context,uint32_t){assert(!context);++requests;}
}
static bool send(OSObject*,const uint8_t*data,size_t length){assert(data&&length==54);if(!senderReady)return false;++sent;return true;}
static unsigned actionsDelivered=0;
static int expectedDataBeforeAction=-1;
static std::vector<uint8_t>lastAction,lastMetadata;
static AirportRTWAwdlDatapath *activeActionPath=nullptr;
static bool dropAction=false,disableInAction=false,stopInAction=false;
static bool actionReceived(OSObject*owner,const uint8_t*frame,size_t n,const uint8_t*metadata,size_t z){
    assert(static_cast<IOWorkLoop*>(owner)->pumping && n>=40 && z==72);
    if(expectedDataBeforeAction>=0)assert(delivered==unsigned(expectedDataBeforeAction));
    lastAction.assign(frame,frame+n);lastMetadata.assign(metadata,metadata+z);++actionsDelivered;
    if(disableInAction)activeActionPath->setEnabled(false);
    if(stopInAction){auto*p=activeActionPath;activeActionPath=nullptr;p->stop();p->release();}
    return !dropAction;
}
int main(){
    auto*loop=new IOWorkLoop;
    // Fail every allocation, including owner-retaining pools and queues. Every
    // failed factory must break reference cycles and release its partial setup.
    for(unsigned fault=1;fault<=8;++fault){faultAt=fault;attempts=0;auto*p=AirportRTWAwdlDatapath::withWorkLoop(loop,loop,send);assert(!p);assert(objects==1&&allocations==0&&loop->sources.empty());}
    faultAt=0;
    for(unsigned fault=1;fault<=4;++fault){loop->adds=0;loop->failAdd=fault;auto*p=AirportRTWAwdlDatapath::withWorkLoop(loop,loop,send);assert(!p);assert(objects==1&&allocations==0&&loop->sources.empty());}
    loop->failAdd=0;
    auto*p=AirportRTWAwdlDatapath::withWorkLoop(loop,loop,send);assert(p);
    uint8_t bytes[54]{};bytes[0]=0x33;bytes[6]=2;bytes[12]=0x86;bytes[13]=0xdd;bytes[14]=0x60;
    assert(!p->receive(bytes,sizeof(bytes)));
    assert(p->setEnabled(true));assert(requests);
    auto*tx=static_cast<FakeQueue*>(p->txSubmission());
    void*txPacket=nullptr;assert(rtw_awdl_allocate(p->txPool(),&txPacket,1)==0);
    auto*buffer=static_cast<FakePacket*>(txPacket);buffer->length=54;memcpy(buffer->bytes+64,bytes,54);
    assert(tx->action(tx->owner,nullptr,&txPacket,1,nullptr)==0&&packets==1);
    senderReady=true;p->resumeTransmit();loop->pump();
    assert(tx->action(tx->owner,nullptr,&txPacket,1,nullptr)==1&&packets==0&&sent==1&&txCompleted==1);
    assert(rtw_awdl_allocate(p->txPool(),&txPacket,1)==0);
    buffer=static_cast<FakePacket*>(txPacket);buffer->length=54;memcpy(buffer->bytes+64,bytes,54);buffer->bytes[64+12]=8;
    assert(tx->action(tx->owner,nullptr,&txPacket,1,nullptr)==1&&packets==0&&sent==1&&txCompleted==2);
    assert(rtw_awdl_allocate(p->txPool(),&txPacket,1)==0);
    buffer=static_cast<FakePacket*>(txPacket);buffer->length=54;memcpy(buffer->bytes+64,bytes,54);
    txCompletionFails=true;
    assert(tx->action(tx->owner,nullptr,&txPacket,1,nullptr)==1&&packets==0&&sent==2);
    txCompletionFails=false;

    assert(p->receive(bytes,sizeof(bytes)));assert(!delivered);loop->pump();assert(delivered==1&&packets==0);
    assert(lastReceived==std::vector<uint8_t>(bytes,bytes+sizeof(bytes)));
    for(unsigned i=0;i<64;++i)assert(p->receive(bytes,sizeof(bytes)));
    assert(!p->receive(bytes,sizeof(bytes)));loop->pump();assert(delivered==65&&packets==0);
    bool*failures[]{&allocationFails,&prepareFails,&lengthFails,&enqueueFails};
    for(auto*flag:failures){*flag=true;assert(p->receive(bytes,sizeof(bytes)));loop->pump();*flag=false;assert(packets==0&&delivered==65);}
    assert(p->setEnabled(false));assert(!p->receive(bytes,sizeof(bytes)));
    assert(p->setEnabled(true));assert(p->receive(bytes,sizeof(bytes)));
    p->resumeTransmit();p->stop();p->stop();loop->pump();
    assert(!p->receive(bytes,sizeof(bytes))&&!p->setEnabled(true));
    p->release();assert(objects==1&&allocations==0&&packets==0&&loop->sources.empty());
    for(unsigned fault=1;fault<=10;++fault){faultAt=fault;attempts=0;
        auto*a=AirportRTWAwdlDatapath::withWorkLoop(loop,loop,send,actionReceived);
        assert(!a && objects==1 && allocations==0 && loop->sources.empty());}
    faultAt=0;
    auto*a=AirportRTWAwdlDatapath::withWorkLoop(loop,loop,send,actionReceived);assert(a);
    activeActionPath=a;
    uint8_t frame[40]{0xd0},metadata[72]{};
    frame[10]=metadata[0]=2;frame[15]=metadata[5]=1;
    frame[24]=127;frame[26]=0x17;frame[27]=0xf2;frame[28]=8;frame[29]=0x10;
    metadata[44]=0x12;
    assert(!a->queueAction(frame,sizeof(frame),metadata,sizeof(metadata)));
    assert(a->setEnabled(true));
    for(size_t n=0;n<74;++n)if(n!=72)assert(!a->queueAction(frame,sizeof(frame),metadata,n));
    metadata[0]^=2;assert(!a->queueAction(frame,sizeof(frame),metadata,72));metadata[0]^=2;
    frame[1]=0x40;assert(!a->queueAction(frame,sizeof(frame),metadata,72));frame[1]=0;
    assert(a->queueAction(frame,sizeof(frame),metadata,72));assert(!actionsDelivered);
    frame[32]=7;metadata[44]=9;
    expectedDataBeforeAction=int(delivered);assert(a->receive(bytes,sizeof(bytes)));loop->pump();
    assert(delivered==unsigned(expectedDataBeforeAction)+1);expectedDataBeforeAction=-1;
    assert(actionsDelivered==1 && lastAction[32]==0 && lastMetadata[44]==0x12);
    for(unsigned i=0;i<16;++i)assert(a->queueAction(frame,sizeof(frame),metadata,72));
    assert(!a->queueAction(frame,sizeof(frame),metadata,72));loop->pump();assert(actionsDelivered==17);
    dropAction=true;assert(a->queueAction(frame,sizeof(frame),metadata,72));loop->pump();
    loop->pump();assert(actionsDelivered==18);dropAction=false;
    assert(a->queueAction(frame,sizeof(frame),metadata,72));assert(a->setEnabled(false));
    assert(a->setEnabled(true));loop->pump();assert(actionsDelivered==18);
    disableInAction=true;for(unsigned i=0;i<3;++i)assert(a->queueAction(frame,sizeof(frame),metadata,72));
    loop->pump();assert(actionsDelivered==19);disableInAction=false;
    assert(a->setEnabled(true));loop->pump();assert(actionsDelivered==19);
    stopInAction=true;assert(a->queueAction(frame,sizeof(frame),metadata,72));loop->pump();
    assert(actionsDelivered==20 && !activeActionPath && objects==1 && allocations==0 && loop->sources.empty());
    loop->release();assert(objects==0);
    puts("PASS: native datapath rollback, pool ownership, RX bounds, failures and teardown");
}
