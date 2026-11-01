extern "C" {
IOWorkLoop*rtw_awdl_interface_workloop(void*p){return failAt==6?nullptr:static_cast<IO80211VirtualInterface*>(p)->baseLoop;}
const char*rtw_awdl_interface_name(void*){return failAt==11?"en0":"awdl0";}
IO80211VirtualInterface*rtw_awdl_controller_interface(IO80211Controller*c){return c->current;}
void rtw_awdl_controller_publish(IO80211Controller*c,IO80211VirtualInterface*i){if(failAt!=10)c->current=i;}
IOReturn rtw_awdl_register_interface(void*,const void*raw,void**q,uint32_t count,void*tx,void*rx,uint32_t){
    const auto*b=static_cast<const uint8_t*>(raw);uint32_t role,mtu;const char*prefix;
    memcpy(&role,b+0x10,4);memcpy(&mtu,b+0x48,4);memcpy(&prefix,b+0x30,sizeof(prefix));
    assert(role==6&&mtu==1428&&!strcmp(prefix,"awdl")&&count==3&&tx&&rx&&q[0]&&q[1]&&q[2]);return failAt==9?kIOReturnError:0;
}
}
struct Control:AirportRTWAwdl::Control{
    bool online=true;uint32_t caps=requiredCapabilities;unsigned prepares=0,shutdowns=0,enables=0,disables=0,requests=0,sends=0;
    IOReturn addressResult=0,enableResult=0;
    AirportRTWAwdl::Request last=AirportRTWAwdl::Request::SSID;bool lastSet=false;void*lastPayload=nullptr;
    unsigned ticks=0;void*context=nullptr;IO80211VirtualInterface*bound=nullptr;void(*onTick)(Control*)=nullptr;
    void timerFired()override{++ticks;if(onTick)onTick(this);}
    uint32_t capabilities()const override{return caps;}
    bool ready()const override{return online;}
    IOReturn prepare(IO80211VirtualInterface*i,const uint8_t*)override{bound=i;++prepares;return failAt==4?kIOReturnError:0;}
    IOReturn enable(bool value)override{if(value){++enables;return enableResult;}++disables;return 0;}
    void shutdown()override{++shutdowns;}
    IOReturn request(AirportRTWAwdl::Request r,bool set,void*p)override{++requests;last=r;lastSet=set;lastPayload=p;return 42;}
    IOReturn setAddress(const uint8_t*)override{return addressResult;}
    bool transmitEthernet(const uint8_t*,size_t)override{++sends;return true;}
};
int main(){
    auto*c=new IO80211Controller;uint8_t mac[6]{2,1,2,3,4,5};
    {Control control;control.online=false;assert(!AirportRTWAwdlInterface::withController(c,&control,mac));assert(!control.prepares&&objects==1);}
    {Control control;c->current=reinterpret_cast<IO80211VirtualInterface*>(uintptr_t(1));assert(!AirportRTWAwdlInterface::withController(c,&control,mac));assert(!control.prepares&&objects==1);c->current=nullptr;}
    for(unsigned bit=0;bit<7;++bit){Control control;control.caps&=~(1U<<bit);assert(!AirportRTWAwdlInterface::withController(c,&control,mac));assert(!control.prepares&&objects==1);}
    {Control control;uint8_t bad[6]{};assert(!AirportRTWAwdlInterface::withController(c,&control,bad));bad[0]=1;assert(!AirportRTWAwdlInterface::withController(c,&control,bad));assert(objects==1);}
    for(unsigned fault=1;fault<=11;++fault){failAt=fault;Control control;auto*i=AirportRTWAwdlInterface::withController(c,&control,mac);assert(!i);assert(!c->current&&objects==1&&c->refs==1);assert(control.shutdowns==(fault>=4));}
    failAt=15;{Control co;assert(!AirportRTWAwdlInterface::withController(c,&co,mac));
      assert(!co.prepares&&!co.shutdowns&&objects==1&&controlLocks==0);}
    failAt=0;Control control;
    auto*i=AirportRTWAwdlInterface::withController(c,&control,mac);assert(i&&c->current==i&&control.prepares==1);
    assert(i->isChipInterfaceReady()&&i->getNumTxQueues()==1&&i->getMaxTransferUnit()==1428);
    assert(i->getTxSubQueue(static_cast<apple80211_wme_ac>(3))&&i->getTxCompQueue()&&i->getRxCompQueue());
    assert(i->getTxPacketPool()&&i->getRxPacketPool());
    uint32_t cookie=123;
