/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlWindowScheduler.hpp>
#include <cassert>
#include <vector>
#include <functional>
#include <cstdio>
using namespace RTWAwdl;
struct Driver:WindowDriver{
    uint64_t time=10000000,deadline=0,latency=0;
    bool online=true,allowed=true,clock=true,armOK=true,restoreOK=true,startOK=true,endOK=true;
    bool leased=false,wrongChannel=false;
    uint8_t current=6;
    unsigned reserves=0,restores=0,arms=0,failArm=0;
    Reservation result=Reservation::Granted;
    std::vector<ScheduledWindow>starts,ends;
    std::vector<uint32_t>startClocks,endClocks;
    std::function<void()>onReserve,onStart,onEnd;
    uint64_t nowUs()const override{return time;}
    bool ready()const override{return online;}
    bool channelAllowed(uint8_t c)const override{return allowed&&(c==44||c==149);}
    uint8_t currentChannel()const override{return current;}
    Reservation reserve(uint8_t c,uint32_t ms)override{
        assert(deadline&&ms&&ms<=100);++reserves;time+=latency;
        if(result!=Reservation::Rejected){leased=true;current=wrongChannel?149:c;}
        if(onReserve)onReserve();return result;
    }
    bool restore()override{++restores;if(!restoreOK)return false;leased=false;current=6;return true;}
    bool wireTime(uint64_t host,uint32_t&wire)const override{wire=uint32_t(host+1234);return clock;}
    bool armTimer(uint64_t at,uint64_t now)override{
        assert(now==time);++arms;if(!armOK||arms==failArm)return false;deadline=at;return true;
    }
    void cancelTimer()override{deadline=0;}
    bool windowStart(const ScheduledWindow&w,uint32_t wire)override{
        if(!startOK)return false;starts.push_back(w);startClocks.push_back(wire);if(onStart)onStart();return true;
    }
    bool windowEnd(const ScheduledWindow&w,uint32_t wire)override{
        if(!endOK)return false;ends.push_back(w);endClocks.push_back(wire);if(onEnd)onEnd();return true;
    }
};
struct Fixture{
    Election::State state{};Driver driver;WindowScheduler scheduler{state,driver};
    Fixture(){Election::Sequence s;s.count=16;s.step=3;s.channels[0]=44;
        const uint8_t mac[6]={2,1,2,3,4,5};assert(state.init(mac,s,driver.time,1));}
    void tick(){assert(driver.deadline);driver.time=driver.deadline;scheduler.service();}
    void open(){assert(scheduler.start(100000));tick();assert(scheduler.phase()==WindowScheduler::Phase::Open);}
};
int main(){
    using P=WindowScheduler::Phase;
    {Fixture f;f.driver.online=false;assert(!f.scheduler.start(100000));}
    {Fixture f;f.driver.clock=false;assert(!f.scheduler.start(100000));}
    {Fixture f;assert(f.state.setPresence(8,f.driver.time));assert(!f.scheduler.start(100000));}
    {Fixture f;f.open();auto w=f.scheduler.window();
     assert(f.driver.starts.size()==1&&f.state.controlsHeld&&f.state.nativeTimelineStarted);
     assert(f.driver.startClocks[0]==uint32_t(w.actualStartUs+1234));
     assert(!f.scheduler.canTransmit(w.actualStartUs));
     assert(!f.scheduler.canTransmit(w.actualStartUs+2048,true));
     f.driver.time=w.actualStartUs+2048;
     assert(f.scheduler.canTransmit(f.driver.time,true));
     f.driver.time=w.endUs;assert(!f.scheduler.canTransmit(w.actualStartUs+2048,true));
     assert(!f.scheduler.canTransmit(w.endUs-2048));
     f.driver.time=w.endUs+1000;f.scheduler.service();
     assert(f.driver.ends.size()==1&&f.driver.endClocks[0]==uint32_t(w.endUs+1234));
     assert(!f.state.controlsHeld&&!f.driver.leased&&f.scheduler.phase()==P::Idle);
     assert(f.scheduler.stop()&&f.scheduler.phase()==P::Stopped);}
    {Fixture f;const uint64_t next=f.driver.time+16*4*Election::awUs;
     f.driver.time=next-2000;f.driver.latency=1000;
     assert(f.scheduler.start(100000,2000));f.tick();assert(f.scheduler.phase()==P::Reserved);
     f.driver.time=next-500;f.scheduler.service();assert(f.scheduler.phase()==P::Reserved&&!f.driver.starts.size());
     f.driver.time=next;f.scheduler.service();assert(f.scheduler.phase()==P::Open&&f.driver.starts[0].counter==64);}
    {Fixture f;f.driver.latency=10000;assert(f.scheduler.start(100000));f.tick();
     assert(f.driver.starts.empty()&&f.driver.restores==1&&f.scheduler.phase()==P::Idle);}
    {Fixture f;f.driver.result=WindowDriver::Reservation::Rejected;
     assert(f.scheduler.start(100000));f.tick();assert(!f.driver.restores&&f.driver.starts.empty());
     f.scheduler.service();assert(f.driver.reserves==1);}
    {Fixture f;f.driver.result=WindowDriver::Reservation::RecoveryRequired;f.driver.restoreOK=false;
     assert(f.scheduler.start(100000));f.tick();assert(f.scheduler.phase()==P::Failed&&f.driver.starts.empty());
     f.scheduler.service();assert(f.driver.reserves==1);
     assert(!f.scheduler.stop());f.driver.restoreOK=true;assert(f.scheduler.recover()&&f.scheduler.phase()==P::Stopped);}
    {Fixture f;f.driver.wrongChannel=true;assert(f.scheduler.start(100000));f.tick();
     assert(f.driver.starts.empty()&&f.driver.restores==1);}
    {Fixture f;f.driver.startOK=false;assert(f.scheduler.start(100000));f.tick();
     assert(!f.state.controlsHeld&&f.driver.ends.empty()&&f.driver.restores==1);}
    {Fixture f;f.open();f.driver.endOK=false;f.driver.time=f.scheduler.window().endUs;f.scheduler.service();
     assert(f.scheduler.phase()==P::Failed&&f.scheduler.nativeResetRequired()&&!f.scheduler.recover());
     assert(!f.driver.leased);}
    {Fixture f;f.driver.onStart=[&]{
        assert(f.state.controlsHeld);f.scheduler.service();assert(!f.scheduler.stop());};
     assert(f.scheduler.start(100000));f.tick();
     assert(f.scheduler.phase()==P::Stopped&&f.driver.starts.size()==1&&f.driver.ends.size()==1&&f.driver.restores==1);}
    {Fixture f;f.driver.onReserve=[&]{assert(!f.scheduler.stop());};
     assert(f.scheduler.start(100000));f.tick();
     assert(f.scheduler.phase()==P::Stopped&&f.driver.starts.empty()&&f.driver.restores==1);}
    {Fixture f;f.open();auto changed=f.state.ownSequence;changed.channels[0]=149;
     f.driver.onEnd=[&]{assert(f.state.controlsHeld);assert(f.state.setSequence(changed,f.driver.time));f.scheduler.service();};
     f.driver.time=f.scheduler.window().endUs;f.scheduler.service();
     assert(!f.state.controlsHeld&&f.state.ownSequence.channels[0]==149&&f.driver.restores==1);}
    {Fixture f;f.driver.failArm=3;assert(f.scheduler.start(100000));f.tick();
     assert(f.scheduler.phase()==P::Stopped&&f.driver.starts.size()==1&&f.driver.ends.size()==1&&f.driver.restores==1);}
    {Fixture f;f.open();f.driver.allowed=false;f.scheduler.service();
     assert(f.driver.ends.size()==1&&f.driver.restores==1&&!f.scheduler.canTransmit(f.driver.time));}
    {Fixture f;f.state.baseCounter=65532;assert(f.scheduler.start(100000));f.tick();
     assert(f.driver.starts.empty());f.tick();assert(f.driver.starts.size()==1&&f.driver.starts[0].counter==0);}
    {Fixture f;f.open();f.driver.time+=3000;f.driver.clock=false;assert(!f.scheduler.canTransmit(f.driver.time));
     f.scheduler.service();assert(f.scheduler.nativeResetRequired()&&f.driver.ends.empty()&&!f.driver.leased);}
    {Fixture f;f.open();f.driver.time=f.scheduler.window().actualStartUs-1;f.scheduler.service();
     assert(f.scheduler.nativeResetRequired()&&f.driver.ends.empty()&&!f.driver.leased);}
    {Fixture f;f.driver.time=UINT64_MAX;f.state.epoch=UINT64_MAX;
     assert(!f.scheduler.start(100000)&&!f.driver.reserves);}
    puts("PASS: AWDL window scheduling, checked leases, native event balance, reentrancy and recovery");
}
