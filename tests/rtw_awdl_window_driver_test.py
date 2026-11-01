#!/usr/bin/env python3
"""Execute production native scheduler transport against deterministic radio/time."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'AirportRTW/WCL/AirportRTWAwdlWindowDriver.hpp').read_text()
source=re.sub(r'^#include[^\n]*\n','',source,flags=re.M)
shim=r'''
#define AIRPORT_WCL 1
#include <AWDL/RTWAwdlWindowScheduler.hpp>
#include <HAL/RTWAwdlRadio.hpp>
#include <cassert>
#include <cstdio>
#define __IO80211_TARGET __MAC_26_0
constexpr unsigned APPLE80211_VERSION=1,APPLE80211_C_FLAG_20MHZ=1,
 APPLE80211_C_FLAG_2GHZ=2,APPLE80211_C_FLAG_5GHZ=4,APPLE80211_C_FLAG_ACTIVE=8;
struct apple80211_channel {unsigned version,channel,flags;};
static uint64_t hostUs=1000000;
static uint64_t mach_absolute_time(){return hostUs*1000;}
static void absolutetime_to_nanoseconds(uint64_t ticks,uint64_t*ns){*ns=ticks;}
struct AirportRTWAwdlInterface {
 unsigned starts=0,ends=0,arms=0,cancels=0,rx=0;bool eventOK=true,timerOK=true;
 uint32_t lastWire=0;uint64_t deadline=0;apple80211_channel channel{};
 bool armWindowTimer(uint64_t d,uint64_t n){assert(n<=hostUs);++arms;deadline=d;return timerOK;}
 void cancelWindowTimer(){++cancels;}
 bool postWindowStart(uint16_t,uint32_t,const uint8_t*,const uint8_t*,const apple80211_channel&c,uint32_t wire){
   ++starts;channel=c;lastWire=wire;return eventOK;
 }
 bool postWindowEnd(uint32_t wire){++ends;lastWire=wire;return eventOK;}
 bool queueRadioAction(const uint8_t*,size_t,const apple80211_channel&c,int32_t,uint32_t wire,bool valid){
   assert(valid);++rx;channel=c;lastWire=wire;return true;
 }
};
struct Radio:RTWAwdl::Radio {
 mutable unsigned queries=0;bool allowed=true,restoreOK=true;unsigned reserves=0,restores=0;
 RTWAwdl::RadioState state{2437,true,false};
 RTWAwdl::RadioReservation result=RTWAwdl::RadioReservation::Granted;
 RTWAwdl::RadioState awdlRadioState()const override{++queries;return state;}
 bool awdlChannelAllowed(uint16_t f)const override{++queries;return allowed&&(f==2437||f==5180);}
 RTWAwdl::RadioReservation reserveAwdlRadio(uint16_t f,uint32_t ms)override{
   assert(ms&&ms<=100);++reserves;if(result==RTWAwdl::RadioReservation::Granted){state.frequency=f;state.recoveryRequired=true;}return result;
 }
 bool restoreAwdlRadio()override{++restores;if(restoreOK){state.frequency=2437;state.recoveryRequired=false;}return restoreOK;}
};
'''
cases=r'''
int main(){
 using Driver=AirportRTWAwdl::WindowDriver;
 using Result=RTWAwdl::WindowDriver::Reservation;
 Radio radio;AirportRTWAwdlInterface native;Driver driver(radio,native);
 for(unsigned ch=0;ch<256;++ch){auto f=Driver::frequencyFor(uint8_t(ch));if(f)assert(Driver::channelFor(f)==ch);}
 assert(!Driver::channelFor(2484)&&!Driver::channelFor(5975)&&!Driver::channelFor(2413));
 assert(driver.ready()&&driver.currentChannel()==6&&driver.channelAllowed(36));
 assert(!driver.channelAllowed(14)&&!driver.channelAllowed(40));
 assert(driver.reserve(14,50)==Result::Rejected&&!radio.reserves);
 assert(driver.reserve(36,101)==Result::Rejected&&!radio.reserves);
 assert(driver.reserve(36,50)==Result::Granted&&driver.currentChannel()==36);
 radio.restoreOK=false;assert(!driver.restore()&&radio.state.recoveryRequired);
 radio.restoreOK=true;assert(driver.restore()&&driver.currentChannel()==6);
 radio.result=RTWAwdl::RadioReservation::RecoveryRequired;
 assert(driver.reserve(36,50)==Result::RecoveryRequired);
 radio.result=RTWAwdl::RadioReservation::Rejected;
 assert(driver.reserve(36,50)==Result::Rejected);
 uint32_t wire=42;assert(!driver.wireTime(hostUs+1,wire)&&wire==42);
 hostUs=uint64_t(UINT32_MAX)+123;assert(driver.wireTime(hostUs,wire)&&wire==122);
 // Action RX must never query the HAL while its registration lock is held.
 auto queries=radio.queries;radio.allowed=false;uint8_t frame[32]{};
 assert(driver.queueAction(frame,sizeof(frame),5180,-40));
 assert(radio.queries==queries&&native.lastWire==122&&native.channel.channel==36);
 assert(native.channel.flags==(APPLE80211_C_FLAG_20MHZ|APPLE80211_C_FLAG_5GHZ));
 assert(!driver.queueAction(frame,sizeof(frame),5975,-40));
 RTWAwdl::ScheduledWindow w{};w.channel=6;w.endUs=hostUs+100;w.role=1;
 assert(!driver.windowStart(w,wire)&&!native.starts);
 radio.allowed=true;assert(driver.windowStart(w,wire)&&native.starts==1&&native.channel.channel==6);
 // Loss of RF/policy must not suppress the closing native event.
 radio.state.ready=false;radio.allowed=false;assert(driver.windowEnd(w,wire)&&native.ends==1);
 assert(!driver.ready()&&!driver.currentChannel());
 radio.state.ready=true;radio.allowed=true;hostUs=w.endUs;
 assert(!driver.windowStart(w,wire)&&native.starts==1);
 native.timerOK=false;assert(!driver.armTimer(hostUs+1,hostUs));
 native.timerOK=true;assert(driver.armTimer(hostUs+1,hostUs));driver.cancelTimer();
 assert(native.arms==2&&native.cancels==1);
 // Real shared scheduler through production transport and HAL contract.
 hostUs=1000000;radio.result=RTWAwdl::RadioReservation::Granted;
 uint8_t mac[6]={2,1,2,3,4,5};RTWAwdl::Election::Sequence seq{};
 seq.count=16;for(auto&c:seq.channels)c=6;
 RTWAwdl::Election::State state;assert(state.init(mac,seq,hostUs,100));
 RTWAwdl::WindowScheduler scheduler(state,driver);assert(scheduler.start(100000));
 hostUs=native.deadline;scheduler.service();assert(scheduler.phase()==RTWAwdl::WindowScheduler::Phase::Open);
 assert(radio.state.recoveryRequired);assert(scheduler.stop());assert(!radio.state.recoveryRequired);
 puts("PASS: production native window transport, software clock and shared HAL contract");
}
'''
with tempfile.TemporaryDirectory(prefix='rtw-window-driver-') as tmp:
    cpp=Path(tmp)/'test.cpp';binary=Path(tmp)/'test'
    cpp.write_text(shim+source+cases)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-I'+str(ROOT/'include'),str(cpp),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
