/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlClock.hpp>
#include <assert.h>
#include <stdio.h>
using namespace RTWAwdl;
int main() {
    RadioClock32 radio;
    uint64_t value=9;
    assert(!radio.sample(0,1,false,value) && value==0);
    assert(radio.sample(0xfffffff0,10,true,value) && value==0xfffffff0);
    assert(radio.sample(0x20,58,true,value) && value==0x100000020ULL);
    assert(!radio.sample(0x10,60,true,value) && value==0);
    assert(radio.sample(0x30,74,true,value) && value==0x100000030ULL);
    assert(!radio.sample(0x40,73,true,value)); // host clock regression
    assert(radio.sample(0x40,75,true,value) && value==0x40);
    assert(!radio.sample(0x50,75+(uint64_t(1)<<31),true,value));
    assert(radio.sample(0x50,76+(uint64_t(1)<<31),true,value) && value==0x50);
    radio.reset();
    assert(radio.sample(0,1,true,value) && value==0);
    assert(!radio.sample(0x80000000,2,true,value));
    AvailabilityClock clock;
    AvailabilityClock::Window w {};
    uint64_t deadline=9;
    assert(!clock.at(0,w));
    assert(!clock.configure(100,0,0,1,0));
    assert(!clock.configure(100,0,16,17,0));
    assert(!clock.configure(100,0,16,0,0));
    assert(!clock.configure(100,0,16,1,512));
    assert(!clock.configure(100,0,16,1,UINT32_MAX));
    assert(clock.configure(100,65535,16,8,100));
    assert(!clock.at(99,w));
    assert(clock.at(100,w) && w.counter==65535 && w.available && !w.txAllowed);
    assert(clock.at(200,w) && w.txAllowed && w.phaseUs==100);
    assert(clock.at(100+8192-101,w) && w.txAllowed);
    assert(clock.at(100+8192-100,w) && !w.txAllowed && w.available);
    assert(clock.at(100+8192,w) && !w.available && !w.txAllowed);
    assert(clock.at(100+16384,w) && w.counter==0 && w.phaseUs==0);
    assert(clock.nextBoundary(100+16384,deadline) && deadline==100+32768);
    const uint64_t cycles=65537;
    assert(clock.at(100+cycles*16384+101,w) && w.counter==0 && w.phaseUs==101);
    // Invalid reconfiguration preserves the previous valid schedule.
    assert(!clock.configure(0,0,0,0,0));
    assert(clock.at(200,w) && w.txAllowed);
    assert(clock.configure(UINT64_MAX-10,1,1,1,0));
    assert(clock.at(UINT64_MAX,w));
    assert(!clock.nextBoundary(UINT64_MAX,deadline) && deadline==0);
    clock.reset();
    assert(!clock.at(UINT64_MAX,w) && !clock.nextBoundary(0,deadline));
    puts("PASS: radio timestamp wrapping, availability windows and deadline bounds");
}
