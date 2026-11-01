/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <AWDL/RTWAwdlStartupProbe.hpp>
#include <cassert>
#include <vector>
#include <cstdio>
using Probe=RTWAwdl::StartupProbe;
using Stage=Probe::Stage;
struct Driver final : RTWAwdl::StartupProbeDriver {
    bool primary=true,openOK=true,bindOK=true,radio=true,closeOK=true;
    unsigned opens=0,binds=0,closes=0,unbound=0;
    uint32_t cap=14;
    std::vector<char> events;
    bool primaryReady()const override{return primary;}
    uint32_t capacity()const override{return cap;}
    bool open()override{++opens;events.push_back('o');return openOK;}
    bool bind()override{++binds;events.push_back('b');return bindOK;}
    bool radioReady()const override{return radio;}
    void unbind()override{++unbound;events.push_back('u');}
    bool close()override{++closes;events.push_back('c');return closeOK;}
};
int main(){
    {Driver d;Probe p(d);assert(!p.tick()&&!d.opens);assert(p.arm());assert(!p.arm());
     assert(p.tick()&&p.stage()==Stage::Listening&&p.peerCapacity()==14);
     for(unsigned i=0;i<9;++i)assert(p.tick());
     assert(!p.tick()&&p.stage()==Stage::Complete&&p.cleanupSucceeded());
     assert(p.listens()==10&&d.events==std::vector<char>({'o','b','u','c'}));
     p.stop();assert(!p.arm()&&!p.tick()&&d.closes==1);}
    {Driver d;d.primary=false;Probe p(d);assert(p.arm());
     for(unsigned i=0;i<30;++i)assert(p.tick());
     assert(!p.tick()&&p.stage()==Stage::TimedOut&&!d.opens&&!d.closes);}
    {Driver d;d.cap=0;Probe p(d);p.arm();assert(!p.tick());
     assert(p.stage()==Stage::Unavailable&&!d.opens&&!d.closes);}
    for(auto failure:{Stage::OpenFailed,Stage::BindFailed,Stage::RadioFailed}){
     Driver d;d.openOK=failure!=Stage::OpenFailed;d.bindOK=failure!=Stage::BindFailed;
     d.radio=failure!=Stage::RadioFailed;Probe p(d);p.arm();assert(!p.tick());
     assert(p.stage()==failure&&p.result()==failure&&p.cleanupSucceeded());
     assert(d.closes==1&&d.unbound==1);assert(d.events[d.events.size()-2]=='u');
     p.stop();assert(d.closes==1);
    }
    {Driver d;d.openOK=false;d.closeOK=false;Probe p(d);p.arm();assert(!p.tick());
     assert(p.stage()==Stage::CleanupFailed&&p.result()==Stage::OpenFailed&&!p.cleanupSucceeded());
     p.stop();assert(!p.arm()&&!p.tick()&&d.closes==1);}
    {Driver d;Probe p(d);p.arm();p.stop();assert(p.stage()==Stage::Cancelled&&!d.opens&&!d.closes);}
    {Driver d;Probe p(d);p.arm();assert(p.tick());d.primary=false;
     assert(!p.tick()&&p.stage()==Stage::RadioFailed&&d.closes==1);}
    {Driver d;Probe p(d);p.arm();assert(p.tick());p.stop();
     assert(p.stage()==Stage::Cancelled&&d.closes==1&&d.unbound==1);}
    puts("PASS: bounded AWDL startup probe cleans partial opens and preserves failed cleanup ownership");
}
