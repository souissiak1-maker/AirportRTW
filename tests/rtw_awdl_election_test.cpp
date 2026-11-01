/* SPDX-License-Identifier: GPL-2.0-only
 * Schedule, role and native-clock cases adapted from MtkWireless's
 * protocol-test.cpp (local revision 98d9442; original GPL-2.0-or-later).
 */
#include <AWDL/RTWAwdlElection.hpp>
#include <cassert>
#include <cstdio>
#include <vector>
using namespace RTWAwdl::Election;
static const uint8_t local[6]={2,1,2,3,4,5},remote[6]={2,1,2,3,4,6};
// Explicit test-only initial plan; production requires a validated caller plan.
struct TestState : RTWAwdl::Election::State {
    void init(const uint8_t *address,uint64_t now) {
        Sequence plan;plan.count=16;plan.step=3;
        for(auto &c:plan.channels)c=6;
        assert(RTWAwdl::Election::State::init(address,plan,now,1,false));
    }
};
static size_t buildAction(TestState &s,uint8_t *f,size_t capacity,uint64_t now) {
    return buildSynchronization(s,f,capacity,now,0x11223344,0x55667788,3);
}
static bool parseAction(const uint8_t *f,size_t n,Advertisement &out) {
    return parseAdvertisement(f,n,out);
}
static void scheduleTests()
{
    for(unsigned presence=1;presence<=16;presence*=2) {
        TestState tx,rx; const uint64_t epoch=10000000;
        tx.init(remote,epoch); rx.init(local,epoch); tx.metric=10;
        assert(tx.setPresence(presence,epoch));
        tx.baseCounter=65536-presence;
        for(unsigned i=0;i<slots;++i) tx.sequence.channels[i]=(i&1) ? 44 : 6;
        tx.ownSequence=tx.sequence; tx.elect(epoch);
        const uint64_t period=presence*awUs;
        const uint64_t offsets[]={0,1,1023,1024,awUs-1,awUs,period-1,period,period+1,period*17+1023};
        for(uint64_t offset:offsets) {
            uint64_t now=epoch+offset; uint8_t f[256]; Advertisement a={};
            size_t n=buildAction(tx,f,sizeof(f),now);
            assert(n && parseAction(f,n,a));
            assert(a.presence==presence && a.sequence.step+1==presence);
            assert(rx.receiveAction(f,n,now)>=0 && rx.synchronized);
            assert(rx.counter(now)==tx.counter(now));
            assert(rx.channel(now)==tx.channel(now));
            assert(rx.peers[rx.find(remote)].channel(now)==tx.channel(now));
            assert(rx.untilNext(now)>=tx.untilNext(now));
            assert(rx.untilNext(now)-tx.untilNext(now)<1024);
        }
    }
    TestState s; s.init(local,10000000);
    s.baseCounter=5;
    assert(s.setPresence(8,10000123));
    assert(s.counter(10000123)==5 && s.untilNext(10000123)==3*awUs-123);
    TestState before=s;
    for(unsigned bad: {0U,3U,5U,65U,255U}) {
        assert(!s.setPresence(bad,10000123)); assert(!memcmp(&before,&s,sizeof(s)));
    }
}
static void roleTests()
{
    TestState tx,rx; uint8_t f[256]; tx.init(remote,1000000); rx.init(local,1000000);
    tx.metric=10; tx.elect(1000000);
    size_t n=buildAction(tx,f,sizeof(f),1000000);
    assert(rx.setSyncRole(3,local));
    assert(rx.receiveAction(f,n,1000000)>=0 && !rx.synchronized);
    assert(!memcmp(rx.master,local,6));
    assert(rx.setSyncRole(2,remote)); assert(!rx.channel(1000000));
    assert(!buildAction(rx,f,0,1000000));
    rx.elect(1000000); assert(rx.synchronized && !memcmp(rx.sync,remote,6));
    rx.elect(5000000); assert(!rx.synchronized && !rx.channel(5000000));
    assert(rx.setSyncRole(1,local)); assert(rx.channel(5000000));
    TestState before=rx;
    assert(!rx.setSyncRole(2,local) && !rx.setSyncRole(3,remote) && !rx.setSyncRole(0,local));
    assert(!memcmp(&before,&rx,sizeof(rx)));
    // Never follow a node which names us as its own synchronization source.
    tx.epoch=5000000; memcpy(tx.sync,local,6);
    n=buildAction(tx,f,sizeof(f),5000000);
    assert(rx.receiveAction(f,n,5000000)>=0 && !rx.synchronized);
}
static void nativeClockTests()
{
    for(int drift:{-3000,3000}) for(uint16_t initial:{uint16_t(12),uint16_t(65532)}) {
        TestState s;s.init(local,1000000);s.nativeElectionManaged=s.nativeParentSelected=true;
        memcpy(s.nativeParent,remote,6);
        auto &p=s.peers[0];p.used=true;p.seen=p.epoch=1000000;p.baseCounter=initial;
        memcpy(p.mac,remote,6);memcpy(p.advertisement.master,remote,6);
        memcpy(p.advertisement.sync,remote,6);p.advertisement.presence=4;
        p.advertisement.sequence=s.sequence;
        s.elect(1000000);assert(s.synchronized&&s.baseCounter==initial);
        uint64_t now=1100000;
        p.seen=now;p.epoch=uint64_t(int64_t(p.epoch)-drift);
        uint32_t before=s.untilNext(now);s.elect(now);
        int32_t change=int32_t(before)-int32_t(s.untilNext(now));
        assert(change==(drift>0?512:-512)&&s.clockCorrections==1);
        uint64_t epoch=s.epoch;uint16_t base=s.baseCounter;
        for(unsigned i=0;i<100;++i)s.elect(now+i);
        assert(s.epoch==epoch&&s.baseCounter==base&&s.clockCorrections==1);
        // A valid but discontinuous counter sample cannot jump this selected
        // native clock. Another fresh observation counts one rejection.
        p.seen=now+1000;p.baseCounter+=64;
        s.elect(p.seen);assert(s.clockRejected==1&&s.epoch==epoch&&s.baseCounter==base);
        assert(!s.synchronized&&s.nativeClockValidated&&s.nativeClockHoldover);
        s.elect(p.seen+1);assert(s.clockRejected==1);
        assert(!s.synchronized&&s.nativeClockHoldover&&s.nativeHoldoverTransitions==1);
        p.seen=now-1;s.elect(now+2000);
        assert(s.clockRejected==1&&s.epoch==epoch&&s.baseCounter==base);
        assert(!s.synchronized&&s.nativeClockHoldover);
        // A later aligned observation resumes discipline without another
        // acquisition or a jump to the rejected counter namespace.
        p.baseCounter=base;p.epoch=epoch;p.seen=now+3000;s.elect(p.seen);
        assert(s.synchronized&&!s.nativeClockHoldover&&s.nativeClockAcquisitions==1);
    }
    // Replace deferred observations instead of accumulating half-TU slews.
    // The hold has an absolute bound even if no grant arrives.
    TestState s;s.init(local,1000000);s.nativeElectionManaged=s.nativeParentSelected=true;
    memcpy(s.nativeParent,remote,6);
    auto &p=s.peers[0];p.used=true;p.seen=p.epoch=1000000;
    memcpy(p.mac,remote,6);memcpy(p.advertisement.master,remote,6);
    s.elect(1000000);s.holdClock(1200000);
    for(unsigned i=1;i<=20;++i) {
        p.seen=1000000+i*5000;p.epoch=1000000-(i<20?3000:100);
        s.elect(p.seen);s.elect(p.seen+1);
    }
    assert(s.epoch==1000000&&s.clockDeferred==20&&s.clockCorrections==0);
    s.elect(1200000);assert(s.clockCorrections==1&&s.clockSampleAt==1100000);
    auto epoch=s.epoch;auto base=s.baseCounter;
    s.elect(1200001);assert(s.epoch==epoch&&s.baseCounter==base);
    s.holdClock(1500000);assert(s.setSyncRole(3,local)&&!s.clockHoldUntil);
    // Native refreshes roles and parent controls while following the same
    // peer. Role toggles must not readopt a discontinuous AW counter.
    for(uint16_t initial:{uint16_t(18080),uint16_t(65532)}) {
        TestState clock;clock.init(local,1000000);
        clock.nativeElectionManaged=clock.nativeParentSelected=true;
        memcpy(clock.nativeParent,remote,6);
        auto &parent=clock.peers[0];parent.used=true;parent.seen=parent.epoch=1000000;
        parent.baseCounter=initial;memcpy(parent.mac,remote,6);
        memcpy(parent.advertisement.master,remote,6);clock.elect(1000000);
        uint64_t now=1100000;uint16_t before=clock.counter(now);
        parent.baseCounter=224;parent.epoch=now;parent.seen=now;
        assert(clock.setSyncRole(1,remote));clock.elect(now);
        assert(clock.counter(now)==before);
        assert(clock.setSyncRole(2,remote));clock.elect(now+1);
        assert(clock.counter(now+1)==before&&clock.clockRejected==1);
        // An explicit new native selection supplies another AW namespace.
        // Acquire it at the safe edge instead of rejecting it forever.
        uint8_t other[6]={2,9,8,7,6,5};
        memcpy(parent.mac,other,6);memcpy(parent.advertisement.master,other,6);
        parent.seen=now+2;clock.nativeTimelineStarted=true;clock.selectNativeParent(other);
        clock.elect(now+2);assert(clock.counter(now+2)==224&&clock.clockRejected==1);
        assert(clock.nativeClockValidated&&clock.nativeClockAcquisitions==2);
    }
    // Local warmup AWs must not prevent the first real native clock selection.
    for(uint16_t peerBase:{uint16_t(18080),uint16_t(65532)}) {
        TestState warm;warm.init(local,1000000);warm.nativeTimelineStarted=true;
        warm.nativeElectionManaged=true;warm.holdClock(1065536);
        auto &p=warm.peers[0];p.used=true;p.seen=p.epoch=1012000;p.baseCounter=peerBase;
        memcpy(p.mac,remote,6);memcpy(p.advertisement.master,remote,6);
        warm.selectNativeParent(remote,remote);warm.elect(1012000);
        assert(warm.counter(1012000)==0&&!warm.nativeClockValidated);
        assert(warm.nativeClockAcquisitionPending&&warm.clockDeferred==1);
        warm.holdClock(0);warm.elect(1065536);
        assert(warm.counter(1065536)==uint16_t(peerBase+3));
        assert(warm.nativeClockValidated&&warm.nativeClockAcquisitions==1&&!warm.clockRejected);
        uint64_t acquiredEpoch=warm.epoch;
        p.baseCounter+=64;p.seen=1065537;
        warm.elect(p.seen);assert(warm.clockRejected==1&&warm.epoch==acquiredEpoch);
        warm.selectNativeParent(remote,remote);warm.elect(p.seen+1);
        assert(warm.nativeClockAcquisitions==1&&warm.clockRejected==1);
        uint8_t newRoot[6]={2,9,8,7,6,4};memcpy(p.advertisement.master,newRoot,6);
        // RX can change the peer's root before native selects it. Rejecting
        // that observation must retain the committed clock identity, so the
        // later native selection still authorizes its real acquisition.
        warm.elect(p.seen+2);
        assert(!memcmp(warm.clockRoot,remote,6)&&!memcmp(warm.master,remote,6));
        assert(warm.nativeClockValidated&&warm.nativeClockAcquisitions==1);
        assert(!warm.synchronized&&warm.nativeClockHoldover);
        warm.selectNativeParent(remote,newRoot);warm.elect(p.seen+2);
        assert(warm.nativeClockAcquisitions==2&&warm.nativeClockValidated);
        assert(warm.synchronized&&!warm.nativeClockHoldover);
        // A different root arriving during deferred acquisition is not the
        // clock selected by native. Wait for its selected tree, or cancellation.
        uint8_t thirdRoot[6]={2,9,8,7,6,3};
        warm.holdClock(1200000);warm.selectNativeParent(remote,thirdRoot);
        uint64_t heldEpoch=warm.epoch;memcpy(p.advertisement.master,thirdRoot,6);
        warm.elect(1100000);assert(warm.epoch==heldEpoch&&warm.nativeClockAcquisitionPending);
        memcpy(p.advertisement.master,newRoot,6);warm.elect(1200000);
        assert(warm.epoch==heldEpoch&&warm.nativeClockAcquisitions==2);
        warm.selectNativeParent(remote,newRoot);warm.elect(1200001);
        assert(!warm.nativeClockAcquisitionPending&&warm.nativeClockAcquisitions==2);
    }
}
int main() {
    scheduleTests();roleTests();nativeClockTests();
    Sequence plan;plan.count=16;plan.step=3;for(auto &channel:plan.channels)channel=44;
    RTWAwdl::Election::State native{};
    assert(native.init(local,plan,10000000,7));
    assert(native.nativeElectionManaged && native.channel(10000000)==44);
    TestState tx;tx.init(remote,10000000);tx.metric=50;
    uint8_t frame[512]{};size_t length=buildAction(tx,frame,sizeof(frame),10000000);
    assert(length && native.receiveAction(frame,length,10000000)>=0);
    assert(!native.synchronized); // Native has not selected this parent.
    native.selectNativeParent(remote,remote,true);native.elect(10000000);
    assert(native.synchronized && native.nativeClockValidated);
    assert(native.sequence.channels[0]==44); // Native channel plan is independent.
    auto before=native;
    assert(!native.init(nullptr,plan,10000000,1));
    assert(!memcmp(&before,&native,sizeof(native)));
    uint8_t output[512]{};
    unsigned sequence=native.frameCounter;
    assert(!buildSynchronization(native,output,10,10000000,1,2,3));
    assert(native.frameCounter==sequence);
    assert(!buildSynchronization(native,output,sizeof(output),10000000,1,2,9));
    length=buildSynchronization(native,output,sizeof(output),10000000,1,2,0);
    assert(length && output[30]==0);
    assert(RTWAwdl::SyncDetail::le32(output+32)==1 && RTWAwdl::SyncDetail::le32(output+36)==2);
    Advertisement decoded;assert(parseAdvertisement(output,length,decoded));
    // Real captured follower advertises our MAC as root: retain observation,
    // but do not elect it or follow a synchronization loop.
    FILE *file=fopen("tests/fixtures/awdl/iphone-election-transition.bin","rb");assert(file);
    std::vector<uint8_t> capture;int c;while((c=fgetc(file))!=EOF)capture.push_back(uint8_t(c));fclose(file);
    TestState root;root.init(local,10000000);
    assert(root.receiveAction(capture.data(),capture.size(),10000000)>=0);
    assert(!root.synchronized && !memcmp(root.master,local,6));
    // Bound peer ownership and reclaim expired entries without allocating.
    RTWAwdl::Election::State table{};assert(table.init(local,plan,10000000,1));
    length=buildAction(tx,frame,sizeof(frame),10000000);
    for(unsigned i=0;i<maxPeers;++i) {
        frame[15]=uint8_t(20+i);
        assert(table.receiveAction(frame,length,10000000)==int(i));
    }
    frame[15]=99;
    assert(table.receiveAction(frame,length,10000000)==-1);
    assert(table.receiveAction(frame,length,10000000+peerLifetimeUs+1)==0);
    // Malformed input must never escape bounded parsing/table storage.
    uint32_t random=29;
    for(unsigned trial=0;trial<20000;++trial) {
        uint8_t mutated[512];memcpy(mutated,frame,length);
        random=random*1664525+1013904223;
        size_t offset=random%length;
        random=random*1664525+1013904223;mutated[offset]^=uint8_t(random>>24);
        table.receiveAction(mutated,length,14000000+trial);
    }
    puts("PASS: AWDL election, native parent selection, clock holdover, rollover and synchronization output");
}
