/* SPDX-License-Identifier: GPL-2.0-only
 * Election/clock state adapted from MtkWireless AwdlProtocol.hpp,
 * revision d0919a374aac38d1703d50b2cd6430db8dbd7f08.
 * Original SPDX: GPL-2.0-or-later; adaptation uses GPL-2.0.
 * Changes: shared decoder, caller-supplied initial channel plan, separate
 * replay ownership, explicit wire clocks and no fabricated identity TLVs.
 */
#ifndef RTW_AWDL_ELECTION_HPP
#define RTW_AWDL_ELECTION_HPP
#include "RTWAwdlSync.hpp"
#ifdef KERNEL
#include <libkern/libkern.h>
#else
#include <string.h>
#endif
namespace RTWAwdl { namespace Election {
static constexpr unsigned maxPeers=16, slots=16;
static constexpr uint64_t peerLifetimeUs=3000000;
static constexpr uint32_t awUs=16*1024;
static const uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
inline bool unicast(const uint8_t *p) { return p && SyncDetail::unicast(p); }
inline void put16(uint8_t *p,uint16_t v) { p[0]=uint8_t(v);p[1]=uint8_t(v>>8); }
inline void put32(uint8_t *p,uint32_t v) { put16(p,uint16_t(v));put16(p+2,uint16_t(v>>16)); }
struct Sequence { uint8_t channels[slots] {};uint8_t count {0},step {0}; };
inline bool validPresence(unsigned n) { return n && n<=16 && !(n&(n-1)); }
inline bool validSequence(const Sequence &s) {
    if(s.count!=slots || !validPresence(unsigned(s.step)+1)) return false;
    for(unsigned i=0;i<s.count;++i) if(s.channels[i]>196) return false;
    return true;
}
struct Advertisement {
    Sequence sequence;
    uint8_t master[6] {},sync[6] {};
    uint16_t period {0},counter {0},down {0};
    uint8_t presence {0};
    uint32_t metric {0},distance {0},masterCounter {0},selfCounter {0};
};
inline bool parseAdvertisement(const uint8_t *frame,size_t length,Advertisement &out) {
    out={};ActionInfo info;SyncMessage decoded;
    if(parseFrame(frame,length,info)!=ParseResult::Valid || !unicast(frame+10) ||
       memcmp(frame+16,bssid,6) ||
       decodeSyncAction(frame+24,length-24,decoded)!=SyncDecode::Valid ||
       decoded.periodTu!=16 || !decoded.countdownTu ||
       decoded.height>10 || decoded.counter%decoded.presence !=
           (unsigned(decoded.presence)*16-decoded.countdownTu)/16) return false;
    Advertisement a;
    a.sequence.count=decoded.sequence.count;a.sequence.step=decoded.sequence.stride-1;
    for(unsigned i=0;i<slots;++i)a.sequence.channels[i]=decoded.sequence.channel[i];
    memcpy(a.master,decoded.master,6);
    memcpy(a.sync,decoded.electionPresent ? decoded.syncAddress : frame+10,6);
    a.period=decoded.periodTu;a.counter=decoded.counter;a.down=decoded.countdownTu;
    a.presence=decoded.presence;a.metric=decoded.masterMetric;
    a.distance=decoded.height;a.masterCounter=decoded.masterCounter;a.selfCounter=decoded.selfCounter;
    out=a;return true;
}
struct Peer {
    uint8_t mac[6] {};Advertisement advertisement;
    uint64_t seen {0},epoch {0};uint16_t baseCounter {0};bool used {false};
    uint8_t channel(uint64_t now) const {
        const Sequence &s=advertisement.sequence;
        if(!used || now<epoch || now<seen || now-seen>peerLifetimeUs || !validSequence(s))return 0;
        uint16_t counter=uint16_t(baseCounter+uint16_t((now-epoch)/awUs));
        return s.channels[(counter/(unsigned(s.step)+1))%s.count];
    }
};
struct State {
    uint8_t mac[6], master[6], sync[6], forcedSync[6];
    Sequence sequence, ownSequence; Peer peers[maxPeers];
    uint64_t epoch; uint16_t baseCounter, dataCounter, frameCounter, psfPeriod;
    uint32_t metric, masterMetric, distance, masterCounter, selfCounter; bool synchronized;
    uint64_t electionEpoch;
    uint8_t presence, ownPresence, syncRole, minExtension[4];
    bool nativeElectionManaged, nativeParentSelected;
    uint8_t nativeParent[6];
    uint64_t clockSampleAt, clockCorrections, clockRejected;
    // Software equivalent of a firmware AW clock: peer observations remain
    // fresh, but phase discipline waits until the promised radio AW ends.
    // Both event production and synchronization TLVs use epoch/baseCounter.
    uint64_t clockHoldUntil, clockDeferredAt, clockDeferred;
    void holdClock(uint64_t until) { clockHoldUntil=until; }
    // The selected clock survives opmode changes and temporary peer expiry.
    // Effective radio controls are a transaction applied between AW events.
    bool nativeClockSelected, nativeTimelineStarted, controlsHeld, controlsDirty;
    bool nativeClockHoldover, nativeClockValidated, nativeClockAcquisitionPending;
    bool clockSampleRejected;
    uint64_t nativeHoldoverTransitions, nativeClockAcquisitions;
    uint8_t clockParent[6], clockRoot[6];
    uint8_t acquisitionParent[6], acquisitionRoot[6];
    bool acquisitionRootKnown;
    uint64_t controlsDeferred;
    struct Controls {
        Sequence sequence;
        uint8_t presence, role, forced[6], parent[6];
        bool parentSelected;
    } pendingControls;
    void holdControls() {
        if(controlsHeld) return;
        pendingControls.sequence=ownSequence; pendingControls.presence=ownPresence;
        pendingControls.role=syncRole; memcpy(pendingControls.forced,forcedSync,6);
        memcpy(pendingControls.parent,nativeParent,6);
        pendingControls.parentSelected=nativeParentSelected;
        controlsHeld=true; controlsDirty=false;
    }
    void discardControls() { controlsHeld=controlsDirty=false; }
    uint8_t requestedRole() const { return controlsHeld ? pendingControls.role : syncRole; }
    bool requestedParentIs(const uint8_t *address) const {
        return controlsHeld ? pendingControls.parentSelected &&
            !memcmp(pendingControls.parent,address,6) : nativeParentSelected &&
            !memcmp(nativeParent,address,6);
    }
    void selectNativeParent(const uint8_t *address,const uint8_t *root=nullptr,
                            bool acquire=false) {
        nativeElectionManaged=true;
        // Only an explicit native selection authorizes acquiring another AW
        // namespace. Ordinary RX from an already selected peer remains a
        // bounded drift observation, even if it carries a discontinuous clock.
        bool keepRoot=!root && nativeClockAcquisitionPending &&
            !memcmp(acquisitionParent,address,6);
        nativeClockAcquisitionPending=acquire || !nativeClockSelected || memcmp(clockParent,address,6) ||
            (root && memcmp(clockRoot,root,6));
        if(keepRoot) nativeClockAcquisitionPending=true;
        memcpy(acquisitionParent,address,6);
        if(!keepRoot) acquisitionRootKnown=root!=nullptr;
        if(root) memcpy(acquisitionRoot,root,6);
        if(controlsHeld) {
            if(!pendingControls.parentSelected || memcmp(pendingControls.parent,address,6)) {
                memcpy(pendingControls.parent,address,6); pendingControls.parentSelected=true;
                controlsDirty=true; ++controlsDeferred;
            }
        } else {
            if(memcmp(nativeParent,address,6)) nativeClockHoldover=false;
            memcpy(nativeParent,address,6); nativeParentSelected=true;
        }
    }
    void clearNativeParent() {
        nativeClockAcquisitionPending=false; acquisitionRootKnown=false;
        if(controlsHeld) {
            if(pendingControls.parentSelected) {
                pendingControls.parentSelected=false; controlsDirty=true; ++controlsDeferred;
            }
            return;
        }
        nativeParentSelected=nativeClockSelected=nativeClockValidated=false;
        nativeClockHoldover=clockSampleRejected=synchronized=false;
        memset(nativeParent,0,6); memset(clockParent,0,6); memset(clockRoot,0,6);
        memcpy(master,mac,6); memcpy(sync,mac,6);
        sequence=ownSequence; presence=ownPresence;
        masterMetric=metric; masterCounter=selfCounter; distance=0;
        // Keep the physical AW counter/phase through local-master promotion.
    }
    bool releaseControls(uint64_t now) {
        if(!controlsHeld) return false;
        bool changed=controlsDirty; controlsHeld=controlsDirty=false;
        if(changed) {
            setSyncRole(pendingControls.role,pendingControls.forced);
            setSequence(pendingControls.sequence,now);
            memcpy(nativeParent,pendingControls.parent,6);
            nativeParentSelected=pendingControls.parentSelected;
            if(nativeElectionManaged && !nativeParentSelected) clearNativeParent();
        }
        elect(now); return changed;
    }
    bool init(const uint8_t *address, const Sequence &initial, uint64_t now,
              uint32_t initialMetric, bool nativeManaged=true) {
        if (!address || !unicast(address) || !validSequence(initial)) return false;
        memset(this,0,sizeof(*this)); memcpy(mac,address,6);
        memcpy(master,address,6); memcpy(sync,address,6); memcpy(forcedSync,address,6);
        epoch=electionEpoch=now; metric=masterMetric=initialMetric;
        presence=ownPresence=uint8_t(initial.step+1); syncRole=1; psfPeriod=110;
        sequence=ownSequence=initial; nativeElectionManaged=nativeManaged;
        for (unsigned i=0;i<4;++i) minExtension[i]=3;
        return true;
    }
    uint16_t counter(uint64_t now) const {
        return baseCounter+uint16_t((now>=epoch ? now-epoch : 0)/awUs);
    }
    uint32_t untilNext(uint64_t now) const {
        if (!validPresence(presence)) return 0;
        uint32_t period=unsigned(presence)*awUs;
        uint64_t elapsed=now>=epoch ? now-epoch : 0;
        return period-uint32_t((uint64_t(baseCounter%presence)*awUs+elapsed%period)%period);
    }
    uint8_t channel(uint64_t now) const {
        if (!radioScheduleReady()) return 0;
        return validSequence(sequence) ? sequence.channels[(counter(now)/(unsigned(sequence.step)+1))%sequence.count] : 0;
    }
    bool radioScheduleReady() const {
        return syncRole!=2 || synchronized || (nativeClockHoldover && nativeElectionManaged &&
            nativeClockSelected && nativeClockValidated && nativeParentSelected &&
            !memcmp(clockParent,nativeParent,6));
    }
    bool setSyncRole(unsigned role,const uint8_t *address) {
        if (role<1 || role>3 || !address || !unicast(address) ||
            (role==2 ? !memcmp(address,mac,6) :
             role==3 ? memcmp(address,mac,6) : (!nativeElectionManaged && memcmp(address,mac,6)))) return false;
        if(controlsHeld) {
            if(pendingControls.role!=role || memcmp(pendingControls.forced,address,6)) {
                pendingControls.role=role; memcpy(pendingControls.forced,address,6);
                controlsDirty=true; ++controlsDeferred;
            }
            return true;
        }
        if (syncRole==role && !memcmp(forcedSync,address,6)) return true;
        holdClock(0);
        syncRole=role; memcpy(forcedSync,address,6);
        synchronized=false; nativeClockHoldover=false; sequence=ownSequence; presence=ownPresence;
        memcpy(master,mac,6); memcpy(sync,mac,6); masterMetric=metric;
        masterCounter=selfCounter; distance=0; return true;
    }
    bool setPresence(uint8_t value,uint64_t now) {
        if (!validPresence(value)) return false;
        if(controlsHeld) {
            if(pendingControls.presence!=value) {
                pendingControls.presence=value; pendingControls.sequence.step=value-1;
                controlsDirty=true; ++controlsDeferred;
            }
            return true;
        }
        ownPresence=value; ownSequence.step=value-1;
        if (!synchronized) {
            // Keep the current AW counter and sub-AW phase through a change
            // of EAW duration. untilNext() includes the base-counter phase.
            uint64_t elapsed=now>=epoch ? now-epoch : 0;
            baseCounter=counter(now); epoch=now-elapsed%awUs;
            presence=value; sequence.step=value-1;
        }
        return true;
    }
    bool setSequence(const Sequence &value,uint64_t now) {
        if(!validSequence(value) || !validPresence(unsigned(value.step)+1)) return false;
        if(controlsHeld) {
            if(memcmp(&pendingControls.sequence,&value,sizeof(value))) {
                pendingControls.sequence=value; pendingControls.presence=value.step+1;
                controlsDirty=true; ++controlsDeferred;
            }
        } else {
            ownSequence=value; setPresence(value.step+1,now);
            sequence=value; presence=value.step+1;
        }
        return true;
    }
    void setSocialChannel(unsigned index,uint8_t channel,uint64_t now) {
        Sequence desired=controlsHeld ? pendingControls.sequence : ownSequence;
        if(index>=desired.count) return;
        desired.channels[index]=channel; setSequence(desired,now);
    }
    int find(const uint8_t *address) const {
        if (!address) return -1;
        for(unsigned i=0;i<maxPeers;++i) if(peers[i].used && !memcmp(peers[i].mac,address,6)) return i;
        return -1;
    }
    void elect(uint64_t now) {
        // Peer RX may refresh observations, but cannot alter an open AW's
        // role, parent, channel or clock. Commit the latest controls at end.
        if(controlsHeld) return;
        // Only a top master advances its own election counter. Followers
        // advertise the counter learned from their selected master.
        if(now<electionEpoch || synchronized || nativeClockHoldover) electionEpoch=now;
        else {
            uint64_t intervals=(now-electionEpoch)/3140000;
            selfCounter+=uint32_t(intervals); electionEpoch+=intervals*3140000;
        }
        // A native interface receives its election result through advertisers.
        // Do not adopt an independently ranked peer before that transaction.
        if(nativeElectionManaged && !nativeParentSelected) return;
        int best=-1;
        for(unsigned i=0;i<maxPeers;++i) {
            Peer &p=peers[i];
            if(p.used && (now<p.seen || now-p.seen>peerLifetimeUs)) p.used=false;
            if(!p.used || !memcmp(p.advertisement.master,mac,6)) continue;
            const Advertisement &a=p.advertisement;
            if(a.distance>=10 || !memcmp(a.sync,mac,6)) continue;
            if(syncRole==3) continue;
            if(nativeElectionManaged) {
                if(!memcmp(p.mac,nativeParent,6)) best=i;
                continue;
            }
            if(syncRole==2) { if(!memcmp(p.mac,forcedSync,6)) best=i; continue; }
            // omdrop-owl's iOS 26 captures show metric precedes counter.
            int32_t rank=int32_t(a.masterCounter-selfCounter);
            if(a.metric<metric || (a.metric==metric && (rank<0 ||
                (!rank && (a.distance || memcmp(p.mac,mac,6)<=0))))) continue;
            if(best<0) { best=i; continue; }
            const Advertisement &b=peers[best].advertisement;
            rank=int32_t(a.masterCounter-b.masterCounter);
            if(a.metric>b.metric || (a.metric==b.metric && (rank>0 || (!rank &&
                (a.distance<b.distance || (a.distance==b.distance && memcmp(p.mac,peers[best].mac,6)>0)))))) best=i;
        }
        if(best<0) {
            // Native selected this firmware-clock equivalent and still owns
            // the configured sequence. A short RX cache expiry must not stop
            // all radio reservations or silently promote us to another tree.
            // Holdover retains the last clock; it does not claim peer RF sync.
            if(nativeElectionManaged && nativeClockSelected && nativeClockValidated &&
               nativeParentSelected && syncRole!=3 &&
               !memcmp(clockParent,nativeParent,6)) {
                if(!nativeClockHoldover) ++nativeHoldoverTransitions;
                nativeClockHoldover=true; synchronized=false;
                sequence=ownSequence; presence=ownPresence;
                memcpy(master,clockRoot,6); memcpy(sync,clockParent,6);
                return;
            }
            nativeClockHoldover=false;
            // Preserve the current AW clock when an elected master expires,
            // but restore our own advertised channel sequence.
            if(synchronized) { sequence=ownSequence; presence=ownPresence; holdClock(0); }
            synchronized=false; masterMetric=metric; masterCounter=selfCounter; distance=0;
            memcpy(master,mac,6); memcpy(sync,mac,6); return;
        }
        const Peer &p=peers[best];
        bool sameClock=nativeElectionManaged ? nativeClockSelected &&
            !memcmp(clockParent,p.mac,6) && !memcmp(clockRoot,p.advertisement.master,6) :
            synchronized && !memcmp(sync,p.mac,6) && !memcmp(master,p.advertisement.master,6);
        // A native selection authorizes this parent/root only. RX arriving
        // while the old AW closes cannot substitute an unrelated clock tree.
        if(nativeElectionManaged && nativeClockAcquisitionPending &&
           (memcmp(acquisitionParent,p.mac,6) ||
            (acquisitionRootKnown && memcmp(acquisitionRoot,p.advertisement.master,6)))) return;
        bool adopt=!nativeElectionManaged || nativeClockAcquisitionPending ||
            (!nativeClockSelected && !nativeTimelineStarted);
        if(nativeElectionManaged && !sameClock && !adopt) {
            // This RX belongs to another clock tree; native has not selected
            // it. Do not overwrite the committed identity before rejecting it,
            // or a subsequent explicit selection looks like a duplicate and
            // leaves validation permanently false.
            if(p.seen>clockSampleAt) { clockSampleAt=p.seen; ++clockRejected; }
            clockSampleRejected=true; synchronized=false;
            if(!nativeClockHoldover) ++nativeHoldoverTransitions;
            nativeClockHoldover=true;
            return;
        }
        if(adopt && nativeElectionManaged && now<clockHoldUntil) {
            if(p.seen>clockDeferredAt) { clockDeferredAt=p.seen; ++clockDeferred; }
            return;
        }
        // A timer rechecking a rejected observation is not a new aligned RX.
        // Retain the acquired clock as holdover until a fresh accepted sample.
        nativeClockHoldover=clockSampleRejected; synchronized=!clockSampleRejected;
        memcpy(master,p.advertisement.master,6);
        memcpy(sync,p.mac,6);
        // Native programs our radio sequence independently of its selected
        // synchronization parent. A peer supplies the clock, not an implicit
        // replacement for the sequence accepted by the native setter.
        sequence=nativeElectionManaged ? ownSequence : p.advertisement.sequence;
        presence=nativeElectionManaged ? ownPresence : p.advertisement.presence;
        masterMetric=p.advertisement.metric; masterCounter=p.advertisement.masterCounter;
        distance=p.advertisement.distance+1;
        if(nativeElectionManaged && !sameClock) {
            nativeClockSelected=true; nativeClockValidated=false; memcpy(clockParent,p.mac,6);
            memcpy(clockRoot,p.advertisement.master,6);
        }
        if(adopt) {
            holdClock(0);
            // Native programChipWithNewMaster supplies a real selected-peer
            // counter/down/timestamp. Acquire that shared event/wire clock at
            // a safe edge, including when local warmup AWs already ran.
            epoch=p.epoch; baseCounter=p.baseCounter; clockSampleAt=p.seen;
            if(nativeElectionManaged) {
                nativeClockValidated=true; nativeClockAcquisitionPending=false;
                clockSampleRejected=false; nativeClockHoldover=false; synchronized=true;
                ++nativeClockAcquisitions;
            }
        } else if(!sameClock || p.seen>clockSampleAt) {
            uint64_t local=now>=epoch ? now-epoch : 0;
            uint64_t remote=now>=p.epoch ? now-p.epoch : 0;
            int32_t delta=int16_t(uint16_t(p.baseCounter+remote/awUs)-counter(now))*int32_t(awUs)+
                int32_t(remote%awUs)-int32_t(local%awUs);
            // Native permits 5 TU between consecutive matching starts. Slew
            // at most half a TU per fresh PSF; a discontinuous peer clock
            // needs a new selection instead of silently skipping real AWs.
            if(delta>5*1024 || delta<-5*1024) {
                clockSampleAt=p.seen; ++clockRejected; clockSampleRejected=true;
                synchronized=false;
                if(!nativeClockHoldover) ++nativeHoldoverTransitions;
                nativeClockHoldover=true; return;
            }
            if(nativeElectionManaged) {
                nativeClockValidated=true; clockSampleRejected=false;
                nativeClockHoldover=false; synchronized=true;
            }
            if(now<clockHoldUntil) {
                if(p.seen>clockDeferredAt) { clockDeferredAt=p.seen; ++clockDeferred; }
                // Do not consume the sample. At the safe edge elect() uses
                // the newest peer observation, never a sum of old slews.
                return;
            }
            clockSampleAt=p.seen;
            int32_t correction=delta>512 ? 512 : delta<-512 ? -512 : delta;
            if(correction) {
                uint16_t base=counter(now);
                int32_t phase=int32_t(local%awUs)+correction;
                if(phase<0) { --base; phase+=awUs; }
                else if(phase>=int32_t(awUs)) { ++base; phase-=awUs; }
                if(now>=uint32_t(phase)) {
                    epoch=now-uint32_t(phase); baseCounter=base; ++clockCorrections;
                }
            }
        }
    }
    int receiveAction(const uint8_t *f,size_t n,uint64_t now) {
        Advertisement a;
        if(!parseAdvertisement(f,n,a) || !memcmp(f+10,mac,6)) return -1;
        uint64_t elapsed=uint64_t(unsigned(a.presence)*a.period-a.down)*1024;
        if(now<elapsed) return -1;
        int idx=find(f+10);
        if(idx<0) for(unsigned i=0;i<maxPeers;++i)
            if(!peers[i].used || now<peers[i].seen || now-peers[i].seen>peerLifetimeUs) { idx=i; break; }
        if(idx<0) return -1;
        Peer &p=peers[idx];
        if(!p.used || now<p.seen || now-p.seen>peerLifetimeUs || memcmp(p.mac,f+10,6)) memset(&p,0,sizeof(p));
        memcpy(p.mac,f+10,6); p.used=true; p.seen=now; p.advertisement=a;
        p.epoch=now-elapsed; p.baseCounter=a.counter-a.counter%a.presence;
        elect(now); return idx;
    }
};
inline void writeSequence(uint8_t *p,const Sequence &s) {
    p[0]=s.count-1; p[1]=p[2]=0; p[3]=s.step; put16(p+4,0xffff);
    memcpy(p+6,s.channels,s.count);
}
inline void writeSync(State &s,uint8_t *p,uint64_t now) {
    p[0]=p[3]=s.channel(now); put16(p+1,(s.untilNext(now)+1023)/1024);
    put16(p+5,16); put16(p+11,16); put16(p+13,16);
    uint32_t remaining=s.untilNext(now), duration=unsigned(s.presence)*awUs;
    uint32_t elapsed=duration-remaining;
    put16(p+15,elapsed<awUs ? (awUs-elapsed)/1024 : 0);
    // No advertised extension may cross the next scheduled channel change.
    for(unsigned i=0;i<4;++i) p[17+i]=s.minExtension[i]<s.presence ? s.minExtension[i] : s.presence-1;
    memcpy(p+21,s.master,6); p[27]=s.presence;
    put16(p+29,s.counter(now)); put16(p+31,s.counter(now));
    writeSequence(p+33,s.sequence);
}
inline void writeElection(State &s,uint8_t *p) {
    memcpy(p,s.master,6); memcpy(p+6,s.sync,6); put32(p+12,s.masterCounter);
    put32(p+16,s.distance); put32(p+20,s.masterMetric); put32(p+24,s.metric);
    put32(p+36,s.selfCounter);
}
// Caller supplies wire clock values in the established radio/event domain.
// now drives the accepted schedule only; it is not silently used as RF TSF.
inline size_t buildSynchronization(State &s,uint8_t *frame,size_t capacity,
    uint64_t now,uint32_t phyTime,uint32_t targetTime,uint8_t subtype) {
    const size_t syncLength=39+s.sequence.count;
    const size_t length=40+3+syncLength+43;
    if(!frame || capacity<length || (subtype!=0 && subtype!=3) ||
       !validSequence(s.sequence) || s.sequence.step+1!=s.presence ||
       !s.radioScheduleReady() || now<s.epoch || !unicast(s.mac)) return 0;
    memset(frame,0,length);frame[0]=0xd0;memset(frame+4,255,6);
    memcpy(frame+10,s.mac,6);memcpy(frame+16,bssid,6);
    put16(frame+22,uint16_t((s.frameCounter++&4095)<<4));
    frame[24]=127;frame[26]=0x17;frame[27]=0xf2;frame[28]=8;
    frame[29]=0x10;frame[30]=subtype;
    put32(frame+32,phyTime);put32(frame+36,targetTime);
    frame[40]=4;put16(frame+41,uint16_t(syncLength));writeSync(s,frame+43,now);
    put16(frame+50,s.psfPeriod);
    const size_t election=43+syncLength;
    frame[election]=24;put16(frame+election+1,40);writeElection(s,frame+election+3);
    return length;
}
} }
#endif
