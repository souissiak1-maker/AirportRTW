/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_PEERS_HPP
#define AIRPORTRTW_AWDL_PEERS_HPP
#include "AirportRTWAwdlPeerControl.hpp"
#include "AirportRTWAwdlInterface.hpp"
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <HAL/RTWAwdlPeer.hpp>
#include <net/ethernet.h>
#include <Airport/apple80211_ioctl.h>
#include <libkern/libkern.h>
namespace AirportRTWAwdl {
// Exclusive native owner of the HAL's AWDL peers. Cache and active traffic are
// independent references. This does not create a VIF or publish capabilities;
// the runtime backend opens/closes it and stops TX before disabling/shutdown.
class NativePeers final : public PeerControl {
public:
    explicit NativePeers(RTWAwdl::PeerHardware &hal):hal_(hal) {}
    ~NativePeers() override { shutdown(); }
    NativePeers(const NativePeers &)=delete;
    NativePeers &operator=(const NativePeers &)=delete;
    bool ready() const override {return !fault_ && hal_.awdlPeerCapacity()!=0;}
    uint32_t capacity() const override {
        const uint32_t count=bound_ && !fault_ ? hal_.awdlPeerCapacity() : 0;
        return count>maximumPeers ? maximumPeers : count;
    }
    IOReturn bind(IO80211VirtualInterface *interface,const uint8_t address[6]) override {
        if (busy_ || closing_ || bound_) return kIOReturnBusy;
        auto *native=OSDynamicCast(AirportRTWAwdlInterface,interface);
        if (!native || !valid(address)) return kIOReturnBadArgument;
        ether_addr current {};
        if (native->getHardwareAddress(&current)!=kIOReturnSuccess || memcmp(current.octet,address,6))
            return kIOReturnBadArgument;
        if (!hal_.awdlPeerCapacity()) return kIOReturnNotReady;
        interface_=native;bound_=true;active_=false;
        fault_=false;lastError_=kIOReturnSuccess;return kIOReturnSuccess;
    }
    IOReturn enable(bool value) override {
        if (!value) {
            revoke();
            if (busy_) {disablePending_=true;return kIOReturnSuccess;}
            clear(false);return lastError_;
        }
        if (busy_ || closing_) return kIOReturnBusy;
        if (!bound_ || !interface_ || !ready()) return kIOReturnNotReady;
        active_=true;return kIOReturnSuccess;
    }
    void revoke() override {active_=false;}
    void shutdown() override {
        revoke();
        if (busy_ || closing_) {shutdownPending_=true;return;}
        clear(true);
    }
    void abandon() override {
        revoke();
        if (busy_ || closing_) {abandonPending_=true;return;}
        for(auto &entry:entries_)entry={};
        memset(trafficPeer_,0,6);interface_=nullptr;bound_=false;
        abandonPending_=shutdownPending_=disablePending_=false;
    }
    bool authorized(const uint8_t address[6]) const {
        if (!bound_ || !active_ || fault_ || closing_ || !valid(address)) return false;
        const int i=find(address);
        return i>=0 && entries_[i].installed && !entries_[i].retiring &&
            (entries_[i].cached || entries_[i].traffic);
    }
    IOReturn lastError() const {return lastError_;}
    IOReturn cache(uint32_t operation,const uint8_t address[6]) override {
        if (!bound_ || !active_ || !interface_ || !interface_->canPostPeerCacheCompletion())
            return kIOReturnNotReady;
        if (busy_ || closing_) return kIOReturnBusy;
        if (!valid(address) || isLocal(address)) return kIOReturnBadArgument;
        if (operation!=0 && operation!=2 && operation!=6) return kIOReturnUnsupported;
        const bool add=operation!=2;
        if (add && (!ready() || fault_)) return kIOReturnNotReady;
        uint8_t peer[6];memcpy(peer,address,6);
        Transaction transaction(*this);
        int i=find(peer);Entry previous {};
        if (i>=0) previous=entries_[i];
        if (add) {
            const IOReturn result=install(peer,i);
            if (result!=kIOReturnSuccess) return result;
            if (!active_ || shutdownPending_) return kIOReturnNotReady;
            entries_[i].cached=true;
        } else if (i>=0) {
            entries_[i].cached=false; // revoke data immediately on removal failure
            if (!entries_[i].traffic) {
                const IOReturn result=remove(i);
                if (result!=kIOReturnSuccess) return result;
            }
        }
        if (!active_ || shutdownPending_) return kIOReturnNotReady;
        if (interface_->postPeerCacheCompletion(peer,add)) return kIOReturnSuccess;
        // A failed handoff cannot invent a successful native cache add. Keep an
        // existing owner; otherwise unwind the newly created hardware reference.
        if (add && i>=0) {
            entries_[i].cached=previous.cached;
            if (!previous.installed && !entries_[i].traffic) (void)remove(i);
        }
        return kIOReturnNotReady;
    }
    IOReturn traffic(const apple80211_awdl_peer_traffic_registration &d) override {
        if (!bound_ || !active_) return kIOReturnNotReady;
        if (busy_ || closing_) return kIOReturnBusy;
        if (d.version>APPLE80211_VERSION || d.active>1 || !d.name_len || d.name_len>sizeof(d.name) ||
            (d.active && (!valid(d.addr) || isLocal(d.addr)))) return kIOReturnBadArgument;
        if (d.active && !ready()) return kIOReturnNotReady;
        Transaction transaction(*this);
        int next=-1;
        if (d.active) {
            const IOReturn result=install(d.addr,next);
            if (result!=kIOReturnSuccess) return result;
            if (!active_ || shutdownPending_) return kIOReturnNotReady;
            entries_[next].traffic=true;
        }
        const int old=find(trafficPeer_);
        memcpy(trafficPeer_,d.active ? d.addr : zeroAddress_,6);
        if (old>=0 && old!=next) {
            entries_[old].traffic=false;
            if (!entries_[old].cached) {
                const IOReturn result=remove(old);
                if (result!=kIOReturnSuccess) return result;
            }
        }
        return active_ && !shutdownPending_ ? kIOReturnSuccess : kIOReturnNotReady;
    }
private:
    static constexpr unsigned maximumPeers=16;
    struct Entry {
        uint8_t address[6] {};
        bool used {false},cached {false},traffic {false},installed {false},retiring {false};
    };
    struct Transaction {
        NativePeers &owner;
        explicit Transaction(NativePeers &p):owner(p) {owner.busy_=true;}
        ~Transaction() {
            owner.busy_=false;
            if (owner.abandonPending_) owner.abandon();
            else if (owner.shutdownPending_) owner.clear(true);
            else if (owner.disablePending_) owner.clear(false);
        }
    };
    static bool valid(const uint8_t *address) {
        if (!address || (address[0]&1)) return false;
        uint8_t bits=0;for(unsigned i=0;i<6;++i)bits|=address[i];return bits!=0;
    }
    bool isLocal(const uint8_t address[6]) const {
        // Native may replace its randomized MAC while disabled. Read the real
        // interface address rather than keeping a stale bind-time copy.
        ether_addr current {};
        return !interface_ || interface_->getHardwareAddress(&current)!=kIOReturnSuccess ||
            !valid(current.octet) || !memcmp(current.octet,address,6);
    }
    int find(const uint8_t *address) const {
        if (!address) return -1;
        for(unsigned i=0;i<maximumPeers;++i)
            if(entries_[i].used && !memcmp(entries_[i].address,address,6))return int(i);
        return -1;
    }
    static IOReturn status(RTWAwdl::PeerResult result) {
        using R=RTWAwdl::PeerResult;
        switch(result) {
        case R::Success:return kIOReturnSuccess;
        case R::Unsupported:return kIOReturnUnsupported;
        case R::Invalid:return kIOReturnBadArgument;
        case R::NotReady:return kIOReturnNotReady;
        case R::NoMemory:return kIOReturnNoMemory;
        case R::NoResources:return kIOReturnNoResources;
        case R::HardwareError:case R::RecoveryRequired:return kIOReturnError;
        }
        return kIOReturnError;
    }
    IOReturn install(const uint8_t address[6],int &index) {
        index=find(address);
        if(index>=0) return entries_[index].installed && !entries_[index].retiring ?
            kIOReturnSuccess : kIOReturnNotReady;
        unsigned count=0;int empty=-1;
        for(unsigned i=0;i<maximumPeers;++i) {
            if(entries_[i].used)++count;
            else if(empty<0)empty=int(i);
        }
        if(empty<0 || count>=capacity())return kIOReturnNoResources;
        auto &entry=entries_[empty];entry.used=true;memcpy(entry.address,address,6);
        const auto result=hal_.setAwdlPeer(entry.address,true);
        lastError_=status(result);
        if(result!=RTWAwdl::PeerResult::Success) {
            if(result==RTWAwdl::PeerResult::RecoveryRequired) {
                entry.installed=true;entry.retiring=true;fault_=true;
            } else entry={};
            return lastError_;
        }
        entry.installed=true;index=empty;return kIOReturnSuccess;
    }
    IOReturn remove(int index) {
        auto &entry=entries_[index];
        entry.retiring=true;
        lastError_=status(hal_.setAwdlPeer(entry.address,false));
        if(lastError_!=kIOReturnSuccess) {fault_=true;return lastError_;}
        entry={};return kIOReturnSuccess;
    }
    void clear(bool unbind) {
        if(closing_){shutdownPending_|=unbind;return;}
        closing_=true;active_=false;
        IOReturn failure=kIOReturnSuccess;
        for(auto &entry:entries_) {
            if(entry.used && entry.installed) {
                const IOReturn result=status(hal_.setAwdlPeer(entry.address,false));
                if(result!=kIOReturnSuccess) failure=result;
            }
            // Failed physical allocations are retained by the HAL, not by a
            // callback into this session. Backend close must quiesce the VIF.
            entry={};
        }
        memset(trafficPeer_,0,6);
        lastError_=failure;
        if(failure!=kIOReturnSuccess)fault_=true;
        if(unbind || shutdownPending_ || abandonPending_) {
            interface_=nullptr;bound_=false;
        }
        shutdownPending_=disablePending_=abandonPending_=false;closing_=false;
    }
    RTWAwdl::PeerHardware &hal_;
    AirportRTWAwdlInterface *interface_ {nullptr}; // weak; runtime shutdown precedes native stop
    Entry entries_[maximumPeers] {};
    uint8_t trafficPeer_[6] {},zeroAddress_[6] {};
    IOReturn lastError_ {kIOReturnSuccess};
    bool bound_ {false},active_ {false},fault_ {false},busy_ {false},closing_ {false};
    bool shutdownPending_ {false},disablePending_ {false},abandonPending_ {false};
};
}
#endif
#endif
