/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_RUNTIME_HPP
#define AIRPORTRTW_AWDL_RUNTIME_HPP
#include "AirportRTWAwdlControl.hpp"
#include "AirportRTWAwdlPeerControl.hpp"
#include "AirportRTWAwdlWindowDriver.hpp"
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <libkern/libkern.h>
#include <Airport/apple80211_var.h>
#include <Airport/apple80211_ioctl.h>
#include <AWDL/RTWAwdlTxTemplate.hpp>
#include <AWDL/RTWAwdlData.hpp>
#include <AWDL/RTWAwdlDataReceive.hpp>
#include <AWDL/RTWAwdlNativeRxMetadata.hpp>
#include <AWDL/RTWAwdlElection.hpp>
#include <AWDL/RTWAwdlWindowScheduler.hpp>

namespace AirportRTWAwdl {
// Nonvirtual local adapters implemented by the real native interface source.
// Runtime holds its interface pin through every callback/delivery.
uint64_t runtimeNowUs();
bool deliverRuntimeEthernet(IO80211VirtualInterface *,const uint8_t *,size_t);
// Owning configuration snapshot: no pointers into native request storage.
struct Settings {
    apple80211_awdl_sync_params synchronization {};
    apple80211_awdl_sync_state parent {};
    apple80211_awdl_sync_channel_sequence channels {};
    apple80211_awdl_election_rssi_thresholds thresholds {};
    uint32_t presence {0}, electionId {0}, metric {0};
    uint32_t actionMode {0};
    bool synchronize {false};
};
// Backend owns radio scheduling, clock acceptance, peers and queued traffic.
// It must outlive Runtime. All calls are serialized on the native workloop.
// No implementation may advertise a capability supplied only by a stub.
class RuntimeBackend {
public:
    // Optional concrete native peer owner; backend/controller owns its lifetime.
    explicit RuntimeBackend(PeerControl *peers=nullptr):peers_(peers) {}
    virtual ~RuntimeBackend() = default;
    bool peersReady() const { return !peers_ || peers_->ready(); }
    IOReturn bindPeers(IO80211VirtualInterface *interface,const uint8_t mac[6]) {
        const IOReturn result=peers_ ? peers_->bind(interface,mac) : kIOReturnSuccess;
        if(result==kIOReturnSuccess){dataInterface_=interface;memcpy(dataAddress_,mac,6);}
        return result;
    }
    IOReturn enablePeers(bool enabled) {
        const IOReturn result=peers_ ? peers_->enable(enabled) : kIOReturnSuccess;
        dataEnabled_=enabled && result==kIOReturnSuccess;return result;
    }
    void revokePeers() {dataEnabled_=false;if (peers_) peers_->revoke();}
    void updateReceiveAddress(const uint8_t address[6]) {memcpy(dataAddress_,address,6);receive_.reset();}
    void abandonPeers() {
        dataEnabled_=false;dataInterface_=nullptr;memset(dataAddress_,0,6);receive_.reset();
        if (peers_) peers_->abandon();
    }
    virtual uint32_t capabilities() const = 0;
    virtual bool ready() const = 0;
    // open may fail part way; close must unwind that case as well. No RX callback
    // may reach the native family until activate(true) has succeeded.
    virtual IOReturn open(IO80211VirtualInterface *, const uint8_t mac[6]) = 0;
    virtual IOReturn activate(bool) = 0;
    // Synchronously stop timers, RX/TX producers and outstanding radio commands,
    // restore the full infrastructure channel definition, then release peers/VIF.
    virtual void close() = 0;
    // Validate against the effective domain, not a channel number whitelist.
    virtual bool channelAllowed(const apple80211_channel &) const = 0;
    virtual bool currentChannel(apple80211_channel &) const = 0;
    // Atomic application: on failure old settings/template remain operational.
    // Copy borrowed inputs before returning; never retain the references.
    virtual IOReturn configure(const Settings &) = 0;
    // Snapshot the accepted settings, including backend initialization and any
    // synchronization-engine updates. Never derive them from stale ioctl data.
    virtual bool configuration(Settings &) const = 0;
    virtual IOReturn installTemplate(const RTWAwdl::TxTemplate &) = 0;
    virtual IOReturn setAddress(const uint8_t mac[6]) = 0;
    virtual bool transmitEthernet(const uint8_t *, size_t) = 0;
    // These are real backend transactions, not merely accepted ioctls. A
    // successful cache change must update data admission/hardware peer ownership
    // and deliver the native cache completion. Copy the borrowed request first.
    // Unsupported defaults keep incomplete backends from claiming peer support.
    virtual IOReturn cachePeer(uint32_t operation, const uint8_t address[6]) {
        return peers_ ? peers_->cache(operation,address) : kIOReturnUnsupported;
    }
    virtual IOReturn registerTraffic(const apple80211_awdl_peer_traffic_registration &d) {
        return peers_ ? peers_->traffic(d) : kIOReturnUnsupported;
    }
    virtual uint32_t peerCapacity() const { return peers_ ? peers_->capacity() : 0; }
    virtual void observeRadioAction(const uint8_t *,size_t,const uint8_t *,size_t) {}
    bool receiveRadioData(const uint8_t *frame,size_t length,const uint8_t *metadata,size_t size) {
        if (!dataEnabled_ || !dataInterface_ || !peers_ || !frame || length<24 ||
            !metadata || size!=RTWAwdl::NativeRxMetadata::size || memcmp(frame+10,metadata,6)) return false;
        const auto *clock=metadata+RTWAwdl::NativeRxMetadata::clockOffset;
        const uint32_t wire=(uint32_t(clock[0])<<24)|(uint32_t(clock[1])<<16)|
            (uint32_t(clock[2])<<8)|clock[3];
        const uint64_t now=runtimeNowUs();const uint32_t age=uint32_t(now)-wire;
        if(age>3000000 || now<age)return false;
        return receive_.deliver(frame,length,dataAddress_,now-age,*peers_,
            [this](const uint8_t *bytes,size_t n) {
                return dataEnabled_ && dataInterface_ && deliverRuntimeEthernet(dataInterface_,bytes,n);
            })!=0;
    }
    virtual void timerFired() {}
private:
    PeerControl *peers_;
    IO80211VirtualInterface *dataInterface_{nullptr}; // weak, Runtime pins it
    uint8_t dataAddress_[6] {};
    bool dataEnabled_{false};
    RTWAwdl::DataReceive receive_;
};

// Concrete native control provider. Publication still requires a complete,
// ready hardware backend; this class does not supply missing radio features.
class Runtime final : public Control {
public:
    explicit Runtime(RuntimeBackend &backend) : backend_(backend) {}
    ~Runtime() override { shutdown(); }
    uint32_t capabilities() const override { return backend_.capabilities(); }
    bool ready() const override { return !stopped_ && backend_.ready() && backend_.peersReady(); }
    IOReturn prepare(IO80211VirtualInterface *interface, const uint8_t mac[6]) override {
        if (stopped_ || opened_ || !interface || !validAddress(mac))
            return kIOReturnBadArgument;
        if (!ready() || (capabilities() & requiredCapabilities) != requiredCapabilities)
            return kIOReturnNotReady;
        interface_=interface;
        Call call(*this);
        attempted_ = true;
        const IOReturn result = backend_.open(interface,mac);
        if (result != kIOReturnSuccess) { shutdown(); return result; }
        if (stopped_) return kIOReturnNotReady;
        const IOReturn peerResult=backend_.bindPeers(interface,mac);
        if (peerResult!=kIOReturnSuccess) {shutdown();return peerResult;}
        for (unsigned i=0;i<6;++i) address_[i]=mac[i];
        if (!backend_.configuration(settings_)) { shutdown(); return kIOReturnNotReady; }
        if (stopped_) return kIOReturnNotReady;
        opened_=true;
        return kIOReturnSuccess;
    }
    IOReturn enable(bool value) override {
        if (!opened_ || stopped_ || (value && !ready())) return kIOReturnNotReady;
        if (value==enabled_) return kIOReturnSuccess;
        Call call(*this);
        if (!value) {enabled_=false;backend_.revokePeers();}
        const IOReturn result=backend_.activate(value);
        if (stopped_) return kIOReturnNotReady;
        if (!value) {
            const IOReturn peers=backend_.enablePeers(false);
            return result!=kIOReturnSuccess ? result : peers;
        }
        if (result!=kIOReturnSuccess) return result;
        const IOReturn peers=backend_.enablePeers(true);
        if (peers!=kIOReturnSuccess) {backend_.activate(false);return peers;}
        if (stopped_) return kIOReturnNotReady;
        enabled_=true;return kIOReturnSuccess;
    }
    void shutdown() override {
        if (stopped_) return;
        stopped_=true;enabled_=false;opened_=false;
        backend_.revokePeers();
        // Native cache completion may re-enter shutdown from postMessage. Keep
        // backend/VIF ownership until the outer request/dispatch has returned.
        if (!calls_) finishShutdown();
    }
    IOReturn setAddress(const uint8_t mac[6]) override {
        if (!validAddress(mac)) return kIOReturnBadArgument;
        if (!opened_ || stopped_) return kIOReturnNotReady;
        if (enabled_) return kIOReturnBusy;
        Call call(*this);
        const IOReturn result=backend_.setAddress(mac);
        if (stopped_) return kIOReturnNotReady;
        if (result==kIOReturnSuccess) {
            for (unsigned i=0;i<6;++i) address_[i]=mac[i];
            backend_.updateReceiveAddress(mac);
        }
        return result;
    }
    bool transmitEthernet(const uint8_t *bytes, size_t length) override {
        if (!opened_ || !enabled_ || !ready() || !RTWAwdl::DataCodec::validEthernet(bytes,length)) return false;
        Call call(*this);
        return backend_.transmitEthernet(bytes,length);
    }
    bool receiveRadioData(const uint8_t *frame,size_t length,const uint8_t *metadata,size_t size) override {
        if (!opened_ || !enabled_ || stopped_ || !ready()) return false;
        Call call(*this);return backend_.receiveRadioData(frame,length,metadata,size);
    }
    void observeRadioAction(const uint8_t *frame,size_t length,const uint8_t *metadata,size_t size) override {
        if (!opened_ || !enabled_ || stopped_ || !ready()) return;
        Call call(*this);backend_.observeRadioAction(frame,length,metadata,size);
    }
    void timerFired() override {
        if (opened_ && enabled_ && !stopped_) {Call call(*this);backend_.timerFired();}
    }
    IOReturn request(Request request, bool set, void *payload) override {
        if (!payload) return kIOReturnBadArgument;
        if (!opened_ || stopped_) return kIOReturnNotReady;
        Call call(*this);
        if (!backend_.configuration(settings_)) return kIOReturnNotReady;
        if (!set) return get(request,payload);
        uint32_t version=0; memcpy(&version,payload,sizeof(version));
        if (version>APPLE80211_VERSION) return kIOReturnBadArgument;
        Settings next=settings_;
        switch (request) {
        case Request::AWDL_SYNC_PARAMS: {
            const auto d=*static_cast<apple80211_awdl_sync_params *>(payload);
            if (d.availability_window_length!=16 || d.availability_window_period!=16 ||
                d.extension_length!=16 || d.non_election_master>1 ||
                (d.synchronization_frame_period!=110 && d.synchronization_frame_period!=440))
                return kIOReturnUnsupported;
            next.synchronization=d; break;
        }
        case Request::AWDL_SYNC_STATE: {
            const auto d=*static_cast<apple80211_awdl_sync_state *>(payload);
            if (d.state>3 || (d.state && !validAddress(d.master))) return kIOReturnBadArgument;
            next.parent=d;
            if (!d.state) next.synchronize=false;
            break;
        }
        case Request::AWDL_SYNC_ENABLED: {
            const auto d=*static_cast<apple80211_awdl_sync_enabled *>(payload);
            if (d.enabled>1) return kIOReturnBadArgument;
            next.synchronize=d.enabled; break;
        }
        case Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE: {
            const auto &d=*static_cast<apple80211_awdl_sync_channel_sequence *>(payload);
            if (!d.length || d.length>16 || d.encoding>1 || d.duplicate_count ||
                !validPresence(uint32_t(d.step_count)+1)) return kIOReturnUnsupported;
            for (unsigned i=0;i<d.length;++i)
                if (d.seqs[i].channel && !backend_.channelAllowed(d.seqs[i]))
                    return kIOReturnBadArgument;
            next.channels=d; break;
        }
        case Request::AWDL_PRESENCE_MODE: {
            const auto d=*static_cast<apple80211_awdl_presence_mode *>(payload);
            if (!validPresence(d.mode)) return kIOReturnUnsupported;
            next.presence=d.mode; break;
        }
        case Request::AWDL_ELECTION_ID:
            next.electionId=static_cast<apple80211_awdl_election_id *>(payload)->election_id; break;
        case Request::AWDL_ELECTION_METRIC:
            next.metric=static_cast<apple80211_awdl_election_metric *>(payload)->metric; break;
        case Request::AWDL_AF_TX_MODE: {
            const auto mode=static_cast<apple80211_awdl_af_tx_mode *>(payload)->mode;
            if (mode!=0 && mode!=3) return kIOReturnUnsupported;
            next.actionMode=mode; break;
        }
        case Request::AWDL_ELECTION_RSSI_THRESHOLDS:
            next.thresholds=*static_cast<apple80211_awdl_election_rssi_thresholds *>(payload);
            if (next.thresholds.peer_rssi_threshold < -127 || next.thresholds.peer_rssi_threshold > -1)
                return kIOReturnBadArgument;
            break;
        case Request::PEER_CACHE_CONTROL: {
            // Native Tahoe's 0x1d0-byte request: version/op/MAC prefix only.
            // Never reinterpret the MAC as a kernel pointer or copy opaque keys.
            if (!enabled_) return kIOReturnNotReady;
            uint32_t operation=0; uint8_t address[6];
            memcpy(&operation,static_cast<const uint8_t *>(payload)+4,4);
            memcpy(address,static_cast<const uint8_t *>(payload)+8,6);
            if (!validAddress(address) || !memcmp(address,address_,6)) return kIOReturnBadArgument;
            if (operation!=0 && operation!=2 && operation!=6) return kIOReturnUnsupported;
            return backend_.cachePeer(operation,address);
        }
        case Request::AWDL_PEER_TRAFFIC_REGISTRATION: {
            if (!enabled_) return kIOReturnNotReady;
            const auto d=*static_cast<const apple80211_awdl_peer_traffic_registration *>(payload);
            if (d.active>1 || d.name_len>sizeof(d.name) || !d.name_len ||
                (d.active && (!validAddress(d.addr) || !memcmp(d.addr,address_,6))))
                return kIOReturnBadArgument;
            return backend_.registerTraffic(d);
        }
        case Request::AWDL_SYNC_FRAME_TEMPLATE: {
            const auto d=*static_cast<apple80211_awdl_sync_frame_template *>(payload);
            if (!d.payload || !d.payload_len ||
                !pendingTemplate_.replaceTlvs(static_cast<const uint8_t *>(d.payload),d.payload_len,0x10,0))
                return kIOReturnBadArgument;
            const IOReturn result=backend_.installTemplate(pendingTemplate_);
            pendingTemplate_.clear();
            return result;
        }
        default: return kIOReturnUnsupported;
        }
        const IOReturn result=backend_.configure(next);
        if (result==kIOReturnSuccess) settings_=next;
        return result;
    }
private:
    struct Call {
        Runtime &owner;
        IO80211VirtualInterface *interface;
        explicit Call(Runtime &runtime):owner(runtime),interface(runtime.interface_) {
            if(interface)interface->retain();
            ++owner.calls_;
        }
        ~Call() {
            if (!--owner.calls_ && owner.stopped_) owner.finishShutdown();
            if(interface)interface->release();
        }
    };
    void finishShutdown() {
        auto *interface=interface_;
        if(interface)interface->retain();
        if (attempted_) {
            attempted_=false;
            // close owns the producer drain and the entire HAL VIF/peer pool.
            // Do not delete peers before close has stopped those producers.
            backend_.abandonPeers();backend_.close();
        }
        interface_=nullptr;
        pendingTemplate_.clear();settings_={};
        for(auto &b:address_)b=0;
        if(interface)interface->release();
    }
    static bool validAddress(const uint8_t *mac) {
        if (!mac || (mac[0]&1)) return false;
        uint8_t bits=0; for (unsigned i=0;i<6;++i) bits|=mac[i];
        return bits!=0;
    }
    static bool validPresence(uint32_t value) {
        return value && value<=16 && !(value&(value-1));
    }
    IOReturn get(Request request, void *payload) {
        switch (request) {
        case Request::PEER_CACHE_MAXIMUM_SIZE: {
            const uint32_t capacity=backend_.peerCapacity();
            if (!capacity) return kIOReturnUnsupported;
            auto &d=*static_cast<apple80211_peer_cache_maximum_size *>(payload);
            d={};d.version=APPLE80211_VERSION;d.max_peers=capacity;return kIOReturnSuccess;
        }
        case Request::SSID: {
            auto &d=*static_cast<apple80211_ssid_data *>(payload);
            d={}; d.version=APPLE80211_VERSION; return kIOReturnSuccess;
        }
        case Request::STATE: {
            auto &d=*static_cast<apple80211_state_data *>(payload);
            d={}; d.version=APPLE80211_VERSION;
            d.state=enabled_ && ready() ? APPLE80211_S_RUN : APPLE80211_S_INIT;
            return kIOReturnSuccess;
        }
        case Request::CHANNEL: {
            apple80211_channel channel {};
            if (!backend_.currentChannel(channel)) return kIOReturnNotReady;
            auto &d=*static_cast<apple80211_channel_data *>(payload);
            d={}; d.version=APPLE80211_VERSION; d.channel=channel;
            return kIOReturnSuccess;
        }
        case Request::AWDL_SYNC_PARAMS:
            *static_cast<apple80211_awdl_sync_params *>(payload)=settings_.synchronization; break;
        case Request::AWDL_SYNC_STATE:
            *static_cast<apple80211_awdl_sync_state *>(payload)=settings_.parent; break;
        case Request::AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE:
            *static_cast<apple80211_awdl_sync_channel_sequence *>(payload)=settings_.channels; break;
        case Request::AWDL_ELECTION_RSSI_THRESHOLDS:
            *static_cast<apple80211_awdl_election_rssi_thresholds *>(payload)=settings_.thresholds; break;
        case Request::AWDL_SYNC_ENABLED: {
            auto &d=*static_cast<apple80211_awdl_sync_enabled *>(payload);
            d={}; d.version=APPLE80211_VERSION; d.enabled=settings_.synchronize; break;
        }
        case Request::AWDL_PRESENCE_MODE: {
            auto &d=*static_cast<apple80211_awdl_presence_mode *>(payload);
            d={}; d.version=APPLE80211_VERSION; d.mode=settings_.presence; break;
        }
        case Request::AWDL_ELECTION_ID: {
            auto &d=*static_cast<apple80211_awdl_election_id *>(payload);
            d={}; d.version=APPLE80211_VERSION; d.election_id=settings_.electionId; break;
        }
        case Request::AWDL_ELECTION_METRIC: {
            auto &d=*static_cast<apple80211_awdl_election_metric *>(payload);
            d={}; d.version=APPLE80211_VERSION; d.metric=settings_.metric; break;
        }
        case Request::AWDL_AF_TX_MODE: {
            auto &d=*static_cast<apple80211_awdl_af_tx_mode *>(payload);
            d={}; d.version=APPLE80211_VERSION; d.mode=settings_.actionMode; break;
        }
        default: return kIOReturnUnsupported;
        }
        uint32_t version=APPLE80211_VERSION; memcpy(payload,&version,sizeof(version));
        return kIOReturnSuccess;
    }
    RuntimeBackend &backend_;
    IO80211VirtualInterface *interface_ {nullptr};
    Settings settings_ {};
    RTWAwdl::TxTemplate pendingTemplate_;
    uint8_t address_[6] {};
    unsigned calls_ {0};
    bool attempted_ {false}, opened_ {false}, enabled_ {false}, stopped_ {false};
};
}
#endif
#endif
