/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_RUNTIME_HPP
#define AIRPORTRTW_AWDL_RUNTIME_HPP
#include "AirportRTWAwdlControl.hpp"
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
#include <libkern/libkern.h>
#include <Airport/apple80211_var.h>
#include <Airport/apple80211_ioctl.h>
#include <AWDL/RTWAwdlTxTemplate.hpp>
#include <AWDL/RTWAwdlData.hpp>
#include <AWDL/RTWAwdlElection.hpp>

namespace AirportRTWAwdl {
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
    virtual ~RuntimeBackend() = default;
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
};

// Concrete native control provider. Publication still requires a complete,
// ready hardware backend; this class does not supply missing radio features.
class Runtime final : public Control {
public:
    explicit Runtime(RuntimeBackend &backend) : backend_(backend) {}
    ~Runtime() override { shutdown(); }
    uint32_t capabilities() const override { return backend_.capabilities(); }
    bool ready() const override { return !stopped_ && backend_.ready(); }
    IOReturn prepare(IO80211VirtualInterface *interface, const uint8_t mac[6]) override {
        if (stopped_ || opened_ || !interface || !validAddress(mac))
            return kIOReturnBadArgument;
        if (!ready() || (capabilities() & requiredCapabilities) != requiredCapabilities)
            return kIOReturnNotReady;
        attempted_ = true;
        const IOReturn result = backend_.open(interface,mac);
        if (result != kIOReturnSuccess) { shutdown(); return result; }
        for (unsigned i=0;i<6;++i) address_[i]=mac[i];
        if (!backend_.configuration(settings_)) { shutdown(); return kIOReturnNotReady; }
        opened_=true;
        return kIOReturnSuccess;
    }
    IOReturn enable(bool value) override {
        if (!opened_ || stopped_ || (value && !backend_.ready())) return kIOReturnNotReady;
        if (value==enabled_) return kIOReturnSuccess;
        const IOReturn result=backend_.activate(value);
        if (result==kIOReturnSuccess) enabled_=value;
        return result;
    }
    void shutdown() override {
        if (stopped_) return;
        stopped_=true; enabled_=false; opened_=false;
        if (attempted_) { backend_.close(); attempted_=false; }
        pendingTemplate_.clear(); settings_={};
        for (auto &b:address_) b=0;
    }
    IOReturn setAddress(const uint8_t mac[6]) override {
        if (!validAddress(mac)) return kIOReturnBadArgument;
        if (!opened_ || stopped_) return kIOReturnNotReady;
        if (enabled_) return kIOReturnBusy;
        const IOReturn result=backend_.setAddress(mac);
        if (result==kIOReturnSuccess)
            for (unsigned i=0;i<6;++i) address_[i]=mac[i];
        return result;
    }
    bool transmitEthernet(const uint8_t *bytes, size_t length) override {
        return opened_ && enabled_ && !stopped_ && backend_.ready() && RTWAwdl::DataCodec::validEthernet(bytes,length) &&
            backend_.transmitEthernet(bytes,length);
    }
    IOReturn request(Request request, bool set, void *payload) override {
        if (!payload) return kIOReturnBadArgument;
        if (!opened_ || stopped_) return kIOReturnNotReady;
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
        case Request::SSID: {
            auto &d=*static_cast<apple80211_ssid_data *>(payload);
            d={}; d.version=APPLE80211_VERSION; return kIOReturnSuccess;
        }
        case Request::STATE: {
            auto &d=*static_cast<apple80211_state_data *>(payload);
            d={}; d.version=APPLE80211_VERSION;
            d.state=enabled_ && backend_.ready() ? APPLE80211_S_RUN : APPLE80211_S_INIT;
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
    Settings settings_ {};
    RTWAwdl::TxTemplate pendingTemplate_;
    uint8_t address_[6] {};
    bool attempted_ {false}, opened_ {false}, enabled_ {false}, stopped_ {false};
};
}
#endif
#endif
