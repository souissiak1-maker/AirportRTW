/* SPDX-License-Identifier: GPL-2.0-only
 * Native control/discovery flow informed by MtkWireless Wi-Fi at
 * 98d9442076939dd3a0360eed27bdcfb5681c3078. Realtek radio operations remain
 * behind RTWCore; no MediaTek firmware, objects or Bluetooth code is used.
 */
#ifndef AIRPORTRTW_AWDL_BACKEND_HPP
#define AIRPORTRTW_AWDL_BACKEND_HPP
#include "AirportRTWAwdlRuntime.hpp"
#include "AirportRTWAwdlPeers.hpp"
#include <AirportRTWDiagnostics.h>
#include "../../rtw/RTWCore.hpp"
#include <AWDL/RTWAwdlNativeAction.hpp>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0
namespace AirportRTWAwdl {
// Heap-own with Runtime in the controller. All methods run on nativeWorkLoop;
// HAL RX uses AirportRTWAwdlInterface::receiveRadio (staging only). Publication
// is still gated by the HAL's explicit complete quiescence support bit.
class NativeBackend final : public RuntimeBackend,public RTWAwdl::WindowDriver {
public:
    explicit NativeBackend(RTWCore &hal):RuntimeBackend(&peers_),hal_(hal),peers_(hal),scheduler_(state_,*this) {}
    ~NativeBackend() override {close();}
    uint32_t capabilities() const override {
        const uint32_t support=hal_.awdlHardwareSupport();
        const uint32_t needed=RTWAwdl::FrameTransport|RTWAwdl::ManualVisits|RTWAwdl::PeerStations;
        if((support&needed)!=needed)return 0;
        uint32_t result=Control::requiredCapabilities&~Control::QuiescentShutdown;
        if(support&RTWAwdl::QuiescentRemoval)result|=Control::QuiescentShutdown;
        return result;
    }
    bool ready() const override {
        if(fault_ || !hal_.awdlPeerCapacity())return false;
        if(!owns_)return true;
        const auto radio=hal_.awdlRadioState();
        return radio.ready && radio.frequency && (!radio.recoveryRequired ||
            (scheduler_.phase()!=RTWAwdl::WindowScheduler::Phase::Stopped &&
             scheduler_.phase()!=RTWAwdl::WindowScheduler::Phase::Failed));
    }
    IOReturn open(IO80211VirtualInterface *interface,const uint8_t mac[6]) override {
        if(owns_ || interface_ || fault_)return kIOReturnBusy;
        auto *native=OSDynamicCast(AirportRTWAwdlInterface,interface);
        if(!native || !RTWAwdl::Election::unicast(mac))return kIOReturnBadArgument;
        if(!hal_.addAwdlInterface(mac))return kIOReturnNotReady;
        owns_=true;interface_=native;
        RTWAwdl::Election::Sequence plan;plan.count=16;plan.step=3;
        const uint8_t social[3]={6,44,149};unsigned count=0;
        for(auto channel:social)if(channelAllowed(channel))plan.channels[count++]=channel;
        if(!count)return kIOReturnNotReady; // close owns the accepted partial open
        for(unsigned i=count;i<16;++i)plan.channels[i]=plan.channels[i%count];
        if(!state_.init(mac,plan,nowUs(),0,true))return kIOReturnBadArgument;
        settings_={};settings_.presence=4;settings_.thresholds={APPLE80211_VERSION,0,0,0,-70};
        settings_.synchronization={APPLE80211_VERSION,16,16,16,110,0};
        settings_.extension={APPLE80211_VERSION,3,3,3,3};
        settings_.parent.version=APPLE80211_VERSION;settings_.parent.state=1;
        memcpy(settings_.parent.master,mac,6);
        settings_.channels.version=APPLE80211_VERSION;settings_.channels.length=16;settings_.channels.step_count=3;
        for(unsigned i=0;i<16;++i)describe(plan.channels[i],settings_.channels.seqs[i]);
        return kIOReturnSuccess;
    }
    IOReturn activate(bool enabled) override {
        if(!owns_ || !interface_)return kIOReturnNotReady;
        if(!enabled) {
            active_=false;pumpDeadline_=0;
            hal_.setAwdlReceiver(nullptr,nullptr);
            const bool stopped=scheduler_.stop();clearQueues();rearm();
            if(!stopped){fault_=true;return kIOReturnError;}
            return kIOReturnSuccess;
        }
        if(active_)return kIOReturnSuccess;
        if(!ready())return kIOReturnNotReady;
        active_=true;
        if(!hal_.setAwdlReceiver(interface_,AirportRTWAwdlInterface::receiveRadio)) {
            active_=false;return kIOReturnError;
        }
        if(settings_.synchronize && !scheduler_.start(100000,5000)) {
            hal_.setAwdlReceiver(nullptr,nullptr);active_=false;return kIOReturnError;
        }
        return kIOReturnSuccess;
    }
    void revokeTraffic() override {active_=false;pumpDeadline_=0;}
    void close() override {
        active_=false;pumpDeadline_=0;
        if(owns_)hal_.setAwdlReceiver(nullptr,nullptr);
        scheduler_.stop();
        if(interface_)interface_->cancelWindowTimer();
        if(owns_ && !hal_.quiesceAwdlInterface())fault_=true;
        owns_=false;interface_=nullptr;windowDeadline_=0;clearQueues();
        psf_.clear();mi_.clear();pendingAction_.clear();miActive_=false;settings_={};
    }
    bool channelAllowed(const apple80211_channel &channel) const override {
        if(channel.version>APPLE80211_VERSION || channel.channel>255)return false;
        if(channel.flags&(APPLE80211_C_FLAG_40MHZ|APPLE80211_C_FLAG_80MHZ|APPLE80211_C_FLAG_160MHZ))return false;
        const uint8_t number=uint8_t(channel.channel);
        if((number<=13 && (channel.flags&APPLE80211_C_FLAG_5GHZ)) ||
           (number>13 && (channel.flags&APPLE80211_C_FLAG_2GHZ)))return false;
        return channelAllowed(number);
    }
    bool currentChannel(apple80211_channel &channel) const override {
        const auto radio=hal_.awdlRadioState();
        const uint8_t number=AirportRTWAwdl::WindowDriver::channelFor(radio.frequency);
        if(!radio.ready || !number)return false;
        describe(number,channel);return true;
    }
    IOReturn configure(const Settings &next) override {return applySettings(next,nullptr);}
    IOReturn applySettings(const Settings &next,const uint8_t *root) {
        if(!owns_ || fault_)return kIOReturnNotReady;
        if(!valid(next))return kIOReturnUnsupported;
        if(active_ && settings_.synchronize && !next.synchronize && !scheduler_.stop()) {
            fault_=true;return kIOReturnError;
        }
        RTWAwdl::Election::Sequence sequence;sequence.count=16;sequence.step=uint8_t(next.presence-1);
        for(unsigned i=0;i<16;++i)sequence.channels[i]=uint8_t(next.channels.seqs[i].channel);
        const uint64_t now=nowUs();
        const unsigned role=next.parent.state ? (next.parent.state==1 && next.synchronization.non_election_master ? 3 : next.parent.state) : 1;
        const uint8_t *parent=role==2 ? next.parent.master : state_.mac;
        state_.setSyncRole(role,parent);state_.setSequence(sequence,now);
        state_.metric=next.metric;
        if(!memcmp(state_.master,state_.mac,6))state_.masterMetric=next.metric;
        state_.psfPeriod=uint16_t(next.synchronization.synchronization_frame_period);
        const uint32_t extensions[4]={next.extension.unk1,next.extension.unk2,next.extension.unk3,next.extension.unk4};
        for(unsigned i=0;i<4;++i)state_.minExtension[i]=uint8_t(extensions[i]);
        if(role!=2)state_.clearNativeParent();
        else if(next.parent.mode_flags&0x20) {
            const bool fresh=!(settings_.parent.mode_flags&0x20) || memcmp(settings_.parent.master,parent,6) ||
                (root && (!state_.nativeClockSelected || memcmp(state_.clockRoot,root,6)));
            state_.selectNativeParent(parent,root,fresh);
        }
        state_.elect(now);const bool start=active_ && next.synchronize && !settings_.synchronize;
        if(start && !scheduler_.start(100000,5000)){fault_=true;return kIOReturnError;}
        settings_=next;nextPsf_=0;miCounterValid_=false;
        if(active_ && next.synchronize){pumpDeadline_=now+1;if(!rearm()){fault_=true;return kIOReturnError;}}
        return kIOReturnSuccess;
    }
    bool configuration(Settings &out) const override {
        if(!owns_ || fault_)return false;
        out=settings_;return true;
    }
    IOReturn installTemplate(const RTWAwdl::TxTemplate &value) override {
        if(!RTWAwdl::NativeAction::valid(value.tlvs(),value.tlvSize()))return kIOReturnBadArgument;
        psf_=value;nextPsf_=0;return kIOReturnSuccess;
    }
    IOReturn setAddress(const uint8_t mac[6]) override {
        if(active_ || !owns_ || !interface_ || !RTWAwdl::Election::unicast(mac))return kIOReturnBusy;
        // The old VIF must quiesce before creating the replacement. A failed
        // hardware transaction faults this backend rather than reporting a MAC
        // that is not actually programmed. Runtime retains the old address.
        if(!hal_.quiesceAwdlInterface()){fault_=true;return kIOReturnError;}
        owns_=false;
        if(!hal_.addAwdlInterface(mac)){fault_=true;return kIOReturnError;}
        owns_=true;
        const auto plan=state_.ownSequence;
        if(!state_.init(mac,plan,nowUs(),settings_.metric,true)){fault_=true;return kIOReturnError;}
        settings_.parent.state=1;memcpy(settings_.parent.master,mac,6);clearQueues();return kIOReturnSuccess;
    }
    bool transmitEthernet(const uint8_t *bytes,size_t length) override {
        if(!active_ || !settings_.synchronize || !RTWAwdl::DataCodec::validEthernet(bytes,length) ||
            memcmp(bytes+6,state_.mac,6) || dataCount_==dataCapacity)return false;
        auto &slot=data_[(dataHead_+dataCount_)%dataCapacity];slot.length=uint16_t(length);
        memcpy(slot.bytes,bytes,length);slot.queued=nowUs();++dataCount_;
        pumpDeadline_=nowUs()+1;rearm();return true;
    }
    void observeRadioAction(const uint8_t *frame,size_t length,const uint8_t *metadata,size_t size) override {
        if(!active_ || !metadata || size!=72 || !frame || length<40 || memcmp(frame+10,metadata,6))return;
        int32_t rssi=0;memcpy(&rssi,metadata+44,4);
        if(rssi<settings_.thresholds.peer_rssi_threshold)return;
        const uint32_t wire=read32be(metadata+48);const uint64_t now=nowUs();
        const uint32_t age=uint32_t(now)-wire;if(age>3000000 || now<age)return;
        const uint64_t received=now-age;
        if(state_.receiveAction(frame,length,received)<0)return;
        auto &sample=samples_[sampleNext_++%16];sample={};
        if(!RTWAwdl::Election::parseAdvertisement(frame,length,sample.advertisement))return;
        sample.valid=true;sample.received=received;memcpy(sample.peer,frame+10,6);
    }
    void timerFired() override {
        if(!active_ || servicing_)return;
        servicing_=true;windowDeadline_=0;pumpDeadline_=0;
        scheduler_.service();
        if(active_ && scheduler_.phase()==RTWAwdl::WindowScheduler::Phase::Open)serviceTransmit();
        servicing_=false;
        if(active_)rearm();
    }
    IOReturn nativeRequest(Request request,bool set,void *payload) override {
        if(!payload)return kIOReturnBadArgument;
        if(!owns_ || fault_)return kIOReturnNotReady;
        static const uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
        switch(request) {
        case Request::AWDL_CONFIG:
            if(!set)return kIOReturnUnsupported;
            if(!valid(settings_))return kIOReturnNotReady;
            configured_=true;return kIOReturnSuccess;
        case Request::AWDL_OOB_AUTO_REQUEST:
        case Request::AWDL_OOB_REQUEST: {
            if(!set)return kIOReturnUnsupported;
            const auto &value=*static_cast<const apple80211_awdl_oob_request *>(payload);
            const auto *raw=static_cast<const uint8_t *>(payload);
            const bool automatic=request==Request::AWDL_OOB_AUTO_REQUEST;
            if(automatic) {
                static const uint8_t broadcast[6]={255,255,255,255,255,255};
                if(memcmp(raw+4,broadcast,6) || (value.unk4 && value.unk4!=0xffffffffU))return kIOReturnUnsupported;
                if(!value.unk4 || !value.data_len){mi_.clear();miActive_=miCounterValid_=false;return kIOReturnSuccess;}
                if(value.unk3>1000000)return kIOReturnBadArgument;
            } else {
                if(read16(raw+20)!=6 || value.unk3 || value.unk4 || memcmp(raw+22,bssid,6))return kIOReturnUnsupported;
                if(!RTWAwdl::Election::unicast(raw+4) || !memcmp(raw+4,state_.mac,6))return kIOReturnBadArgument;
                const int index=state_.find(raw+4);const uint64_t now=nowUs();
                if(!active_ || !settings_.synchronize || !state_.radioScheduleReady())return kIOReturnNotReady;
                if(index<0 || now<state_.peers[index].seen || now-state_.peers[index].seen>3000000)return kIOReturnNotFound;
                if(oobCount_==4)return kIOReturnNoResources;
            }
            if(!RTWAwdl::NativeAction::valid(value.data,value.data_len))return kIOReturnBadArgument;
            if(!pendingAction_.replaceTlvs(value.data,value.data_len,0x10,3))return kIOReturnBadArgument;
            if(automatic) {
                const bool same=mi_.tlvSize()==pendingAction_.tlvSize() && mi_.tlvs() &&
                    !memcmp(mi_.tlvs(),pendingAction_.tlvs(),mi_.tlvSize());
                mi_=pendingAction_;miActive_=true;
                if(!same){miStart_=nowUs()+value.unk3;miCounterValid_=false;}
            } else {
                auto &slot=oob_[(oobHead_+oobCount_)%4];slot.action=pendingAction_;
                slot.queued=nowUs();memcpy(slot.peer,raw+4,6);++oobCount_;
            }
            pendingAction_.clear();
            if(active_){pumpDeadline_=nowUs()+1;if(!rearm()){fault_=true;return kIOReturnError;}}
            return kIOReturnSuccess;
        }
        case Request::AWDL_AWDL_ADVERTISERS: {
            if(!set)return kIOReturnUnsupported;
            const auto *raw=static_cast<const uint8_t *>(payload);
            if(!RTWAwdl::Election::unicast(raw+32) || !RTWAwdl::Election::unicast(raw+38))return kIOReturnBadArgument;
            if(read16(raw+10)!=16 || read16(raw+12)!=16 || !RTWAwdl::Election::validPresence(raw[16]) ||
                raw[15] || raw[17] || raw[19])return kIOReturnUnsupported;
            const uint64_t now=nowUs();
            for(const auto &sample:samples_) {
                const auto &a=sample.advertisement;
                if(!sample.valid || now<sample.received || now-sample.received>3000000 ||
                    uint32_t(sample.received)!=read32be(raw+20) || memcmp(sample.peer,raw+38,6) ||
                    memcmp(a.master,raw+32,6) || a.counter!=read16(raw) || a.down!=read16(raw+2) || a.presence!=raw[16])continue;
                const uint64_t elapsed=uint64_t(unsigned(a.presence)*a.period-a.down)*1024;
                const int index=state_.find(sample.peer);
                if(index<0 || sample.received<elapsed)return kIOReturnNotReady;
                auto &peer=state_.peers[index];
                // A cached native selection must not relabel an older clock
                // observation with a newer RX timestamp.
                if(peer.seen<=sample.received || memcmp(peer.advertisement.master,a.master,6)) {
                    peer.advertisement=a;peer.seen=sample.received;peer.epoch=sample.received-elapsed;
                    peer.baseCounter=uint16_t(a.counter-a.counter%a.presence);
                }
                state_.selectNativeParent(sample.peer,a.master);state_.elect(now);
                nextPsf_=0;miCounterValid_=false;
                if(active_){pumpDeadline_=now+1;if(!rearm()){fault_=true;return kIOReturnError;}}
                return kIOReturnSuccess;
            }
            return kIOReturnNotReady;
        }
        case Request::AWDL_DEVICE_CAPABILITIES: {
            if(set)return kIOReturnUnsupported;
            auto &out=*static_cast<apple80211_awdl_device_capabilities *>(payload);
            out={APPLE80211_VERSION,0,10,uint32_t(hal_.awdlPeerCapacity()),16};
            return kIOReturnSuccess;
        }
        case Request::AWDL_ELECTION_PARAMS: {
            auto &value=*static_cast<apple80211_awdl_election_params *>(payload);
            if(!set) {
                value={};value.version=APPLE80211_VERSION;value.election_id=uint16_t(settings_.electionId);
                value.distance=uint8_t(state_.distance);memcpy(value.master,state_.master,6);
                value.master_metric=state_.masterMetric;value.self_metric=state_.metric;
                return kIOReturnSuccess;
            }
            if(value.distance>10 || !RTWAwdl::Election::unicast(value.master))return kIOReturnBadArgument;
            Settings next=settings_;next.metric=value.self_metric;next.electionId=value.election_id;
            if(!memcmp(value.master,state_.mac,6)) {
                if(value.distance)return kIOReturnBadArgument;
                next.parent.state=1;next.parent.mode_flags=0;memcpy(next.parent.master,state_.mac,6);
            } else {
                next.parent.state=2;next.parent.mode_flags|=0x20;memcpy(next.parent.master,value.master,6);
                const uint64_t now=nowUs();uint64_t newest=0;
                for(const auto &sample:samples_)if(sample.valid && now>=sample.received &&
                    now-sample.received<=3000000 && sample.received>=newest &&
                    !memcmp(sample.advertisement.master,value.master,6)) {
                    newest=sample.received;memcpy(next.parent.master,sample.peer,6);
                }
            }
            return applySettings(next,value.master);
        }
        case Request::AWDL_MASTER_CHANNEL:
        case Request::AWDL_SECONDARY_MASTER_CHANNEL: {
            const unsigned index=request==Request::AWDL_MASTER_CHANNEL ? 0 : 1;
            // Both family payloads contain a version followed by a u32 channel.
            uint32_t number=0;memcpy(&number,static_cast<uint8_t *>(payload)+4,4);
            if(!set) {
                number=settings_.channels.seqs[index].channel;
                const uint32_t version=APPLE80211_VERSION;memcpy(payload,&version,4);
                memcpy(static_cast<uint8_t *>(payload)+4,&number,4);return kIOReturnSuccess;
            }
            if(number>255 || !channelAllowed(uint8_t(number)))return kIOReturnBadArgument;
            Settings next=settings_;describe(uint8_t(number),next.channels.seqs[index]);return configure(next);
        }
        case Request::AWDL_MIN_RATE: {
            auto &value=*static_cast<apple80211_awdl_min_rate *>(payload);
            if(set)return value.min_rate==12 ? kIOReturnSuccess : kIOReturnUnsupported;
            value={APPLE80211_VERSION,12};return kIOReturnSuccess; // actual HAL transport: 6 Mbps OFDM
        }
        case Request::AWDL_BSSID: {
            auto &value=*static_cast<apple80211_awdl_bssid *>(payload);
            if(set)return !memcmp(value.bssid,bssid,6) ? kIOReturnSuccess : kIOReturnUnsupported;
            value={};value.version=APPLE80211_VERSION;memcpy(value.bssid,bssid,6);return kIOReturnSuccess;
        }
        default:return kIOReturnUnsupported;
        }
    }

    uint64_t nowUs() const override {return runtimeNowUs();}
    bool channelAllowed(uint8_t channel) const override {
        const uint16_t frequency=AirportRTWAwdl::WindowDriver::frequencyFor(channel);
        return frequency && hal_.awdlChannelAllowed(frequency);
    }
    uint8_t currentChannel() const override {
        const auto radio=hal_.awdlRadioState();
        return radio.ready ? AirportRTWAwdl::WindowDriver::channelFor(radio.frequency) : 0;
    }
    Reservation reserve(uint8_t channel,uint32_t ms) override {
        const auto result=hal_.reserveAwdlRadio(AirportRTWAwdl::WindowDriver::frequencyFor(channel),ms);
        return result==RTWAwdl::RadioReservation::Granted ? Reservation::Granted :
            result==RTWAwdl::RadioReservation::Rejected ? Reservation::Rejected : Reservation::RecoveryRequired;
    }
    bool restore() override {return hal_.restoreAwdlRadio();}
    bool wireTime(uint64_t host,uint32_t &wire) const override {
        if(host>nowUs())return false;wire=uint32_t(host);return true;
    }
    bool armTimer(uint64_t deadline,uint64_t) override {windowDeadline_=deadline;return rearm();}
    void cancelTimer() override {windowDeadline_=0;rearm();}
    bool windowStart(const RTWAwdl::ScheduledWindow &window,uint32_t wire) override {
        apple80211_channel channel{};describe(window.channel,channel);
        return interface_ && interface_->postWindowStart(window.counter,window.role,window.parent,window.root,channel,wire);
    }
    bool windowEnd(const RTWAwdl::ScheduledWindow &,uint32_t wire) override {
        return interface_ && interface_->postWindowEnd(wire);
    }
private:
    static constexpr unsigned dataCapacity=64;
    struct DataSlot {uint64_t queued;uint16_t length;uint8_t bytes[14+RTWAwdl::DataCodec::mtu];};
    struct OobSlot {uint64_t queued{0};uint8_t peer[6]{};RTWAwdl::TxTemplate action;};
    struct Sample {RTWAwdl::Election::Advertisement advertisement;uint64_t received{0};uint8_t peer[6]{};bool valid{false};};
    static uint16_t read16(const uint8_t *p){return uint16_t(p[0])|uint16_t(uint16_t(p[1])<<8);}
    static uint32_t read32be(const uint8_t *p){return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
    static void describe(uint8_t number,apple80211_channel &channel) {
        channel={};channel.version=APPLE80211_VERSION;channel.channel=number;
        channel.flags=APPLE80211_C_FLAG_20MHZ|(number<=13 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ);
    }
    bool valid(const Settings &s) const {
        if(s.synchronization.availability_window_length!=16 || s.synchronization.availability_window_period!=16 ||
            s.synchronization.extension_length!=16 || s.synchronization.non_election_master>1 ||
            (s.synchronization.synchronization_frame_period!=110 && s.synchronization.synchronization_frame_period!=440) ||
            s.channels.encoding>1 || s.channels.duplicate_count || s.electionId>65535 ||
            (s.actionMode!=0 && s.actionMode!=3) || s.extension.unk1>255 || s.extension.unk2>255 ||
            s.extension.unk3>255 || s.extension.unk4>255 || s.thresholds.unk1 || s.thresholds.unk2 || s.thresholds.unk3 ||
            (s.parent.mode_flags&~0x20) || !s.presence || s.presence>4 || (s.presence&(s.presence-1)) || s.channels.length!=16 ||
            s.channels.step_count+1!=s.presence || s.parent.state>3 ||
            (s.parent.state==2 && (!RTWAwdl::Election::unicast(s.parent.master) || !memcmp(s.parent.master,state_.mac,6))) ||
            ((s.parent.state==1 || s.parent.state==3) && memcmp(s.parent.master,state_.mac,6)) ||
            s.thresholds.peer_rssi_threshold < -127 || s.thresholds.peer_rssi_threshold > -1)return false;
        unsigned channels=0;
        for(unsigned i=0;i<16;++i)if(s.channels.seqs[i].channel) {
            if(!channelAllowed(s.channels.seqs[i]))return false;++channels;
        }
        return channels!=0;
    }
    bool rearm() {
        if(!interface_)return false;
        if(!active_){interface_->cancelWindowTimer();return true;}
        uint64_t deadline=windowDeadline_;
        if(pumpDeadline_ && (!deadline || pumpDeadline_<deadline))deadline=pumpDeadline_;
        if(!deadline){interface_->cancelWindowTimer();return true;}
        return interface_->armWindowTimer(deadline,nowUs());
    }
    void clearQueues(){
        dataHead_=dataCount_=0;memset(data_,0,sizeof(data_));
        oobHead_=oobCount_=0;for(auto &slot:oob_){slot.action.clear();slot.queued=0;memset(slot.peer,0,6);}
    }
    void serviceTransmit() {
        const auto &window=scheduler_.window();uint64_t now=nowUs();
        const uint16_t frequency=AirportRTWAwdl::WindowDriver::frequencyFor(window.channel);
        if(!settings_.actionMode && psf_.size() && scheduler_.canTransmit(now) &&
            (lastPsfChannel_!=window.channel || now>=nextPsf_)) {
            const size_t length=RTWAwdl::NativeAction::build(state_,psf_,frame_,sizeof(frame_),now,uint32_t(now),0);
            if(length)hal_.transmitAwdlAction(frame_,length,frequency);
            lastPsfChannel_=window.channel;nextPsf_=now+uint64_t(state_.psfPeriod)*1000;
        }
        const uint16_t eaw=uint16_t(window.counter/window.presence);
        if(active_ && miActive_ && now>=miStart_ && (!miCounterValid_ || lastMiEaw_!=eaw) && scheduler_.canTransmit(now)) {
            const size_t length=RTWAwdl::NativeAction::build(state_,mi_,frame_,sizeof(frame_),now,uint32_t(now),3);
            if(length && hal_.transmitAwdlAction(frame_,length,frequency)){lastMiEaw_=eaw;miCounterValid_=true;}
        }
        for(unsigned budget=0;budget<4 && active_ && oobCount_;++budget) {
            auto &slot=oob_[oobHead_];now=nowUs();
            const int index=state_.find(slot.peer);
            if(now<slot.queued || now-slot.queued>3000000 || index<0){popOob();continue;}
            if(state_.peers[index].channel(now)!=window.channel || !scheduler_.canTransmit(now))break;
            const size_t length=RTWAwdl::NativeAction::build(state_,slot.action,frame_,sizeof(frame_),now,uint32_t(now),3);
            if(!length){popOob();continue;}
            memcpy(frame_+4,slot.peer,6);
            if(!hal_.transmitAwdlAction(frame_,length,frequency))break;
            popOob();
        }
        for(unsigned budget=0;budget<8 && active_ && dataCount_;++budget) {
            auto &slot=data_[dataHead_];now=nowUs();
            if(now<slot.queued || now-slot.queued>3000000){popData();continue;}
            const bool group=(slot.bytes[0]&1)!=0;
            if(!group && !peers_.authorized(slot.bytes))break;
            const int index=group ? -1 : state_.find(slot.bytes);
            if(index>=0 && state_.peers[index].channel(now)!=window.channel)break;
            if(!scheduler_.canTransmit(now,group))break;
            size_t length=0;
            if(!RTWAwdl::DataCodec::encode(slot.bytes,slot.length,frame_,sizeof(frame_),state_.frameCounter++,state_.dataCounter,length)) {
                popData();continue;
            }
            if(!hal_.transmitAwdlData(frame_,length,frequency,window.endUs))break;
            ++state_.dataCounter;popData();
        }
        now=nowUs();
        if(window.endUs>now+2500){pumpDeadline_=now+1000;}
    }
    void popOob(){oob_[oobHead_].action.clear();oobHead_=(oobHead_+1)%4;--oobCount_;}
    void popData(){data_[dataHead_].length=0;dataHead_=(dataHead_+1)%dataCapacity;--dataCount_;if(interface_)interface_->resumeTransmit();}
    RTWCore &hal_;
    NativePeers peers_;
    RTWAwdl::Election::State state_{};
    RTWAwdl::WindowScheduler scheduler_;
    AirportRTWAwdlInterface *interface_{nullptr};
    Settings settings_{};
    RTWAwdl::TxTemplate psf_,mi_,pendingAction_;
    OobSlot oob_[4]{};unsigned oobHead_{0},oobCount_{0};
    uint64_t miStart_{0};uint16_t lastMiEaw_{0};bool miActive_{false},miCounterValid_{false};
    bool configured_{false};
    Sample samples_[16]{};unsigned sampleNext_{0};
    DataSlot data_[dataCapacity]{};unsigned dataHead_{0},dataCount_{0};
    uint8_t frame_[4096]{};
    uint64_t windowDeadline_{0},pumpDeadline_{0},nextPsf_{0};
    uint8_t lastPsfChannel_{0};
    bool owns_{false},active_{false},fault_{false},servicing_{false};
};
}
#endif
#endif
