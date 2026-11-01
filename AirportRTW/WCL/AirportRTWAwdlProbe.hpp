/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AIRPORTRTW_AWDL_PROBE_HPP
#define AIRPORTRTW_AWDL_PROBE_HPP
#include <AirportRTWDiagnostics.h>
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_26_0 && (RTW_DIAGNOSTICS || RTW_AWDL_STARTUP_PROBE)
#include <AWDL/RTWAwdlStartupProbe.hpp>
#include "../../rtw/RTWCore.hpp"
// Controller owns this adapter; stop/unbind before HAL power-off or deletion.
// RX runs with the HAL registration lock: counters only, no HAL/workloop calls.
class AirportRTWAwdlProbe final : public RTWAwdl::StartupProbeDriver {
public:
    AirportRTWAwdlProbe(RTWCore &core,IOService &owner):state(*this),core_(core),owner_(owner) {}
    bool primaryReady() const override {
        const auto *ic=core_.get80211Controller();
        return ic && ic->ic_state==IEEE80211_S_RUN;
    }
    uint32_t capacity() const override {return core_.awdlPeerCapacity();}
    bool open() override {
        const auto *ic=core_.get80211Controller();
        if (!ic) return false;
        uint8_t mac[6];memcpy(mac,ic->ic_myaddr,6);
        mac[0]=(mac[0]|2)&0xfe;mac[5]^=0x40;
        ownsInterface_=core_.addAwdlInterface(mac);
        return ownsInterface_;
    }
    bool bind() override {
        if (!receive_) return false;
        __atomic_store_n(&receiving_,true,__ATOMIC_RELEASE);
        const bool okay=core_.setAwdlReceiver(&owner_,receive_);
        if (!okay) __atomic_store_n(&receiving_,false,__ATOMIC_RELEASE);
        return okay;
    }
    bool radioReady() const override {
        const auto radio=core_.awdlRadioState();
        return radio.ready && !radio.recoveryRequired && radio.frequency;
    }
    void unbind() override {
        __atomic_store_n(&receiving_,false,__ATOMIC_RELEASE);
        if (ownsInterface_) core_.setAwdlReceiver(nullptr,nullptr);
    }
    bool close() override {
        // A refused add can mean another owner already has the VIF. The HAL
        // unwinds failed adds itself; never unbind/delete another owner's VIF.
        if (!ownsInterface_) return true;
        const bool okay=core_.quiesceAwdlInterface();
        ownsInterface_=false; // HAL retains failed cleanup through full detach
        return okay;
    }
    void receive(const RTWAwdl::ReceiveMetadata &metadata) {
        if (!__atomic_load_n(&receiving_,__ATOMIC_ACQUIRE)) return;
        if (metadata.kind==RTWAwdl::FrameKind::Action)
            __atomic_fetch_add(&actions_,uint32_t(1),__ATOMIC_RELAXED);
        else __atomic_fetch_add(&data_,uint32_t(1),__ATOMIC_RELAXED);
    }
    void publish() const {
        owner_.setProperty("RTWAwdlProbeRevision",uint64_t(1),32);
        owner_.setProperty("RTWAwdlProbeStage",uint64_t(state.stage()),32);
        owner_.setProperty("RTWAwdlProbeResult",uint64_t(state.result()),32);
        owner_.setProperty("RTWAwdlProbeWaits",uint64_t(state.waits()),32);
        owner_.setProperty("RTWAwdlProbeListens",uint64_t(state.listens()),32);
        owner_.setProperty("RTWAwdlProbePeerCapacity",uint64_t(state.peerCapacity()),32);
        owner_.setProperty("RTWAwdlProbeCleanupSucceeded",state.cleanupSucceeded()?kOSBooleanTrue:kOSBooleanFalse);
        owner_.setProperty("RTWAwdlProbeActionRx",uint64_t(__atomic_load_n(&actions_,__ATOMIC_RELAXED)),32);
        owner_.setProperty("RTWAwdlProbeDataRx",uint64_t(__atomic_load_n(&data_,__ATOMIC_RELAXED)),32);
    }
    void setReceiveHandler(RTWAwdl::ReceiveHandler handler) {receive_=handler;}
    RTWAwdl::StartupProbe state;
private:
    RTWCore &core_;
    IOService &owner_;
    RTWAwdl::ReceiveHandler receive_{nullptr};
    bool receiving_{false},ownsInterface_{false};
    uint32_t actions_{0},data_{0};
};
#endif
#endif
